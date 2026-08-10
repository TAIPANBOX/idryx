package detectors

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/TAIPANBOX/idryx/internal/ebpfcapture"
	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// EnforcementSource is the bus producer whose journal says an agent's web
// egress is governed: the web-egress enforcement point (agent-passport SPEC
// §6.2, source "scopyx"), which writes one event per fetch and one per
// refusal.
const EnforcementSource = "scopyx"

// UnroutedEgress flags an agent whose web egress is governed by an enforcement
// point and which the sensor nevertheless saw opening its own connections to
// the public internet.
//
// # WHY THE OBVIOUS JOIN IS NOT THE ONE BUILT HERE
//
// The question is "did this agent reach a host it was never routed through an
// enforcement point to reach", and the obvious shape is a join on the host:
// take the destinations the sensor observed, take the origins the plane's
// journal recorded, report the difference. That join cannot be built, for two
// reasons that are properties of the data rather than of the effort available.
//
// The sensor reports ADDRESSES. internal/ebpfcapture reads the destination out
// of `connect()` and substitutes a hostname for exactly three hosts, resolved
// once at startup (capture_linux.go's knownLLMHosts). The plane's journal
// records an ORIGIN, `https://docs.example`, and deliberately never the rest of
// the URL. The two sides therefore meet on three hosts out of the internet, and
// resolving names inside a detector to close the gap would put a DNS lookup in
// the detection path, which is invariant 1 gone.
//
// And in the deployment the plane actually ships, the governed side is invisible
// to the sensor anyway: the enforcement point is an MCP server, its default bind
// is loopback, and the sensor discards loopback that is not a local model port.
//
// # SO THE RULE IS INVERTED, AND THE INVERSION IS WHAT MAKES IT SOUND
//
// A governed fetch cannot produce a connection from the AGENT's process at all.
// The enforcement point performs the fetch inside its own process: the
// passthrough backend on its own pinned client, the browser behind a proxy it
// owns, the external backend on somebody else's infrastructure. There is no
// path in which an agent routed through it opens a socket to the destination.
//
// So a flow the sensor attributed to a governed agent, reaching a public
// address, is not "probably ungoverned" and needs no correlation of timestamps:
// it could not have been governed. What the journal supplies is not the
// comparison, it is the PRECONDITION, which is the second half of the design.
//
// # THE TWO PRECONDITIONS, AND WHY EACH SILENCE IS A DIFFERENT SILENCE
//
// An agent is judged only when both nodes exist in the graph: `agent://X` with
// at least one event the enforcement point wrote (proof the plane exists, is
// deployed, and serves this agent), and `claimed:agent://X` carrying egress the
// sensor observed (proof of direct connection). Firing without the first would
// light up every install that runs no enforcement point, where "bypassed
// everything" and "nothing to bypass" are one silence.
//
// The second missing is the opposite fact and is reported rather than dropped:
// a governed agent the sensor never saw is a coverage gap, not a clean bill.
//
// # WHAT IS DELIBERATELY NOT JUDGED, AND IT IS COUNTED RATHER THAN DROPPED
//
// PRIVATE, loopback, link-local and carrier-NAT destinations. This is not
// caution, it is the plane's own constitution: its address rules refuse those
// ranges outright, so a flow to one of them is not something that should have
// been routed through it. It is also, on any real deployment, the cluster's DNS,
// the other MCP transports, the money plane's gateway and the enforcement
// point's own address. Judging them would fire on every healthy estate.
//
// LLM API destinations. Model traffic is a different plane's subject and
// already has three detectors: shadow_ai, claimed_agent_drift and
// claimed_agent_unknown. Excluding it here is visible rather than silent,
// because the same flow still produces a finding under its correct name.
//
// Both are counted per agent and named in the finding, because an exclusion
// nobody can see is the failure this repository has recorded nine times.
//
// # WHAT IT CANNOT SEE, STATED SO NOBODY BUYS MORE THAN IT SELLS
//
//   - Attribution is AGENT_PASSPORT_ID, which a process writes about itself
//     (SPEC 3.3). An agent that unsets it leaves this detector entirely and its
//     flows fall back to `proc:` identities, where unmanaged_egress still fires
//     at medium. The evasion degrades rather than disappears, and the two
//     detectors are each other's fallback.
//   - An enforcement point at a PUBLIC address would make the agent's own
//     transport to it look like unrouted egress. Every documented deployment
//     binds loopback or a private address, so this is an edge rather than the
//     normal case, but it is a real one.
//   - A provider's own built-in web search reaches web content with no agent
//     socket except to the model API, which is excluded here. Nothing at this
//     layer closes that.
//   - The sensor is Linux-only and needs root on the agent's own host.
//
// Severity is medium for direct public egress and rises to high when the same
// agent also carries refusals: a plane that said no, and traffic that went
// around it, is a different fact from traffic that never asked.
type UnroutedEgress struct{}

func NewUnroutedEgress() *UnroutedEgress { return &UnroutedEgress{} }

func (d *UnroutedEgress) Name() string { return "unrouted_egress" }

// governance is what the enforcement point's journal says about one agent.
type governance struct {
	events  int
	refused int
}

// split is one governed agent's observed egress, sorted into what this detector
// judges and what it deliberately does not.
type split struct {
	public  []string // judged: reached directly, and the plane never decided it
	private int      // not judged: the plane's own address rules refuse these ranges
	llm     int      // not judged here: the shadow-AI detectors own model traffic
}

func (d *UnroutedEgress) Detect(g graph.Reader) []model.Alert {
	identities := g.Identities()

	// What the enforcement point has said, per agent it spoke about. Claimed
	// identities are excluded from this side on purpose: the journal's subject
	// comes from an authenticated credential (the plane derives identity from
	// the key presented, never from a claim), so it belongs to the established
	// namespace and a `claimed:` node could never legitimately carry it.
	governed := map[string]*governance{}
	for _, id := range identities {
		if ebpfcapture.IsClaimed(id.ID) {
			continue
		}
		for _, e := range id.Events {
			if e.Source != EnforcementSource {
				continue
			}
			gv := governed[id.ID]
			if gv == nil {
				gv = &governance{}
				governed[id.ID] = gv
			}
			gv.events++
			if e.Type == model.EventWebBlocked {
				gv.refused++
			}
		}
	}
	if len(governed) == 0 {
		return nil // no enforcement point in this graph: nothing to be outside of
	}

	// Whether the sensor contributed anything at all. Without this the detector
	// would report a coverage gap for every governed agent on an estate that
	// simply does not run the optional eBPF layer, which is the capture layer's
	// own fact to report (invariant 4) and not a per-agent finding.
	if !carriesSensorEvidence(identities) {
		return nil
	}

	// The claimed side, keyed by the agent each claim names.
	claimed := map[string]*model.Identity{}
	for _, id := range identities {
		if !ebpfcapture.IsClaimed(id.ID) {
			continue
		}
		claimed[strings.TrimPrefix(id.ID, ebpfcapture.ClaimedPrefix)] = id
	}

	var alerts []model.Alert
	for _, agent := range sortedGoverned(governed) {
		gv := governed[agent]
		node, seen := claimed[agent]
		if !seen {
			alerts = append(alerts, model.Alert{
				Detector:   d.Name(),
				IdentityID: agent,
				Severity:   model.SeverityInfo,
				Time:       now(),
				Summary: fmt.Sprintf("%s is governed by the web-egress plane (%d journal event(s)) and was not judged: no connection the sensor observed carries its claim, so either nothing runs the sensor where it runs, or its process does not declare AGENT_PASSPORT_ID",
					agent, gv.events),
			})
			continue
		}

		sp := splitEgress(node)
		if len(sp.public) == 0 {
			alerts = append(alerts, model.Alert{
				Detector:   d.Name(),
				IdentityID: node.ID,
				Severity:   model.SeverityInfo,
				Time:       now(),
				Summary: fmt.Sprintf("a process claiming to be %s is governed by the web-egress plane (%d journal event(s)) and no unrouted public egress was found%s",
					agent, gv.events, notJudged(sp)),
			})
			continue
		}

		sev := model.SeverityMedium
		summary := fmt.Sprintf("a process claiming to be %s reached %d public destination(s) directly (e.g. %s) while that agent's web egress is governed by the plane (%d journal event(s)): a governed fetch is performed by the enforcement point's own process, so these connections never passed it. Either the agent fetches outside its plane, or something else is using its name",
			agent, len(sp.public), sp.public[0], gv.events)
		if gv.refused > 0 {
			sev = model.SeverityHigh
			summary = fmt.Sprintf("a process claiming to be %s was refused by the web-egress plane (%d refusal(s) of %d journal event(s)) and reached %d public destination(s) directly (e.g. %s): connections that never passed the enforcement point that had already said no to this agent",
				agent, gv.refused, gv.events, len(sp.public), sp.public[0])
		}
		alerts = append(alerts, model.Alert{
			Detector:   d.Name(),
			IdentityID: node.ID,
			Severity:   sev,
			Time:       now(),
			Summary:    summary + notJudged(sp),
		})
	}

	sort.Slice(alerts, func(i, j int) bool { return alerts[i].IdentityID < alerts[j].IdentityID })
	return alerts
}

// notJudged renders the counted exclusions, or nothing when there were none.
// Rendered into every finding, positive and informational alike: a detector
// that reports what it looked at and stays quiet about what it skipped is one
// whose clean answer cannot be read.
func notJudged(sp split) string {
	var parts []string
	if sp.private > 0 {
		parts = append(parts, fmt.Sprintf("%d connection(s) to private, loopback or carrier-NAT ranges not judged (the plane's own address rules refuse those ranges, so they were never its to decide)", sp.private))
	}
	if sp.llm > 0 {
		parts = append(parts, fmt.Sprintf("%d connection(s) to model APIs left to the shadow-AI detectors, which own that traffic", sp.llm))
	}
	if len(parts) == 0 {
		return ""
	}
	return "; " + strings.Join(parts, "; ")
}

// splitEgress sorts one claimed identity's observed egress into the three
// buckets. Destinations are de-duplicated so an agent polling one host a
// thousand times is one destination rather than a thousand, and sorted so the
// example named in a finding is the same one on every run (invariant 1).
func splitEgress(id *model.Identity) split {
	var sp split
	public := map[string]bool{}
	for _, e := range id.Events {
		if e.Type != model.EventEgress {
			continue
		}
		if _, isLLM := matchLLM(e.Resource); isLLM {
			sp.llm++
			continue
		}
		host := destinationHost(e.Resource)
		if !isPublicDestination(host) {
			sp.private++
			continue
		}
		public[host] = true
	}
	sp.public = sortedKeys(public)
	return sp
}

// destinationHost is the host part of an egress destination, lowercased, with
// an IPv6 address returned UNBRACKETED so it can be parsed as an address.
//
// It does not reuse normalizeHost (undeclared_llm.go), and the difference is
// not cosmetic. That one splits on the last colon, which leaves `[fd00::1]:443`
// as `[fd00::1]`: brackets and all, which netip.ParseAddr refuses, so every
// IPv6 destination fell through to the "this is a name" branch and was judged
// public. The sensor brackets EVERY IPv6 address it reports
// (ebpfcapture.destination uses net.JoinHostPort for exactly that reason), so
// that would have been every IPv6 flow in the estate, private ones included.
// Caught by a test rather than by review, which is why the private-range case
// lists an IPv6 unique-local address among its destinations.
func destinationHost(resource string) string {
	if host, _, err := net.SplitHostPort(resource); err == nil {
		return strings.ToLower(strings.TrimSpace(host))
	}
	// No port, so SplitHostPort refuses: a bare hostname, or a bare IPv6
	// address that may still be written in brackets.
	return strings.ToLower(strings.TrimSpace(strings.Trim(resource, "[]")))
}

// isPublicDestination reports whether a destination is one the enforcement
// point could have been asked to reach.
//
// It mirrors the plane's own refusal rules rather than inventing a second
// policy: RFC 1918, loopback, link-local (which is every cloud metadata
// service), RFC 6598 carrier-grade NAT, "this network", IPv6 unique-local and
// IPv6 link-local, plus the name suffixes that mean "inside a deployment".
// A copy of somebody else's list is a thing that drifts, so it is written here
// in the standard library's own vocabulary wherever that says the same thing,
// and the two ranges it has no predicate for are named with their RFCs. If the
// two ever disagree, this detector judges something the plane would have
// refused, which surfaces as a finding an operator can contradict rather than
// as silence.
//
// A destination that is a NAME and not an address is judged public unless it
// carries one of those suffixes. The sensor produces addresses, so this is the
// path a proxy or CASB export takes, and resolving the name here to be sure
// would put DNS in the detection path.
func isPublicDestination(host string) bool {
	for _, suffix := range []string{".internal", ".local", ".localdomain", ".cluster.local"} {
		if strings.HasSuffix(host, suffix) {
			return false
		}
	}
	if host == "localhost" || host == "" {
		return false
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return true // a name, and not one that says it is internal
	}
	// ::ffff:10.0.0.1 is 10.0.0.1 wearing an IPv6 hat, and every prefix test
	// below matches nothing at all against the mapped form.
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() {
		return false // loopback, link-local, multicast, unspecified
	}
	if addr.IsPrivate() {
		return false // RFC 1918, and IPv6 unique-local fc00::/7
	}
	for _, p := range []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"), // RFC 6598, carrier-grade NAT
		netip.MustParsePrefix("0.0.0.0/8"),     // RFC 1122, "this network"
	} {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// carriesSensorEvidence reports whether the eBPF sensor contributed anything to
// this graph, by either of the two identity shapes only it produces.
func carriesSensorEvidence(identities []*model.Identity) bool {
	for _, id := range identities {
		if ebpfcapture.IsClaimed(id.ID) || strings.HasPrefix(id.ID, ebpfcapture.IdentityPrefix) {
			return true
		}
	}
	return false
}

func sortedGoverned(m map[string]*governance) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
