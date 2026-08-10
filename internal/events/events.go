// Package events puts idryx's findings on the estate's shared event bus.
//
// # WHY THIS EXISTS
//
// Until it did, idryx's detections left by OTLP and by Slack and nowhere else,
// so agent-passport SPEC 6.2 listed every idryx type as RESERVED, not emitted.
// The consequence was larger than a missing row: heraldyx never mailed an
// identity finding and trailryx never recorded one, because neither reads OTLP
// and neither reads Slack. A detector that fires into a channel the governance
// planes do not read is a detector nobody acts on.
//
// # ONE TYPE, NOT TWENTY-FIVE
//
// `@yurii 2026-08-10`, asked with both shapes measured and costed: "перший,
// один тип".
//
// idryx ships 25 detectors and the registry reserved seven names, two of which
// had no producer at all. Registering 25 types would put 25 rows in SPEC 6.2,
// 25 severities beside them, 25 entries in heraldyx's render catalogue, and
// would make every new detector a nine-repository spec change, which is the
// tax that stops detectors being written.
//
// So the bus carries `identity_finding` and the detector name travels in
// `data.detector`. The 25 names stay idryx's own vocabulary, where they can
// change without anybody else editing anything, and a consumer needs one
// handler rather than 25.
//
// It also settles a collision by construction: `mcp_drift` is a registered
// tokenfuse type AND an idryx detector name. Under one type, tokenfuse keeps
// the wire string and idryx's detector of that name is `data.detector`, so no
// consumer is ever handed two producers for one name.
//
// # WHAT `data` CARRIES, AND WHAT IT REFUSES TO
//
// The detector name, and nothing else.
//
// An Alert also has a Summary, which is prose a detector wrote and which
// routinely names the identity it is about, and an IdentityID, which for a
// human identity is an email address. Both are personal data, and the event is
// the part designed to be kept, so neither is written. The subject is already
// in `agent_id`, where it is typed, validated and erasable, and heraldyx
// renders its own explanation per type rather than repeating a producer's text.
package events

import (
	"fmt"
	"strings"
	"sync"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/agent-stack-go/passport"

	"github.com/TAIPANBOX/idryx/internal/ebpfcapture"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// The envelope's fixed fields, per agent-passport SPEC 6.
const (
	Schema = "taipanbox.dev/agent-event/v0.2"
	Source = "idryx"

	// TypeIdentityFinding is the one type this product emits.
	TypeIdentityFinding = "identity_finding"
)

// Outcome is what happened to one alert, reported back rather than logged
// inside, because a skip that is only ever logged is a skip nobody counts.
type Outcome int

const (
	// Written: the alert reached the bus.
	Written Outcome = iota
	// SkippedNoAgentSubject: the finding is about an identity that is not an
	// agent, so it has no subject this envelope can carry.
	//
	// This is the common case rather than an error. idryx inventories service
	// accounts, machine identities and people as well as agents, and SPEC 6.1
	// is explicit that an observation with no agent subject cannot travel in
	// this stream at all and that a producer MUST skip rather than fabricate
	// one: a fallback id or the org's own id in that field makes every
	// downstream count wrong and puts a name on an alert that did not do the
	// thing.
	//
	// Those findings still reach OTLP and Slack, which is where they went
	// before this package existed.
	SkippedNoAgentSubject
	// SkippedClaimedSubject: the finding is about an identity a PROCESS
	// asserted about itself, read from AGENT_PASSPORT_ID by the eBPF sensor
	// (agent-passport SPEC 3.3) and recorded under the `claimed:` prefix.
	//
	// Counted apart from SkippedNoAgentSubject because the two are different
	// stories and only one of them is permanent. "Not an agent" is a person or
	// a service account, and no envelope change would ever give it a subject.
	// This one IS an agent, or says it is, and idryx is the only party that
	// knows the difference: the envelope has one subject field and no way to
	// qualify it, and SPEC 6.1 obliges a consumer to ignore `data` keys it does
	// not know, so writing the claim into `agent_id` would deliver a
	// self-declaration to every conforming consumer as an established fact.
	// SPEC 3.3 forbids exactly that, and growing the envelope a subject basis
	// is a change every consumer makes together.
	//
	// So the finding is held back, and the number is the honest form of the
	// gap: an operator can see how much the bus is not being told. It still
	// reaches OTLP and Slack, where the `claimed:` prefix travels with it and
	// 3.3's "make the distinction visible" is satisfied.
	SkippedClaimedSubject
	// WriteFailed: the journal could not be appended to.
	WriteFailed
)

// Sink writes findings to idryx's own agent-event journal.
//
// It implements `sink.Sink`, so it plugs into the pipeline that already fans
// alerts out to Slack and OTLP rather than adding a second one. Nothing about
// the existing destinations changes: this is one more reader of the same
// batch.
type Sink struct {
	mu sync.Mutex
	w  *event.Writer

	// RunID labels this process's findings. One per run, because a scan is the
	// unit an operator repeats.
	runID string

	// trustDomain is the operator's own. Empty means nothing is written: see
	// trustedID.
	trustDomain string

	skipped int
	claimed int
	failed  int
}

// New opens a journal at path.
//
// An empty path returns nil, meaning "no bus destination configured", which is
// a configuration and not a fault. The caller adds a nil sink to nothing.
//
// `trustDomain` is the operator's own, and it is REQUIRED for anything to be
// written. See trustedID.
//
// It is also checked HERE rather than at write time, and the reason is the
// failure that check exists to prevent. One capital letter is enough:
// `Acme.Example` builds `agent://Acme.Example/ops-helper`, which the envelope's
// grammar rejects, so every finding about the operator's own inventory would be
// silently skipped while every already-canonical subject was still written.
// That is a journal that reads as whole while missing half the estate, and the
// empty-domain gate below never covered it, because the domain is not empty.
//
// The check is a probe against the shared validator rather than a pattern
// written here: a second grammar in this repository is the drift AGENTS.md
// invariant 3 exists to prevent, and it would drift toward accepting more.
func New(path, runID, trustDomain string) (*Sink, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	domain := strings.TrimSpace(trustDomain)
	if domain != "" {
		if err := passport.ValidateAgentURI("agent://" + domain + "/probe"); err != nil {
			return nil, fmt.Errorf("IDRYX_TRUST_DOMAIN=%q cannot form a subject the event envelope accepts "+
				"(agent://%s/<name> is not a valid agent id: %v). It is a DNS name your organisation controls, "+
				"lowercase, e.g. acme.example", trustDomain, domain, err)
		}
	}
	w, err := event.NewWriter(path)
	if err != nil {
		return nil, fmt.Errorf("opening the idryx event journal at %s: %w", path, err)
	}
	return &Sink{w: w, runID: runID, trustDomain: domain}, nil
}

// trustedID turns idryx's own identity id into an envelope subject, or reports
// that it cannot.
//
// # THE THREE NAMESPACES, WHICH IS THE WHOLE OF THIS FUNCTION
//
// idryx inventories identities under ids from three different places, and the
// first version of this function knew about one of them.
//
//  1. Its own short form, `agent:ops-helper`, from the `agents` inventory
//     connector. A NAME and nothing else. The envelope wants
//     `agent://<trust-domain>/<name>`, and only the operator can say the
//     domain, so the subject is BUILT here and then validated.
//  2. A canonical `agent://<domain>/<name>` that arrived already complete: from
//     a Passport document (`internal/ingest/passport`, which takes the
//     document's own id), and from every agent-event producer on the bus
//     (tokenfuse, wardryx, mockryx, verdryx, scopyx), whose envelopes carry it.
//     Nothing is built. It travels as itself.
//  3. Everything else: a person, a service account, an ARN, a `proc:` identity
//     the eBPF sensor could only describe, a `claimed:` one a process asserted
//     about itself. SPEC 6.1 has no subject kind for any of these and requires
//     a producer to skip rather than fabricate one.
//
// # WHY 2 IS ITS OWN BRANCH AND NOT A SPECIAL CASE OF 1
//
// A canonical URI also begins with `agent:`. Cutting that prefix and prepending
// the operator's domain therefore built a second scheme onto a string that
// already had one, and the shared validator accepted the result because its
// pattern lets the path hold empty segments.
//
// @measured 2026-08-10, `IDRYX_TRUST_DOMAIN=acme-bank.example idryx detect
// --load egress:testdata/egress.json --passports 'testdata/passports/*.json'`:
// the journal received
// `agent://acme-bank.example///acme-bank.example/eng/standalone`. The finding
// was not lost, it was published about an agent that does not exist, and the
// subject was the operator's OWN registered agent, read from its own Passport.
//
// The bus case is worse in kind rather than in number. An agent of
// `acme-bank.example` observed by a deployment configured for `acme.example`
// came out as `agent://acme.example///acme-bank.example/...`: a foreign
// tenant's agent carrying OUR trust domain. trailryx's invariant 35 compares
// exactly that field to decide whether it may record an event at all, so the
// mangle did not merely corrupt the subject, it walked it past the one check in
// the estate that exists to stop it.
//
// # SO A CANONICAL SUBJECT TRAVELS UNCHANGED, INCLUDING A FOREIGN DOMAIN
//
// Not compared against the operator's own, and not suppressed. Tenancy is the
// RECEIVER's rule: trailryx invariant 35 is a boundary check, and a producer
// that pre-enforced it would only hide the mismatch from the boundary that owns
// it. Passing the true subject through restores that check's input and leaves
// the finding in idryx's own journal either way, which is the part designed to
// be kept. A foreign domain here is usually a misconfigured
// IDRYX_TRUST_DOMAIN, and under this rule it is visible instead of silent.
//
// With no configured domain nothing is written at all, and the count says so.
// That stays all-or-nothing on purpose even though branch 2 needs no domain:
// letting canonical subjects through while the inventory's own are silently
// dropped would produce a partial journal that reads as a whole one.
func (s *Sink) trustedID(identityID string) (string, bool) {
	if s.trustDomain == "" {
		return "", false
	}
	// Namespace 2 first, and the order is the fix: this test has to run before
	// anything cuts an `agent:` prefix, because a canonical URI carries one.
	if passport.ValidateAgentURI(identityID) == nil {
		return identityID, true
	}
	name, ok := strings.CutPrefix(identityID, "agent:")
	if !ok || name == "" {
		return "", false
	}
	if strings.HasPrefix(name, "/") {
		// `agent://`, `agent:///bot`: a canonical URI that failed the test
		// above, so what is left after the cut is the husk of a broken one and
		// not an inventory name. Building from it gives
		// `agent://<domain>///bot`, which the shared validator accepts because
		// its path class allows empty segments, so this would be the same
		// fabrication one namespace narrower. It is reachable: agents.json is
		// taken verbatim, and the envelope only checks that `agent_id` is
		// non-empty.
		return "", false
	}
	// Built rather than parsed, then validated, so a name idryx accepted but
	// the envelope's grammar does not is refused here rather than written.
	id := "agent://" + s.trustDomain + "/" + name
	if passport.ValidateAgentURI(id) != nil {
		return "", false
	}
	return id, true
}

func (s *Sink) Name() string { return "agent-event" }

// Close flushes and closes.
func (s *Sink) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.w == nil {
		return nil
	}
	return s.w.Close()
}

// Send writes one event per alert that has an agent subject.
//
// No severity threshold of its own, deliberately. Slack and OTLP filter because
// they page a person; this is a record, and a record filtered by severity is a
// record that answers "what happened" with "the parts somebody thought were
// interesting". heraldyx applies the threshold at the other end, which is
// where it belongs, because it is the plane that writes to a human.
func (s *Sink) Send(alerts []model.Alert) error {
	if s == nil || len(alerts) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var firstErr error
	for _, a := range alerts {
		if out := s.write(a); out == WriteFailed && firstErr == nil {
			firstErr = fmt.Errorf("writing an identity_finding for detector %q", a.Detector)
		}
	}
	return firstErr
}

func (s *Sink) write(a model.Alert) Outcome {
	agentID, ok := s.trustedID(a.IdentityID)
	if !ok {
		if ebpfcapture.IsClaimed(a.IdentityID) {
			s.claimed++
			return SkippedClaimedSubject
		}
		s.skipped++
		return SkippedNoAgentSubject
	}

	e := event.Event{
		Schema:   Schema,
		TS:       a.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		Source:   Source,
		Type:     TypeIdentityFinding,
		AgentID:  agentID,
		Severity: severityWire(a.Severity),
		RunID:    s.runID,
		Data: map[string]any{
			// The detector, and nothing else. See the package comment: the
			// Summary is prose that names people and the IdentityID is already
			// the typed subject above.
			"detector": a.Detector,
		},
	}
	if err := s.w.Write(e); err != nil {
		s.failed++
		return WriteFailed
	}
	return Written
}

// Counts reports how many alerts were held back and why, and how many failed to
// write.
//
// All three are reported rather than kept private, because each is a number that
// means "this journal is not the whole story", and a reader who cannot see it
// has no way to know.
//
// `skipped` is the expected one: on an estate whose identities are mostly
// service accounts and people it will be most of them, and that is correct
// rather than broken. `claimed` is the one worth acting on, because it is a gap
// rather than a property: those findings are about agents, and what stops them
// is that the envelope cannot yet say a subject was self-declared. See
// SkippedClaimedSubject.
func (s *Sink) Counts() (skipped, claimed, failed int) {
	if s == nil {
		return 0, 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.skipped, s.claimed, s.failed
}

// severityWire maps idryx's bands onto the envelope's five.
//
// Every band maps to something: an unknown one becomes "medium" rather than
// being dropped, because a finding that vanished for want of a severity name
// would be the worst possible way to lose one.
func severityWire(sev model.Severity) string {
	switch sev {
	case model.SeverityCritical:
		return "critical"
	case model.SeverityHigh:
		return "high"
	case model.SeverityMedium:
		return "medium"
	case model.SeverityLow:
		return "low"
	case model.SeverityInfo:
		return "info"
	default:
		return "medium"
	}
}
