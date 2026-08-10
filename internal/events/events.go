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
	failed  int
}

// New opens a journal at path.
//
// An empty path returns nil, meaning "no bus destination configured", which is
// a configuration and not a fault. The caller adds a nil sink to nothing.
//
// `trustDomain` is the operator's own, and it is REQUIRED for anything to be
// written. See trustedID.
func New(path, runID, trustDomain string) (*Sink, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	w, err := event.NewWriter(path)
	if err != nil {
		return nil, fmt.Errorf("opening the idryx event journal at %s: %w", path, err)
	}
	return &Sink{w: w, runID: runID, trustDomain: strings.TrimSpace(trustDomain)}, nil
}

// trustedID turns idryx's own identity id into an envelope subject, or reports
// that it cannot.
//
// # THE TWO NAMESPACES, WHICH IS THE WHOLE OF THIS FUNCTION
//
// idryx inventories identities under its own ids: `agent:ops-helper`,
// `bob@example.com`, an AWS role ARN. The envelope wants
// `agent://<trust-domain>/<name>`. They are different namespaces and only one
// of them says which organisation an agent belongs to.
//
// The NAME comes from the inventory. The DOMAIN can only come from the
// operator, and this is the field trailryx refuses events on at the other end:
// its invariant 35 exists because, without the comparison, one valid producer
// could write records about every agent in the estate under one receiver's
// tenant. Inventing a domain here would be manufacturing exactly that.
//
// So with no configured domain nothing is written at all, and the count says
// so. That is a deployment that has not finished being configured, not a
// deployment with no findings, and the difference is the one this estate keeps
// paying for.
func (s *Sink) trustedID(identityID string) (string, bool) {
	if s.trustDomain == "" {
		return "", false
	}
	name, ok := strings.CutPrefix(identityID, "agent:")
	if !ok || name == "" {
		// Not an agent in idryx's own inventory: a person, a service account,
		// a machine identity. SPEC 6.1 has no subject kind for those, and a
		// fabricated one would put a name on an alert that did not do the
		// thing.
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

// Counts reports how many alerts were skipped for want of an agent subject and
// how many failed to write.
//
// Both are reported rather than kept private, because each is a number that
// means "this journal is not the whole story", and a reader who cannot see it
// has no way to know. The skip count is the interesting one: on an estate whose
// identities are mostly service accounts it will be most of them, and that is
// correct rather than broken.
func (s *Sink) Counts() (skipped, failed int) {
	if s == nil {
		return 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.skipped, s.failed
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
