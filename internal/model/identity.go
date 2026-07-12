// Package model defines the core data types of the idryx identity graph.
package model

import "time"

// EventType is the normalized kind of an identity event.
type EventType string

const (
	EventLogin        EventType = "login"
	EventMFAChallenge EventType = "mfa_challenge"
	EventEgress       EventType = "egress"
	EventOther        EventType = "other"

	// TokenFuse behavioral event types (agent-passport SPEC §6.2, source
	// "tokenfuse"). Values match the wire `type` field verbatim so the
	// tokenfuse connector can pass raw types straight through unchanged.
	EventBudgetExhausted EventType = "budget_exhausted"
	EventSustainedLoop   EventType = "sustained_loop"
	EventSpendSpike      EventType = "spend_spike"
	EventFanoutExplosion EventType = "fanout_explosion"
	EventBreakerTripped  EventType = "breaker_tripped"
	EventDLPBlock        EventType = "dlp_block"
	EventTaintBlock      EventType = "taint_block"
	EventMCPDrift        EventType = "mcp_drift"
)

// Event is a single normalized observation about an identity, produced by a
// source connector (e.g. the Okta System Log).
type Event struct {
	Time       time.Time
	IdentityID string // normalized actor, e.g. email
	Type       EventType
	Outcome    string // SUCCESS | FAILURE | DENY
	IP         string
	City       string
	Country    string
	Lat        float64
	Lon        float64
	Device     string // user agent or device fingerprint
	Resource   string // destination host/service for egress events (e.g. api.openai.com)

	// Severity is the producer-assigned severity for sources whose events
	// carry one (agent-passport SPEC §6.1: info|low|medium|high|critical,
	// e.g. tokenfuse). Empty for sources without the concept (Okta, Entra,
	// CloudTrail, egress) — the zero value leaves all existing connectors
	// and detectors untouched.
	Severity string

	// Source is the agent-event bus producer that emitted this event:
	// tokenfuse, wardryx, mockryx, verdryx, or any future emitter on the
	// shared taipanbox.dev/agent-event bus (agent-passport SPEC §6.3),
	// taken verbatim from the envelope's own `source` field, never a
	// hardcoded literal. Several bus producers can emit events for the same
	// agent identity, so this is recorded per event, not just once on the
	// Identity: Identity.Source recognizes only one connector name at a
	// time, but an agent's Events slice can legitimately mix tokenfuse
	// spend events with wardryx policy events with verdryx quality events,
	// all attached to the same identity node. Empty for sources without the
	// concept (Okta, Entra, CloudTrail, egress); the zero value leaves all
	// existing connectors and detectors untouched.
	Source string
}

// IdentityType distinguishes humans from non-human identities (NHIs) and, in
// later phases, agents. Defaulting to the zero value keeps existing ITDR code
// (which only ever dealt with humans) working unchanged.
type IdentityType string

const (
	IdentityHuman          IdentityType = ""                // default: human user
	IdentityServiceAccount IdentityType = "service_account" // IAM user/role, GCP SA, etc.
	IdentityKey            IdentityType = "key"             // access key / credential
	IdentityAgent          IdentityType = "agent"           // AI agent (Phase 5)
	IdentityMCPServer      IdentityType = "mcp_server"      // MCP server exposing tools to agents
)

// Permission is a single granted capability on an NHI (e.g. an attached IAM
// policy, an admin-equivalent grant, or an agent tool/scope).
type Permission struct {
	Name  string // policy, grant, or tool name
	Admin bool   // grants admin-equivalent access
	Used  bool   // whether this grant has been observed in use (when usage data exists)

	// ARN is the connector-reported real resource identifier for this grant,
	// when the source provides one (e.g. an AWS attached managed policy's
	// PolicyArn). It is authoritative and must be preferred over any
	// heuristic reconstruction: an AWS customer-managed policy's real ARN is
	// arn:aws:iam::<account-id>:policy/<name>, which cannot be derived from
	// the name alone (only the aws-managed arn:aws:iam::aws:policy/<name>
	// shape can). Empty when the source has no ARN concept for the grant
	// (e.g. an inline policy, or a GCP/Azure/agent permission).
	ARN string
}

// Identity is an actor in the graph: a human, service account, key, or agent.
type Identity struct {
	ID         string
	Type       IdentityType
	Privileged bool
	Events     []Event

	// NHI metadata (zero for humans).
	Source      string       // connector that produced it, e.g. "aws_iam"
	Owner       string       // mapped owner, when known
	Created     time.Time    // when the identity was created
	LastUsed    time.Time    // last observed use (zero if never)
	Permissions []Permission // granted permissions

	// Agent / delegation metadata (zero for non-agents).
	Runtime string // where the agent executes, e.g. "langgraph", "bedrock"

	// OnBehalfOf is the agent's delegation chain (agent-passport SPEC §5):
	// ordered root-first, the last element is the immediate principal that
	// invoked this identity. Entries are agent:// or user:// URIs, or a
	// legacy plain identity ID — all treated as opaque strings. An empty
	// chain means the identity acts autonomously.
	OnBehalfOf []string

	// Parent is the agent's static provisioning parent (agent-passport SPEC
	// §4.2: "the agent that provisions/spawns this one, if any — an org-chart
	// relationship"), as recorded in its Passport document. It is distinct
	// from OnBehalfOf, which is the *dynamic*, per-request delegation chain
	// (SPEC §5) — a sub-agent's static Parent and its runtime OnBehalfOf
	// principal are usually, but not necessarily, the same identity. Zero
	// value means no Passport (or a Passport without `parent`) was ingested
	// for this identity.
	Parent string

	// Attestation is how the org binds this identity's name to a workload
	// (agent-passport SPEC §4.3: attestation.method — one of "none", "oidc",
	// "spiffe-svid", "enclave-key", "mtls-cert"), as recorded in its Passport
	// document. The zero value means unknown/none: either no Passport was
	// ingested for this identity, or its Passport explicitly declared
	// "none". Both are indistinguishable on purpose — SPEC §4.3 treats "none"
	// as the honest default and expects idryx to surface it, not hide the
	// distinction from "not evaluated yet".
	Attestation string

	// MCP metadata (zero for non-MCP identities).
	Shadow bool // MCP server in use but absent from the sanctioned registry
}

// IsAgent reports whether the identity is an AI agent.
func (i *Identity) IsAgent() bool { return i.Type == IdentityAgent }

// IsNHI reports whether the identity is non-human.
func (i *Identity) IsNHI() bool { return i.Type != IdentityHuman }

// HasAdmin reports whether any granted permission is admin-equivalent.
func (i *Identity) HasAdmin() bool {
	for _, p := range i.Permissions {
		if p.Admin {
			return true
		}
	}
	return false
}

// Severity ranks the urgency of an alert.
type Severity int

const (
	SeverityNone Severity = iota
	SeverityInfo
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	case SeverityInfo:
		return "info"
	default:
		return "none"
	}
}

// Alert is a detection result tied to an identity.
type Alert struct {
	Detector   string
	IdentityID string
	Severity   Severity
	Time       time.Time
	Summary    string
}
