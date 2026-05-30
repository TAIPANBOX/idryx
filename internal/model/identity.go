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
)

// Permission is a single granted capability on an NHI (e.g. an attached IAM
// policy, an admin-equivalent grant, or an agent tool/scope).
type Permission struct {
	Name  string // policy, grant, or tool name
	Admin bool   // grants admin-equivalent access
	Used  bool   // whether this grant has been observed in use (when usage data exists)
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
	Runtime    string // where the agent executes, e.g. "langgraph", "bedrock"
	OnBehalfOf string // identity ID this agent acts on behalf of (one hop up)
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
