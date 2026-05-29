// Package model defines the core data types of the idryx identity graph.
package model

import "time"

// EventType is the normalized kind of an identity event.
type EventType string

const (
	EventLogin        EventType = "login"
	EventMFAChallenge EventType = "mfa_challenge"
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
}

// Identity is an actor in the graph with its chronological events.
type Identity struct {
	ID         string
	Privileged bool
	Events     []Event
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
