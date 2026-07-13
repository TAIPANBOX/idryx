package detectors

import (
	"testing"

	"github.com/TAIPANBOX/idryx/internal/ebpfcapture"
	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

func unmanagedEgressGraph() *graph.Store {
	g := graph.New(nil)
	// eBPF-only identity reaching a known LLM provider -> high
	g.AddEvent(egress(ebpfcapture.Identity("python3"), "api.openai.com:443"))
	// eBPF-only identity reaching an unremarkable host -> medium
	g.AddEvent(egress(ebpfcapture.Identity("curl"), "203.0.113.5:443"))
	// eBPF-only identity with no egress events at all -> nothing to flag
	g.AddIdentity(model.Identity{ID: ebpfcapture.Identity("idle"), Source: "ebpf"})
	// a normally-attributed identity (no "proc:" prefix) -> not this detector's job, even reaching an LLM
	g.AddEvent(egress("arn:role/etl", "api.anthropic.com:443"))
	return g
}

func TestUnmanagedEgress(t *testing.T) {
	withFixedNow(t)
	got := detect(NewUnmanagedEgress(), unmanagedEgressGraph())

	if a, ok := got[ebpfcapture.Identity("python3")]; !ok {
		t.Error("eBPF-only identity reaching a known LLM API should be flagged")
	} else if a.Severity != model.SeverityHigh {
		t.Errorf("severity = %v, want high", a.Severity)
	}
	if a, ok := got[ebpfcapture.Identity("curl")]; !ok {
		t.Error("eBPF-only identity with any egress should be flagged")
	} else if a.Severity != model.SeverityMedium {
		t.Errorf("severity = %v, want medium", a.Severity)
	}
	if _, ok := got[ebpfcapture.Identity("idle")]; ok {
		t.Error("eBPF-only identity with no captured egress must not be flagged")
	}
	if _, ok := got["arn:role/etl"]; ok {
		t.Error("non-eBPF identity must not be flagged by unmanaged_egress, even reaching an LLM API")
	}
}
