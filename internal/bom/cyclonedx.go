package bom

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

// cyclonedxDoc is the top-level CycloneDX-flavoured document a BOM renders
// into. It intentionally emits only the subset of the CycloneDX 1.6 schema
// an Agent-BOM needs: metadata, components (one per agent, tools nested
// underneath), and dependencies (delegation parents). It mirrors the shape
// of qryx's internal/report/cbom.go (bomFormat/specVersion/metadata/
// components) so the two BOM outputs read as one family, but this one has
// no metadata.component: an Agent-BOM inventories many agents, not one
// scanned root.
type cyclonedxDoc struct {
	BOMFormat    string                `json:"bomFormat"`
	SpecVersion  string                `json:"specVersion"`
	Version      int                   `json:"version"`
	Metadata     cyclonedxMetadata     `json:"metadata"`
	Components   []cyclonedxComponent  `json:"components"`
	Dependencies []cyclonedxDependency `json:"dependencies,omitempty"`
}

type cyclonedxMetadata struct {
	Timestamp string          `json:"timestamp"`
	Tools     []cyclonedxTool `json:"tools"`
}

type cyclonedxTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// cyclonedxComponent is one agent (top level) or one of its tools (nested,
// via Components). CycloneDX 1.6 components are self-similar: a component's
// own Components field can hold sub-components, so a tool is modeled as a
// component nested under the agent that grants it, no separate type needed.
type cyclonedxComponent struct {
	Type       string               `json:"type"`
	BOMRef     string               `json:"bom-ref,omitempty"`
	Name       string               `json:"name"`
	Properties []cyclonedxProperty  `json:"properties,omitempty"`
	Components []cyclonedxComponent `json:"components,omitempty"`
}

type cyclonedxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// cyclonedxDependency expresses one agent's delegation parents: Ref depends
// on (acts on behalf of) every principal in DependsOn.
type cyclonedxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// JSON writes b as a CycloneDX-shaped JSON document to w. version identifies
// the idryx build that produced it (metadata.tools[0].version), mirroring
// qryx's report.CBOM(w, res, version).
func JSON(w io.Writer, b BOM, version string) error {
	doc := cyclonedxDoc{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: cyclonedxMetadata{
			Timestamp: b.GeneratedAt.UTC().Format(time.RFC3339),
			Tools: []cyclonedxTool{
				{Vendor: "idryx", Name: "idryx", Version: version},
			},
		},
		Components: []cyclonedxComponent{},
	}
	for _, a := range b.Agents {
		doc.Components = append(doc.Components, toComponent(a))
		if dep, ok := toDependency(a); ok {
			doc.Dependencies = append(doc.Dependencies, dep)
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// toComponent renders one agent as a CycloneDX component: bom-ref/name are
// the agent id, properties carry the governance-critical fields (owner,
// runtime, parent, attestation, privileged) plus delegation/blast-radius
// context, and each tool/permission becomes a nested sub-component, so the
// document literally answers "what is this agent made of".
//
// Property order below is a fixed declaration order, not a lexicographic
// sort: the determinism a golden-JSON test needs only requires the same
// order on every call, which a fixed literal already guarantees. Where a
// value instead comes from a graph walk or a permission slice (tools, blast
// radius), Build has already sorted those by name before they reach here.
func toComponent(a AgentBOM) cyclonedxComponent {
	comp := cyclonedxComponent{
		Type:   "application",
		BOMRef: a.ID,
		Name:   a.ID,
		Properties: []cyclonedxProperty{
			{Name: "idryx:owner", Value: a.Owner},
			{Name: "idryx:runtime", Value: a.Runtime},
			{Name: "idryx:parent", Value: a.Parent},
			{Name: "idryx:attestation", Value: attestationOr(a.Attestation)},
			{Name: "idryx:privileged", Value: boolString(a.Privileged)},
			{Name: "idryx:delegationDepth", Value: fmt.Sprintf("%d", len(a.DelegationChain)-1)},
			{Name: "idryx:onBehalfOf", Value: strings.Join(onBehalfOf(a.DelegationChain), ",")},
			{Name: "idryx:blastRadiusCount", Value: fmt.Sprintf("%d", len(a.BlastRadius))},
			{Name: "idryx:blastRadius", Value: strings.Join(a.BlastRadius, ",")},
		},
	}
	for _, tool := range a.Tools {
		comp.Components = append(comp.Components, cyclonedxComponent{
			Type:   "library",
			BOMRef: a.ID + "#tool:" + tool.Name,
			Name:   tool.Name,
			Properties: []cyclonedxProperty{
				{Name: "idryx:admin", Value: boolString(tool.Admin)},
				{Name: "idryx:used", Value: boolString(tool.Used)},
			},
		})
	}
	return comp
}

// toDependency expresses an agent's delegation parents (agent-passport SPEC
// Sec 5 OnBehalfOf, resolved via graph.WalkDelegationChain) as a CycloneDX
// dependency edge: the agent depends on (acts on behalf of) every principal
// above it in the chain. An autonomous agent (a chain of just itself) gets
// no entry at all rather than an empty "dependsOn": [] -- CycloneDX treats a
// missing entry as "no dependency information" and an empty array as "known
// to have none"; an autonomous agent is the latter, but omitting the entry
// keeps the common case out of the document.
func toDependency(a AgentBOM) (cyclonedxDependency, bool) {
	if len(a.DelegationChain) < 2 {
		return cyclonedxDependency{}, false
	}
	return cyclonedxDependency{Ref: a.ID, DependsOn: onBehalfOf(a.DelegationChain)}, true
}

// onBehalfOf strips the agent itself (chain[0]) from a resolved delegation
// chain, returning just the principals it acts on behalf of, or nil for an
// autonomous agent.
func onBehalfOf(chain []string) []string {
	if len(chain) < 2 {
		return nil
	}
	return chain[1:]
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// attestationOr renders an Identity.Attestation value for display, spelling
// out the zero value as "none" (agent-passport SPEC Sec 4.3 treats an absent
// attestation.method the same as an explicit "none": both mean the org has
// not bound this identity's name to a workload).
func attestationOr(a string) string {
	if a == "" {
		return "none"
	}
	return a
}

// Human writes a short, readable summary of the BOM to w: one line per agent
// with its owner/runtime/attestation/privilege state, tool count, and blast
// radius size, in the same order as JSON.
func Human(w io.Writer, b BOM) {
	fmt.Fprintf(w, "idryx agent-bom: %d agent(s)\n\n", len(b.Agents))
	if len(b.Agents) == 0 {
		fmt.Fprintln(w, "No agent identities in the graph.")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "AGENT\tOWNER\tRUNTIME\tATTESTATION\tPRIVILEGED\tTOOLS\tBLAST RADIUS")
	for _, a := range b.Agents {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%t\t%d\t%d\n",
			a.ID, valueOr(a.Owner, "-"), valueOr(a.Runtime, "-"), attestationOr(a.Attestation),
			a.Privileged, len(a.Tools), len(a.BlastRadius))
	}
	_ = tw.Flush()
}

func valueOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
