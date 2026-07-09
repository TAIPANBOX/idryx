// Package bom builds an Agent Bill of Materials (Agent-BOM): a defensive
// governance inventory of an operator's own AI agent identities, so the
// operator can see and prove what each agent is made of (owner, runtime,
// attestation, tools/permissions, delegation chain, blast radius). Build
// only inventories the graph; it never scores or flags anything itself,
// that is internal/detect's job. See detectors/bom_incomplete.go for the
// companion detector that flags agents an Agent-BOM can't yet fully prove.
package bom

import (
	"sort"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// now is overridable in tests for a deterministic BOM timestamp, mirroring
// the detectors package's own now var (internal/detect/detectors/nhi.go).
var now = time.Now

// ToolRef is one permission/tool grant on an agent, projected from
// model.Permission down to the fields an Agent-BOM records.
type ToolRef struct {
	Name  string
	Admin bool
	Used  bool
}

// AgentBOM is the bill-of-materials entry for one agent identity: every field
// an operator needs to see and prove what the agent is made of.
type AgentBOM struct {
	ID          string
	Owner       string
	Runtime     string
	Parent      string
	Attestation string
	Privileged  bool
	Tools       []ToolRef

	// DelegationChain is the agent's resolved delegation chain
	// (graph.WalkDelegationChain): the agent itself first, then each
	// principal it acts on behalf of, immediate principal first, up to the
	// ultimate root. A length-1 chain (just the agent) means it acts
	// autonomously, with no OnBehalfOf principal.
	DelegationChain []string

	// BlastRadius is the sorted, de-duplicated set of permission names
	// reachable through DelegationChain (graph.BlastRadius): everything this
	// agent can do, directly or via delegation.
	BlastRadius []string
}

// BOM is the full Agent-BOM for a graph: one AgentBOM per agent-type
// identity, sorted by ID.
type BOM struct {
	GeneratedAt time.Time
	Agents      []AgentBOM
}

// Build assembles the Agent-BOM for every agent-type identity in g. Output is
// fully sorted (agents by ID, each agent's tools by name, each agent's blast
// radius by permission name), so Build is deterministic for a given graph
// regardless of ingestion or map-iteration order upstream.
func Build(g graph.Reader) BOM {
	index := make(map[string]*model.Identity)
	for _, id := range g.Identities() {
		index[id.ID] = id
	}

	var agents []AgentBOM
	for _, id := range g.Identities() {
		if !id.IsAgent() {
			continue
		}
		agents = append(agents, buildAgent(index, id))
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].ID < agents[j].ID })

	return BOM{GeneratedAt: now(), Agents: agents}
}

// buildAgent assembles one agent's BOM entry, reusing the graph package's
// delegation-chain walker and blast-radius helpers, the same ones
// excessive_agency and runaway_agent already use, rather than re-deriving
// either from scratch.
func buildAgent(index map[string]*model.Identity, id *model.Identity) AgentBOM {
	tools := make([]ToolRef, 0, len(id.Permissions))
	for _, p := range id.Permissions {
		tools = append(tools, ToolRef{Name: p.Name, Admin: p.Admin, Used: p.Used})
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })

	chain := graph.WalkDelegationChain(index, id.ID)

	blast := graph.BlastRadius(index, id.ID)
	radius := make([]string, 0, len(blast))
	for _, p := range blast {
		radius = append(radius, p.Name)
	}
	sort.Strings(radius)

	return AgentBOM{
		ID:              id.ID,
		Owner:           id.Owner,
		Runtime:         id.Runtime,
		Parent:          id.Parent,
		Attestation:     id.Attestation,
		Privileged:      id.Privileged,
		Tools:           tools,
		DelegationChain: chain,
		BlastRadius:     radius,
	}
}
