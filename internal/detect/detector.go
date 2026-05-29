// Package detect runs ITDR detectors over the identity graph.
package detect

import (
	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// Detector inspects the graph and returns alerts. Detection is deterministic:
// statistics and rules over the graph, never an LLM in the decision path.
type Detector interface {
	Name() string
	Detect(g *graph.Store) []model.Alert
}
