package aiusage

import (
	"encoding/json"
	"fmt"
	"sort"
)

// CodeScanSchema is the document this package reads: the machine-readable AI
// inventory qryx writes with `qryx scan --format ai-inventory`.
//
// It is checked rather than assumed, and a document that does not carry it is
// refused. A source scan is the one leg of this inventory with no subject and
// no second opinion, so a reader that silently accepted an unrecognised shape
// would report an empty coded column, which is indistinguishable from an
// estate whose code reaches no model at all.
const CodeScanSchema = "qryx.ai-inventory/v1"

// CodeScan is the coded leg, reduced to what the reconciliation needs: which
// providers the source tree can reach, in how many places, under what labels.
//
// The document's per-occurrence file and line are deliberately dropped here.
// They belong to a repository and this report is about an estate; carrying
// them would invite a reader to treat a path in one operator's checkout as an
// address in the graph, which it is not.
type CodeScan struct {
	Root        string
	GeneratedAt string
	Tool        string
	Limits      []string
	Providers   map[string]CodeScanEntry
}

// CodeScanEntry is one provider's presence in the code.
type CodeScanEntry struct {
	Sites  int
	Labels []string
}

// codeScanDoc mirrors the published shape. Only the fields this package reads
// are declared: unknown fields are ignored, which is the same forward
// compatibility SPEC 6.1 requires of every consumer in this estate.
type codeScanDoc struct {
	Schema      string `json:"schema"`
	GeneratedAt string `json:"generatedAt"`
	Root        string `json:"root"`
	Tool        struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"tool"`
	Entries []struct {
		Provider    string `json:"provider"`
		Role        string `json:"role"`
		Label       string `json:"label"`
		Occurrences []struct {
			File string `json:"file"`
			Line int    `json:"line"`
		} `json:"occurrences"`
	} `json:"entries"`
	Limits []string `json:"limits"`
}

// ParseCodeScan reads a qryx ai-inventory document.
//
// A row whose provider is empty is skipped and NOT an error, and that is the
// interesting case rather than an edge one: qryx writes an empty provider for
// a framework row on purpose, meaning the tree reaches a model through
// LangChain or LiteLLM and which one is chosen by configuration a text scan
// cannot read. There is no provider to reconcile, so it cannot appear in a
// per-provider table. It is counted, and the count goes into the limits, so a
// reader learns the code reaches models this report cannot name.
func ParseCodeScan(data []byte) (*CodeScan, error) {
	var doc codeScanDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse ai-inventory: %w", err)
	}
	if doc.Schema != CodeScanSchema {
		return nil, fmt.Errorf(
			"parse ai-inventory: schema is %q, want %q; a document this reader does not know would be reported as an empty code column, which reads as an estate whose code reaches no model",
			doc.Schema, CodeScanSchema)
	}

	scan := &CodeScan{
		Root:        doc.Root,
		GeneratedAt: doc.GeneratedAt,
		Tool:        doc.Tool.Name + " " + doc.Tool.Version,
		Limits:      doc.Limits,
		Providers:   map[string]CodeScanEntry{},
	}

	unnamed := 0
	unnamedSites := 0
	for _, e := range doc.Entries {
		sites := len(e.Occurrences)
		p := normalize(e.Provider)
		if p == "" {
			unnamed++
			unnamedSites += sites
			continue
		}
		entry := scan.Providers[p]
		entry.Sites += sites
		if e.Label != "" {
			entry.Labels = append(entry.Labels, e.Label)
		}
		scan.Providers[p] = entry
	}
	for p, entry := range scan.Providers {
		entry.Labels = dedupeSorted(entry.Labels)
		scan.Providers[p] = entry
	}
	if unnamed > 0 {
		scan.Limits = append(scan.Limits, fmt.Sprintf(
			"The scan found %d row(s) at %d site(s) that reach a model through an indirection it could not resolve, so they name no provider and appear in no row below.",
			unnamed, unnamedSites))
	}
	return scan, nil
}

// SortedProviders is the providers the scan named, for a caller that wants to
// report the coded side on its own.
func (c *CodeScan) SortedProviders() []string {
	out := make([]string, 0, len(c.Providers))
	for p := range c.Providers {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
