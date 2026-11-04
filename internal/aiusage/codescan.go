package aiusage

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
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

// Bounds on a document this package did not write. A qryx file is a file
// somebody else could have edited, so what is read from it is cut to sizes a
// report can carry, and what is cut is counted in the limits and never dropped
// in silence.
const (
	MaxCodeScanBytes = 32 << 20 // the largest document read at all
	maxProviders     = 512      // distinct provider ids carried
	maxLabels        = 32       // labels kept for one provider
	maxScanLimits    = 64       // limits carried from the scan's own list
)

// validProviderID reports whether s has the grammar of a registered provider
// id (agent-passport SPEC 4.7): lowercase letters, digits, dot, underscore and
// hyphen, starting with a letter or digit, at most 64 bytes. A string that
// does not is not an id, whatever it was meant to say, and a join on it could
// only be a spelling.
func validProviderID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case i > 0 && (c == '.' || c == '_' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// LoadCodeScan reads a qryx ai-inventory document from a file, refusing one
// larger than MaxCodeScanBytes before it is held in memory.
func LoadCodeScan(path string) (*CodeScan, error) {
	f, err := os.Open(path) // #nosec G304 -- path is the operator's --code-scan flag, the same trust as the other input paths
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxCodeScanBytes+1))
	if err != nil {
		return nil, err
	}
	return ParseCodeScan(data)
}

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
	if len(data) > MaxCodeScanBytes {
		return nil, fmt.Errorf("parse ai-inventory: the document is larger than %d bytes, which is more than a source scan of one estate writes; it was not read", MaxCodeScanBytes)
	}
	var doc codeScanDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse ai-inventory: %w", err)
	}
	if doc.Schema != CodeScanSchema {
		return nil, fmt.Errorf(
			"parse ai-inventory: schema is %q, want %q; a document this reader does not know would be reported as an empty code column, which reads as an estate whose code reaches no model",
			escape(doc.Schema, 80), CodeScanSchema)
	}

	scan := &CodeScan{
		Root:        escape(doc.Root, maxStored),
		GeneratedAt: escape(doc.GeneratedAt, maxStored),
		Tool:        escape(doc.Tool.Name+" "+doc.Tool.Version, maxStored),
		Providers:   map[string]CodeScanEntry{},
	}
	for i, l := range doc.Limits {
		if i == maxScanLimits {
			scan.Limits = append(scan.Limits, fmt.Sprintf(
				"The scan listed %d limit(s) and this report carries the first %d.", len(doc.Limits), maxScanLimits))
			break
		}
		scan.Limits = append(scan.Limits, escape(l, maxStored))
	}

	var unnamed, unnamedSites, notID, notIDSites, beyond, beyondSites int
	for _, e := range doc.Entries {
		sites := len(e.Occurrences)
		p := normalize(e.Provider)
		switch {
		case p == "":
			unnamed++
			unnamedSites += sites
			continue
		case !validProviderID(p):
			notID++
			notIDSites += sites
			continue
		}
		entry, known := scan.Providers[p]
		if !known && len(scan.Providers) >= maxProviders {
			beyond++
			beyondSites += sites
			continue
		}
		entry.Sites += sites
		if label := strings.TrimSpace(e.Label); label != "" && len(entry.Labels) < maxLabels {
			entry.Labels = append(entry.Labels, escape(label, maxStored))
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
	if notID > 0 {
		scan.Limits = append(scan.Limits, fmt.Sprintf(
			"The scan named %d row(s) at %d site(s) with something that is not a provider id, so they appear in no row below.",
			notID, notIDSites))
	}
	if beyond > 0 {
		scan.Limits = append(scan.Limits, fmt.Sprintf(
			"The scan named more than %d providers; %d row(s) at %d site(s) for the rest are not carried.",
			maxProviders, beyond, beyondSites))
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
