package aiusage

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Schema names the document JSON writes. A consumer reads it first and refuses
// a version it does not know, the same discipline the source scan this report
// consumes applies to itself.
const Schema = "idryx.ai-inventory/v1"

type document struct {
	Schema      string      `json:"schema"`
	Tool        string      `json:"tool"`
	GeneratedAt string      `json:"generated_at"`
	CodeScan    CodeScanRef `json:"code_scan"`
	Rows        []Row       `json:"rows"`
	Limits      []string    `json:"limits"`
}

// JSON writes the report for another program.
func JSON(w io.Writer, r Report, version, generatedAt string) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(document{
		Schema:      Schema,
		Tool:        "idryx " + version,
		GeneratedAt: generatedAt,
		CodeScan:    r.CodeScan,
		Rows:        r.Rows,
		Limits:      r.Limits,
	})
}

// Human writes the report for a person.
//
// The three columns are the point, so they are shown as counts with the shape
// of the disagreement beside them rather than as a verdict. This report ranks
// nothing: a provider found only in code is often correct, a provider observed
// and never declared is often not, and which is which is a judgement about an
// estate that this tool does not have.
func Human(w io.Writer, r Report) {
	fmt.Fprintln(w, "AI usage across three sources")
	fmt.Fprintln(w)

	if r.CodeScan.Present {
		fmt.Fprintf(w, "code scan: %s", r.CodeScan.Root)
		if r.CodeScan.Tool != "" {
			fmt.Fprintf(w, " (%s", strings.TrimSpace(r.CodeScan.Tool))
			if r.CodeScan.GeneratedAt != "" {
				fmt.Fprintf(w, ", %s", r.CodeScan.GeneratedAt)
			}
			fmt.Fprint(w, ")")
		}
		fmt.Fprintln(w)
	} else {
		// Said first and plainly. Without it every zero in the last column
		// reads as a measurement, and it is an absence of one.
		fmt.Fprintln(w, "code scan: none supplied, so the CODE column is not a measurement.")
		fmt.Fprintln(w, "           run `qryx scan --format ai-inventory <path>` and pass it with --code-scan.")
	}
	fmt.Fprintln(w)

	if len(r.Rows) == 0 {
		fmt.Fprintln(w, "No provider is named by any of the three sources.")
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "PROVIDER\tDECLARED\tOBSERVED\tIN CODE\tWHERE THEY DISAGREE")
		for _, row := range r.Rows {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
				row.Provider,
				count(len(row.DeclaredBy), "agent"),
				count(len(row.ObservedBy), "agent"),
				codeCell(row),
				disagreement(row),
			)
		}
		// Dropped deliberately, and consistently: every Fprintln above writes
		// to the same w and discards its error too, the way bom.Human does. A
		// writer that has failed has failed for all of them, and a report that
		// returned an error only from its last flush would say the table broke
		// when the whole output did.
		_ = tw.Flush()
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "What none of these three can see:")
	for _, l := range r.Limits {
		fmt.Fprintf(w, "  - %s\n", l)
	}
}

func count(n int, unit string) string {
	if n == 0 {
		return "-"
	}
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

func codeCell(r Row) string {
	if r.CodeSites == 0 {
		return "-"
	}
	return count(r.CodeSites, "site")
}

// disagreement names the shape rather than scoring it. The wording says what
// is missing and never what to do about it, because the right action differs
// per estate and this tool does not know which.
func disagreement(r Row) string {
	switch {
	case r.Agrees():
		return ""
	case r.Observed() && !r.Declared():
		return "reached, and declared by nobody"
	case r.Declared() && !r.Observed() && !r.Coded():
		return "declared, and neither reached nor in code"
	case r.Declared() && !r.Observed():
		return "declared and in code, not observed reaching it"
	case r.Coded() && !r.Declared():
		return "in code, declared by nobody"
	default:
		return "not in every source"
	}
}
