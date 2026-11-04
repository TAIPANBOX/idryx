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
	Schema      string       `json:"schema"`
	Tool        string       `json:"tool"`
	GeneratedAt string       `json:"generated_at"`
	CodeScan    CodeScanRef  `json:"code_scan"`
	Sources     []SourceRow  `json:"sources"`
	Rows        []Row        `json:"rows"`
	Subjects    []SubjectRow `json:"subjects"`
	Limits      []string     `json:"limits"`
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
		Sources:     r.Sources,
		Rows:        r.Rows,
		Subjects:    r.Subjects,
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
		fmt.Fprintf(w, "code scan: %s", show(r.CodeScan.Root))
		if r.CodeScan.Tool != "" {
			fmt.Fprintf(w, " (%s", show(strings.TrimSpace(r.CodeScan.Tool)))
			if r.CodeScan.GeneratedAt != "" {
				fmt.Fprintf(w, ", %s", show(r.CodeScan.GeneratedAt))
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

	humanSources(w, r.Sources)

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

	humanSubjects(w, r.Subjects)

	fmt.Fprintln(w)
	fmt.Fprintln(w, "What none of these three can see:")
	for _, l := range r.Limits {
		fmt.Fprintf(w, "  - %s\n", show(l))
	}
}

// humanSources writes one line per source, present or not. An absent source is
// a line that says what its absence means, so a reader never takes a missing
// column for a count of zero.
func humanSources(w io.Writer, sources []SourceRow) {
	if len(sources) == 0 {
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SOURCE\tSTATE\tWHAT IT HOLDS")
	for _, s := range sources {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", show(s.Source), show(s.State), show(s.Detail))
	}
	_ = tw.Flush()
	fmt.Fprintln(w)
}

// humanSubjects writes one row per subject and provider. The CODE column is for
// the whole estate: a source scan finds a file and a line, and no field binds a
// repository to an identity, so the same provider shows the same code figure on
// every subject that uses it.
func humanSubjects(w io.Writer, subjects []SubjectRow) {
	if len(subjects) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "By agent or service (the CODE column is per provider, for the whole estate, because a scan has no subject):")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SUBJECT\tKIND\tPROVIDER\tDECLARED\tSEEN\tCODE\tWHERE THEY DISAGREE")
	for _, s := range subjects {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			show(s.Subject), subjectKind(s), orDash(show(s.Provider)),
			declaredCell(s), seenCell(s), subjectCodeCell(s), GapText(s.Gap))
	}
	_ = tw.Flush()
}

func subjectKind(s SubjectRow) string {
	if s.Attribution == "" {
		return show(s.Kind)
	}
	return show(s.Kind) + ", " + show(s.Attribution)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func declaredCell(s SubjectRow) string {
	switch {
	case len(s.Models) > 0:
		return show(strings.Join(s.Models, ", "))
	case s.Declared:
		return "yes"
	}
	return "-"
}

func seenCell(s SubjectRow) string {
	switch s.Seen {
	case SeenEgress:
		return show(strings.Join(s.Via, "+") + " " + strings.Join(s.Hosts, ","))
	case SeenBusOnly:
		var parts []string
		for _, b := range s.Bus {
			parts = append(parts, fmt.Sprintf("%s %d", show(b.Source), b.Events))
		}
		return "bus only (" + strings.Join(parts, ", ") + ")"
	}
	return "-"
}

func subjectCodeCell(s SubjectRow) string {
	switch s.Code {
	case CodeFound:
		return count(s.CodeSites, "site")
	case CodeNotFound:
		return "not found"
	case CodeNotScanned:
		return "not scanned"
	}
	return "-"
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
