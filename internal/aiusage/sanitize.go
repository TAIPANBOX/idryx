package aiusage

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Bounds for text this package did not write. A name arrives from a Passport,
// a bus envelope, a capture or a qryx document, and each of those is a file
// somebody else could have edited. Every such string passes through escape
// before it is stored or shown, so a hostile one is a long printable line at
// worst and never a sequence a terminal acts on.
const (
	maxShown  = 120 // a name in a table cell
	maxStored = 300 // a string kept from a qryx document
)

// escape renders s as printable text of at most max runes. A control
// character, a format character (bidirectional overrides among them), a line
// or paragraph separator and any byte that is not UTF-8 become \xNN or \uNNNN,
// so the reader sees what was there instead of what it would have done. Text
// cut for length ends in an ellipsis. It is idempotent: its output holds no
// character it would change.
func escape(s string, max int) string {
	var b strings.Builder
	n := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		var piece string
		switch {
		case r == utf8.RuneError && size == 1:
			piece = fmt.Sprintf(`\x%02x`, s[i])
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ':
			if r < 0x100 {
				piece = fmt.Sprintf(`\x%02x`, r)
			} else {
				piece = fmt.Sprintf(`\u%04x`, r)
			}
		default:
			piece = s[i : i+size]
		}
		i += size
		pr := utf8.RuneCountInString(piece)
		limit := max
		if i < len(s) {
			limit = max - 1 // room for the ellipsis when more text follows
		}
		if n+pr > limit {
			b.WriteString("…")
			return b.String()
		}
		b.WriteString(piece)
		n += pr
	}
	return b.String()
}

// show is escape at the width of a table cell.
func show(s string) string { return escape(s, maxShown) }
