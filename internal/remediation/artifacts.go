package remediation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Artifact indexes one written remediation file in manifest.json.
type Artifact struct {
	Identity    string `json:"identity"`
	Kind        string `json:"kind"`
	File        string `json:"file"`
	Explanation string `json:"explanation"`
}

// WriteArtifacts writes each recommendation as a .tf file plus a manifest.json
// index into dir, and returns the manifest. The .tf content is a human-readable
// proposed diff, not a directly terraform-apply-able file: right-size output
// marks the lines to remove from your existing configuration (it is not a
// complete standalone resource definition, since idryx has no visibility into
// your actual Terraform state/config to know the real resource address), and
// even rotation output should be reviewed and adapted, not applied blind.
// idryx stays read-only on the cloud: it emits files to review and fold into
// your own IaC, never mutating the provider itself. It is the single source of
// truth for both `remediate --out` and the pull-request enforcement flow.
func WriteArtifacts(dir string, recs []*Recommendation) ([]Artifact, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	manifest := make([]Artifact, 0, len(recs))
	used := map[string]bool{}
	for _, rem := range recs {
		name := fmt.Sprintf("%s__%s.tf", rem.Kind, SanitizeName(rem.IdentityID))
		for n := 2; used[name]; n++ {
			name = fmt.Sprintf("%s__%s_%d.tf", rem.Kind, SanitizeName(rem.IdentityID), n)
		}
		used[name] = true
		if err := os.WriteFile(filepath.Join(dir, name), []byte(rem.Code+"\n"), 0o600); err != nil {
			return nil, err
		}
		manifest = append(manifest, Artifact{
			Identity:    rem.IdentityID,
			Kind:        rem.Kind,
			File:        name,
			Explanation: rem.Explanation,
		})
	}
	mb, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), append(mb, '\n'), 0o600); err != nil {
		return nil, err
	}
	return manifest, nil
}

// SanitizeName makes an identity ID safe to use as a filename segment.
func SanitizeName(id string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, id)
}
