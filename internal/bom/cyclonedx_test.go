package bom

import (
	"bytes"
	"strings"
	"testing"
)

// goldenBOM is a small, hand-built BOM (bypassing Build/graph entirely) so
// this file tests only the renderer's shape, independent of Build's own
// correctness (covered in bom_test.go). agent:solo is complete and
// autonomous with one non-admin tool; agent:sub is bare/incomplete and
// delegates to agent:solo, to exercise the dependencies edge and the
// zero-value ("none"/"-") rendering paths in one document.
func goldenBOM() BOM {
	return BOM{
		GeneratedAt: fixedNow(),
		Agents: []AgentBOM{
			{
				ID:              "agent:solo",
				Owner:           "team-x",
				Runtime:         "langgraph",
				Attestation:     "oidc",
				Privileged:      false,
				Tools:           []ToolRef{{Name: "read_only", Admin: false, Used: true}},
				DelegationChain: []string{"agent:solo"},
				BlastRadius:     []string{"read_only"},
			},
			{
				ID:              "agent:sub",
				Privileged:      true,
				DelegationChain: []string{"agent:sub", "agent:solo"},
			},
		},
	}
}

// TestJSONGolden pins the exact CycloneDX-shaped byte output for goldenBOM.
// Field order, indentation, property naming, nested tool components, and the
// dependencies block are all part of the documented shape, so this compares
// full output rather than spot-checking substrings.
func TestJSONGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, goldenBOM(), "test-version"); err != nil {
		t.Fatal(err)
	}

	want := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2026-07-01T00:00:00Z",
    "tools": [
      {
        "vendor": "idryx",
        "name": "idryx",
        "version": "test-version"
      }
    ]
  },
  "components": [
    {
      "type": "application",
      "bom-ref": "agent:solo",
      "name": "agent:solo",
      "properties": [
        {
          "name": "idryx:owner",
          "value": "team-x"
        },
        {
          "name": "idryx:runtime",
          "value": "langgraph"
        },
        {
          "name": "idryx:parent",
          "value": ""
        },
        {
          "name": "idryx:attestation",
          "value": "oidc"
        },
        {
          "name": "idryx:privileged",
          "value": "false"
        },
        {
          "name": "idryx:delegationDepth",
          "value": "0"
        },
        {
          "name": "idryx:onBehalfOf",
          "value": ""
        },
        {
          "name": "idryx:blastRadiusCount",
          "value": "1"
        },
        {
          "name": "idryx:blastRadius",
          "value": "read_only"
        }
      ],
      "components": [
        {
          "type": "library",
          "bom-ref": "agent:solo#tool:read_only",
          "name": "read_only",
          "properties": [
            {
              "name": "idryx:admin",
              "value": "false"
            },
            {
              "name": "idryx:used",
              "value": "true"
            }
          ]
        }
      ]
    },
    {
      "type": "application",
      "bom-ref": "agent:sub",
      "name": "agent:sub",
      "properties": [
        {
          "name": "idryx:owner",
          "value": ""
        },
        {
          "name": "idryx:runtime",
          "value": ""
        },
        {
          "name": "idryx:parent",
          "value": ""
        },
        {
          "name": "idryx:attestation",
          "value": "none"
        },
        {
          "name": "idryx:privileged",
          "value": "true"
        },
        {
          "name": "idryx:delegationDepth",
          "value": "1"
        },
        {
          "name": "idryx:onBehalfOf",
          "value": "agent:solo"
        },
        {
          "name": "idryx:blastRadiusCount",
          "value": "0"
        },
        {
          "name": "idryx:blastRadius",
          "value": ""
        }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "agent:sub",
      "dependsOn": [
        "agent:solo"
      ]
    }
  ]
}
`
	if buf.String() != want {
		t.Errorf("JSON golden mismatch:\n--- got ---\n%s\n--- want ---\n%s", buf.String(), want)
	}
}

// TestJSONEmptyBOM asserts a BOM with no agents still renders components as
// [] (never null) and omits dependencies entirely, mirroring report.JSON's
// "empty must be []" contract for alerts.
func TestJSONEmptyBOM(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, BOM{GeneratedAt: fixedNow()}, "test-version"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `"components": []`) {
		t.Errorf("empty BOM must render components as [], got:\n%s", out)
	}
	if strings.Contains(out, `"dependencies"`) {
		t.Errorf("empty BOM must omit dependencies entirely, got:\n%s", out)
	}
}

func TestHumanRendersSummary(t *testing.T) {
	var buf bytes.Buffer
	Human(&buf, goldenBOM())
	out := buf.String()
	for _, want := range []string{
		"idryx agent-bom: 2 agent(s)",
		"agent:solo", "team-x", "langgraph", "oidc",
		"agent:sub", "none", // agent:sub's attestation renders as "none", not empty
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Human output missing %q:\n%s", want, out)
		}
	}
	// agent:sub has no owner/runtime: the "-" fallback must render, not "".
	// tabwriter re-flows tabs into aligned spaces, so split into fields
	// rather than matching literal whitespace.
	var subLine string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "agent:sub") {
			subLine = line
		}
	}
	fields := strings.Fields(subLine)
	if len(fields) < 3 || fields[1] != "-" || fields[2] != "-" {
		t.Errorf("agent:sub owner/runtime should render as '-' fallbacks, got line %q", subLine)
	}
}

func TestHumanEmpty(t *testing.T) {
	var buf bytes.Buffer
	Human(&buf, BOM{GeneratedAt: fixedNow()})
	if !strings.Contains(buf.String(), "No agent identities in the graph.") {
		t.Errorf("empty render wrong: %q", buf.String())
	}
}
