package ingest

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

// This file reads what an AWS IAM policy actually says, rather than what its
// name suggests.
//
// Before it, the aws_iam connector emitted policy NAMES and decided admin
// equivalence by string-matching them ("administratoraccess", "admin"). Two
// consequences, both silent:
//
//   - the privilege_escalation detector keys on cloud ACTION strings
//     (iam:passrole and friends) and no connector ever produced one, so the
//     detector could not fire from any shipped input;
//   - a customer-managed or inline policy granting "Action": "*" on
//     "Resource": "*" under any ordinary name was not admin-equivalent to
//     idryx, which made it invisible to every detector that keys on
//     Identity.HasAdmin().
//
// What is parsed here is deliberately a subset of the IAM policy language: a
// full evaluator (conditions, NotAction/NotResource semantics, resource-path
// matching, permission boundaries, SCPs, session policies, trust policies)
// is a different piece of work. See README and VALIDATION.md for exactly
// what is and is not covered.

// awsPolicyDoc is the part of an IAM policy document idryx reads.
type awsPolicyDoc struct {
	Statement []awsStatement `json:"Statement"`
}

type awsStatement struct {
	Effect    string       `json:"Effect"`
	Action    awsStringSet `json:"Action"`
	NotAction awsStringSet `json:"NotAction"`
	Resource  awsStringSet `json:"Resource"`
}

// awsStringSet accepts the two shapes IAM uses interchangeably for Action and
// Resource: a bare string, or an array of strings.
type awsStringSet []string

func (s *awsStringSet) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*s = awsStringSet{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

// decodePolicyDocument accepts both shapes an IAM export carries. The API
// returns a policy document URL-encoded inside a JSON string; the AWS CLI
// decodes it and hands back a JSON object. Both appear in real
// get-account-authorization-details output depending on how it was produced,
// so both are read. Returns false when there is no document, or it does not
// parse: an unreadable document must leave the grant with no derived actions
// rather than a wrong set of them.
func decodePolicyDocument(raw json.RawMessage) (awsPolicyDoc, bool) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return awsPolicyDoc{}, false
	}

	if strings.HasPrefix(trimmed, `"`) {
		var encoded string
		if err := json.Unmarshal(raw, &encoded); err != nil {
			return awsPolicyDoc{}, false
		}
		decoded, err := url.QueryUnescape(encoded)
		if err != nil {
			// Not URL-encoded after all: some exports embed plain JSON in the
			// string. Fall through and try it as-is.
			decoded = encoded
		}
		var doc awsPolicyDoc
		if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
			return awsPolicyDoc{}, false
		}
		return doc, true
	}

	var doc awsPolicyDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return awsPolicyDoc{}, false
	}
	return doc, true
}

// policyEffect summarizes one policy document: the action strings it allows
// (lowercased, de-duplicated, in document order so the result is
// deterministic), and whether it is administrator-equivalent.
//
// Administrator-equivalent means an Allow of every action on every resource.
// A statement written with NotAction and Resource "*" ("everything except
// these") counts too: it is a grant of nearly the whole account, and reading
// it as anything narrower would be the same name-shaped blindness this file
// exists to end. The listed NotAction entries are NOT added to the action
// list, since they are the actions being excluded, and reading them as
// allowed would invert the statement.
//
// Deny statements are skipped entirely: they cannot grant, and treating a
// Deny of iam:PassRole as evidence of holding it would be exactly backwards.
// Conditions are not evaluated, so a conditioned Allow is read as an Allow,
// which over-reports rather than under-reports.
func policyEffect(doc awsPolicyDoc) (actions []string, admin bool) {
	seen := map[string]bool{}
	for _, st := range doc.Statement {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		everyResource := false
		for _, r := range st.Resource {
			if strings.TrimSpace(r) == "*" {
				everyResource = true
				break
			}
		}
		for _, a := range st.Action {
			a = strings.ToLower(strings.TrimSpace(a))
			if a == "" {
				continue
			}
			if a == "*" && everyResource {
				admin = true
			}
			if !seen[a] {
				seen[a] = true
				actions = append(actions, a)
			}
		}
		if len(st.NotAction) > 0 && everyResource {
			admin = true
		}
	}
	return actions, admin
}

// normalizeActions lowercases, de-duplicates and sorts a hand-maintained
// action list (the GCP and Azure role tables), so a grant's Actions come out
// in one shape regardless of which connector produced it.
func normalizeActions(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, a := range in {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}
