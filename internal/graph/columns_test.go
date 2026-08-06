package graph

import (
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// This file holds the two checks that would have caught a whole field going
// missing between the in-memory graph and the Postgres one, and that need no
// database to run: they read the SQL this package actually issues and the
// schema it actually applies.
//
// The failure they exist for is silent by construction. `Identity.Shadow`
// (MCP) and `Identity.DeclaredModels` (Passport 4.5) had no column anywhere,
// were never written by IngestIdentities and never read by Snapshot, so
// after `idryx load --db --source mcp ...` a later `idryx detect --db` ran
// shadow_mcp, agent_shadow_tool and undeclared_llm over a graph where every
// Shadow flag was false and every agent had zero declared models. All three
// returned empty, with no warning, against a backend AGENTS.md says
// detectors "run unchanged" over.

// sqlSources are the files whose SQL is checked. Both live in this package
// and both write and read the same tables.
var sqlSources = []string{"pgstore.go", "remediations.go"}

var (
	insertRe  = regexp.MustCompile(`INSERT INTO (\w+)\s*\(([^)]*)\)`)
	selectRe  = regexp.MustCompile(`(?s)SELECT\s+(.*?)\s+FROM (\w+)`)
	orderByRe = regexp.MustCompile(`ORDER BY ([a-z_, ]+)`)
	createRe  = regexp.MustCompile(`(?s)CREATE TABLE IF NOT EXISTS (\w+) \((.*?)\n\);`)
	alterRe   = regexp.MustCompile(`ALTER TABLE (\w+) ADD COLUMN IF NOT EXISTS (\w+)`)
)

// columnSets returns, per table, the columns this package writes and the
// columns it reads, plus every column named in any ORDER BY (which is a read
// of that column even though it never reaches a Scan).
func columnSets(t *testing.T) (inserts, selects map[string]map[string]bool, ordered map[string]bool) {
	t.Helper()
	inserts = map[string]map[string]bool{}
	selects = map[string]map[string]bool{}
	ordered = map[string]bool{}

	add := func(m map[string]map[string]bool, table, list string) {
		if m[table] == nil {
			m[table] = map[string]bool{}
		}
		for _, c := range strings.Split(list, ",") {
			c = strings.TrimSpace(c)
			// Drop any table qualifier and skip anything that is not a plain
			// column reference (a function call, a literal, `*`).
			if i := strings.LastIndex(c, "."); i >= 0 {
				c = c[i+1:]
			}
			if c == "" || !regexp.MustCompile(`^[a-z_][a-z0-9_]*$`).MatchString(c) {
				continue
			}
			m[table][c] = true
		}
	}

	for _, f := range sqlSources {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		src := string(data)
		for _, m := range insertRe.FindAllStringSubmatch(src, -1) {
			add(inserts, m[1], m[2])
		}
		for _, m := range selectRe.FindAllStringSubmatch(src, -1) {
			add(selects, m[2], m[1])
		}
		for _, m := range orderByRe.FindAllStringSubmatch(src, -1) {
			for _, c := range strings.Split(m[1], ",") {
				if c = strings.TrimSpace(c); c != "" {
					ordered[c] = true
				}
			}
		}
	}
	if len(inserts) == 0 || len(selects) == 0 {
		t.Fatal("found no INSERT or no SELECT at all, so this check measured nothing")
	}
	return inserts, selects, ordered
}

// schemaColumns returns, per table, the columns schema.sql declares, and the
// subset of them the database generates for itself (BIGSERIAL surrogate
// keys), which are legitimately read without ever being written.
func schemaColumns(t *testing.T) (declared map[string]map[string]bool, generated map[string]bool) {
	t.Helper()
	declared = map[string]map[string]bool{}
	generated = map[string]bool{}

	for _, m := range createRe.FindAllStringSubmatch(schema, -1) {
		table := m[1]
		if declared[table] == nil {
			declared[table] = map[string]bool{}
		}
		for _, line := range strings.Split(m[2], "\n") {
			line = strings.TrimSpace(line)
			fields := strings.Fields(line)
			if len(fields) < 2 || strings.HasPrefix(line, "--") {
				continue
			}
			switch strings.ToUpper(fields[0]) {
			case "PRIMARY", "UNIQUE", "FOREIGN", "CONSTRAINT", "CHECK":
				continue
			}
			declared[table][fields[0]] = true
			if strings.HasPrefix(strings.ToUpper(fields[1]), "BIGSERIAL") {
				generated[fields[0]] = true
			}
		}
	}
	for _, m := range alterRe.FindAllStringSubmatch(schema, -1) {
		if declared[m[1]] == nil {
			declared[m[1]] = map[string]bool{}
		}
		declared[m[1]][m[2]] = true
	}
	if len(declared) == 0 {
		t.Fatal("parsed no tables out of schema.sql, so this check measured nothing")
	}
	return declared, generated
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestPgStoreWritesAndReadsTheSameColumns holds the three ways a column can
// exist and still carry nothing:
//
//  1. written and never read back (a write-only column: the data is in the
//     database and no detector ever sees it),
//  2. read and never written (a read-only column: every row comes back as
//     the schema default, which is exactly how a false Shadow flag looks),
//  3. named in SQL and never declared in schema.sql (the migration half).
//
// It needs no database: the SQL is read out of the source, the columns out
// of the embedded schema.
func TestPgStoreWritesAndReadsTheSameColumns(t *testing.T) {
	inserts, selects, ordered := columnSets(t)
	declared, generated := schemaColumns(t)

	for table, written := range inserts {
		for _, col := range sortedKeys(written) {
			if !selects[table][col] && !ordered[col] {
				t.Errorf("%s.%s is written and never read back: the value reaches Postgres and no Snapshot ever returns it, so no detector can see it", table, col)
			}
		}
	}

	for table, read := range selects {
		for _, col := range sortedKeys(read) {
			if !inserts[table][col] && !generated[col] {
				t.Errorf("%s.%s is read and never written: every row comes back as the schema default, which is indistinguishable from real data", table, col)
			}
		}
	}

	for _, sets := range []map[string]map[string]bool{inserts, selects} {
		for table, cols := range sets {
			for _, col := range sortedKeys(cols) {
				if !declared[table][col] {
					t.Errorf("%s.%s appears in SQL but schema.sql declares no such column, so migrate() leaves it missing", table, col)
				}
			}
		}
	}
}

// persistence says where the Postgres backend keeps one field of a model
// type. An empty Table means the field is deliberately not persisted, and
// Why then has to say so: the point of this map is that adding a field to
// the model forces a decision about the durable backend in the same change,
// rather than leaving it to be discovered by a detector that silently
// returns nothing.
type persistence struct {
	Table  string
	Column string
	Why    string
}

// identityPersistence covers every field of model.Identity. For the slice
// fields the column named is the child table's own key or payload column:
// the fields of the element type are covered by their own map below.
var identityPersistence = map[string]persistence{
	"ID":             {Table: "identities", Column: "id"},
	"Type":           {Table: "identities", Column: "type"},
	"Privileged":     {Table: "identities", Column: "privileged"},
	"Events":         {Table: "events", Column: "identity_id"},
	"Source":         {Table: "identities", Column: "source"},
	"Owner":          {Table: "identities", Column: "owner"},
	"Created":        {Table: "identities", Column: "created"},
	"LastUsed":       {Table: "identities", Column: "last_used"},
	"Permissions":    {Table: "permissions", Column: "identity_id"},
	"Runtime":        {Table: "identities", Column: "runtime"},
	"OnBehalfOf":     {Table: "on_behalf_of", Column: "principal"},
	"Parent":         {Table: "identities", Column: "parent"},
	"Attestation":    {Table: "identities", Column: "attestation"},
	"DeclaredModels": {Table: "declared_models", Column: "identity_id"},
	"Shadow":         {Table: "identities", Column: "shadow"},
}

var permissionPersistence = map[string]persistence{
	"Name":    {Table: "permissions", Column: "name"},
	"Admin":   {Table: "permissions", Column: "admin"},
	"Used":    {Table: "permissions", Column: "used"},
	"ARN":     {Table: "permissions", Column: "arn"},
	"Actions": {Table: "permission_actions", Column: "action"},
}

var declaredModelPersistence = map[string]persistence{
	"Provider": {Table: "declared_models", Column: "provider"},
	"Model":    {Table: "declared_models", Column: "model"},
	"Endpoint": {Table: "declared_models", Column: "endpoint"},
}

// TestModelFieldsAllHaveAPersistenceDecision fails when a field exists on a
// model type that this package neither persists nor explicitly declines to
// persist. It is the ratchet for the actual defect: Shadow and
// DeclaredModels were added to model.Identity, ingested by connectors, read
// by three detectors, and never carried to Postgres, so the whole backend
// disagreed with the in-memory graph for those two fields and nothing said
// so.
func TestModelFieldsAllHaveAPersistenceDecision(t *testing.T) {
	inserts, selects, ordered := columnSets(t)
	declared, _ := schemaColumns(t)

	check := func(typeName string, typ reflect.Type, want map[string]persistence) {
		for i := 0; i < typ.NumField(); i++ {
			name := typ.Field(i).Name
			p, ok := want[name]
			if !ok {
				t.Errorf("%s.%s has no persistence decision. Add it to this map: either the table.column that carries it, or an empty Table with a Why saying why the Postgres backend deliberately drops it. A field the durable backend silently loses turns every detector that reads it into one that returns nothing over --db.", typeName, name)
				continue
			}
			if p.Table == "" {
				if p.Why == "" {
					t.Errorf("%s.%s is marked as not persisted with no reason given", typeName, name)
				}
				continue
			}
			if !declared[p.Table][p.Column] {
				t.Errorf("%s.%s claims to live in %s.%s, which schema.sql does not declare", typeName, name, p.Table, p.Column)
			}
			if !inserts[p.Table][p.Column] {
				t.Errorf("%s.%s claims to live in %s.%s, which nothing in this package ever writes", typeName, name, p.Table, p.Column)
			}
			if !selects[p.Table][p.Column] && !ordered[p.Column] {
				t.Errorf("%s.%s claims to live in %s.%s, which nothing in this package ever reads back", typeName, name, p.Table, p.Column)
			}
		}
		for name := range want {
			if _, ok := typ.FieldByName(name); !ok {
				t.Errorf("this map names %s.%s, which no longer exists on the type", typeName, name)
			}
		}
	}

	check("model.Identity", reflect.TypeOf(model.Identity{}), identityPersistence)
	check("model.Permission", reflect.TypeOf(model.Permission{}), permissionPersistence)
	check("model.DeclaredModel", reflect.TypeOf(model.DeclaredModel{}), declaredModelPersistence)
}
