//go:build integration

// These tests require a real Postgres. Run with:
//
//	DATABASE_URL=postgres://user:pass@localhost:5432/idryx_test?sslmode=disable \
//	    go test -tags integration ./cmd/idryx/
package main

import (
	"context"
	"os"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// testDSN returns the integration DSN, skipping when there is none.
//
// This package shares that one database with internal/graph, whose own
// helper TRUNCATEs it at the start of every test. Nothing here truncates,
// and every assertion below is scoped to the identities this test ingested,
// so a stray row from another package cannot change the verdict. The run
// itself is serialized with `go test -p 1` (Makefile and CI) so a truncate
// cannot land between this test's ingest and its read: a shared fixture that
// only works when nobody else is looking is a flake waiting for a busy day.
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	return dsn
}

// TestDetectDBAppliesPrivilegedFlag is the end-to-end half of the ignored
// --privileged flag: the whole path an operator takes, `idryx load --db`
// followed by `detect --db --privileged`, over a real database.
//
// buildGraph's Postgres branch returned the snapshot without ever
// referencing its privileged parameter. The set was applied only at `idryx
// load` time, so an operator who learned that an identity was privileged
// after loading had no way to say so, and got systematically under-ranked
// findings with nothing indicating why.
func TestDetectDBAppliesPrivilegedFlag(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()

	store, err := graph.OpenPg(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	// Load an identity WITHOUT any privileged marking, exactly as a plain
	// `idryx load --db` would.
	ids := []model.Identity{
		{ID: "agent://acme.example/deployer", Type: model.IdentityAgent, Source: "agents", Owner: "platform"},
		{ID: "agent://acme.example/reader", Type: model.IdentityAgent, Source: "agents", Owner: "platform"},
	}
	if err := store.IngestIdentities(ctx, ids); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	g, err := buildGraph("", "agent://acme.example/deployer", "", dsn, "", "", "", nil)
	if err != nil {
		t.Fatalf("buildGraph: %v", err)
	}

	var deployer, reader *model.Identity
	for _, id := range g.Identities() {
		switch id.ID {
		case "agent://acme.example/deployer":
			deployer = id
		case "agent://acme.example/reader":
			reader = id
		}
	}
	if deployer == nil || reader == nil {
		t.Fatal("the loaded identities did not come back from the snapshot")
	}
	if !deployer.Privileged {
		t.Error("--privileged named the deployer and the Postgres-backed graph came back with Privileged=false, so all ten severity-raising detectors rank it as ordinary")
	}
	if reader.Privileged {
		t.Error("an identity not named in --privileged came back privileged")
	}
}
