# Contributing to idryx

> Working with an AI coding agent? See [`AGENTS.md`](AGENTS.md) for the
> repo-specific recipes and conventions.

## Development

```sh
make build    # build bin/idryx
make test     # run tests
make lint     # gofmt + go vet
make detect   # ITDR detectors over the event fixtures
make nhi      # NHI + agent + shadow-ai detectors over the inventory fixtures
make serve    # read-only dashboard on :8080
```

Before every commit, this must be clean:

```sh
gofmt -l .    # prints nothing
go vet ./...  # exits 0
go test ./... # all packages ok
```

CI also runs `go test -race ./...` and integration tests behind the `integration`
build tag against a Postgres service (`make test-integration` with `DATABASE_URL`).

## Conventions

- Conventional Commits: `feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, `test:`.
- One logical change per commit.
- `make lint` and `make test` must pass before a PR.
- Detection is deterministic — statistics and rules over the graph. No LLM in the
  detection path; LLMs are only ever an interface layer.
- idryx is read-only: it observes identities, it never mutates the IdP or cloud.

## Adding a detector

1. Implement `detect.Detector` (`Name()` + `Detect(graph.Reader) []model.Alert`)
   in `internal/detect/detectors/`.
2. Use `now()` for timestamps so tests can pin the clock; skip identity kinds you
   don't target (e.g. `continue` on humans for NHI detectors).
3. Register it in `runDetectors` in `cmd/idryx/main.go` — an unregistered detector
   never runs.
4. Add a `_test.go` with positive and negative cases, and document it in `README.md`.

## Adding a source connector

- **Event sources** (logs) parse to `[]model.Event` and wire into `parseSource`.
- **Inventory sources** (identities + permissions) parse to `[]model.Identity` and
  wire into `parseInventory`.

In both cases: normalize vendor fields into the shared model in
`internal/ingest/`, add the source to the `--source` help strings, add a
`_test.go` and a `testdata/` fixture, and update the connectors table in
`README.md`.
