# Contributing to idryx

## Development
```
make build    # build bin/idryx
make test     # run tests
make lint     # gofmt + go vet
make detect   # run against testdata/events.json
```

## Conventions
- Conventional Commits: `feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, `test:`.
- One logical change per commit.
- `make lint` and `make test` must pass before a PR.
- Detection is deterministic — statistics and rules over the graph. No LLM in the
  detection path; LLMs are only ever an interface layer.

## Adding a detector
1. Implement `detect.Detector` in `internal/detect/detectors/`.
2. Register it in `cmd/idryx/main.go`.
3. Add events to `testdata/events.json` and assert them in
   `internal/detect/detect_test.go`.

## Adding a source connector
Implement parsing into `[]model.Event` under `internal/ingest/` (see `okta.go`).
Connectors normalize source-specific logs into the shared event model.
