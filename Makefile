VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"
# Static-analysis binary. Overridable, e.g. STATICCHECK=$(go env GOPATH)/bin/staticcheck.
# Without this the `staticcheck` target expanded `$(STATICCHECK)` to empty, so
# `command -v` always failed and static analysis was silently skipped for everyone.
STATICCHECK ?= staticcheck

.PHONY: build test test-integration vet fmt lint detect nhi remediate serve clean

build:
	go build $(LDFLAGS) -o bin/idryx ./cmd/idryx

test:
	go test ./...

# Requires a running Postgres; set DATABASE_URL.
test-integration:
	go test -tags integration ./internal/graph/

vet:
	go vet ./...

fmt:
	gofmt -w .

lint: vet staticcheck
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

# Static analysis beyond go vet. Install: go install honnef.co/go/tools/cmd/staticcheck@latest
staticcheck:
	@command -v $(STATICCHECK) >/dev/null 2>&1 && $(STATICCHECK) ./... || echo "staticcheck not installed; skipping (go install honnef.co/go/tools/cmd/staticcheck@latest)"

detect: build
	./bin/idryx detect --privileged bob@example.com,carol@example.com ./testdata/events.json
	@echo
	./bin/idryx detect ./testdata/baseline_events.json

nhi: build
	./bin/idryx detect --source aws_iam ./testdata/aws_iam.json
	@echo
	./bin/idryx detect --source gcp_iam ./testdata/gcp_iam.json
	@echo
	./bin/idryx detect --source azure ./testdata/azure.json
	@echo
	./bin/idryx detect --source mcp ./testdata/mcp.json

remediate: build
	./bin/idryx remediate --source aws_iam --cloudtrail ./testdata/cloudtrail.json ./testdata/aws_iam.json
	@echo
	./bin/idryx remediate --source gcp_iam --gcp-audit ./testdata/gcp_audit.json ./testdata/gcp_iam.json
	@echo
	./bin/idryx remediate --source agents ./testdata/agents.json

serve: build
	./bin/idryx serve ./testdata/baseline_events.json

clean:
	rm -rf bin
