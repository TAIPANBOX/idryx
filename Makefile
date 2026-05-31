VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

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

lint: vet
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

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
	./bin/idryx remediate --source aws_iam ./testdata/aws_iam.json
	@echo
	./bin/idryx remediate --source agents ./testdata/agents.json

serve: build
	./bin/idryx serve ./testdata/baseline_events.json

clean:
	rm -rf bin
