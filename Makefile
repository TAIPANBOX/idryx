VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build test test-integration vet fmt lint detect nhi serve clean

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

serve: build
	./bin/idryx serve ./testdata/baseline_events.json

clean:
	rm -rf bin
