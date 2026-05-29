VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build test vet fmt lint detect clean

build:
	go build $(LDFLAGS) -o bin/idryx ./cmd/idryx

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

lint: vet
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

detect: build
	./bin/idryx detect --privileged bob@example.com,carol@example.com ./testdata/events.json

clean:
	rm -rf bin
