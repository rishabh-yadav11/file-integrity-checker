BINARY_NAME := integrity-check
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/rishabh-yadav11/file-integrity-checker/cmd/ic/cmd.version=$(VERSION)

.PHONY: all build test race vet fmt cover fuzz lint clean docker release

all: vet test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME) ./cmd/ic

test:
	go test ./... -timeout 10m

race:
	go test -race ./... -timeout 10m

vet:
	go vet ./...

fmt:
	gofmt -w .

cover:
	go test ./... -coverprofile=coverage.out -timeout 10m
	go tool cover -func=coverage.out | tail -1

fuzz:
	go test ./internal/baseline -run FuzzLoad -fuzz FuzzLoad -fuzztime 60s

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed; skipping lint (install via https://golangci-lint.run)"; \
	fi

clean:
	rm -rf dist coverage.out bin/

docker:
	docker build --build-arg VERSION=$(VERSION) -t integrity-check:$(VERSION) .

release:
	goreleaser release --clean
