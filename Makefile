BINARY_NAME := integrity-check
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/rishabh-yadav11/file-integrity-checker/cmd/ic/cmd.version=$(VERSION)

.PHONY: all build test race vet fmt cover fuzz lint clean docker release

all: build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME) ./cmd/ic

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
	golangci-lint run

clean:
	rm -rf dist coverage.out bin/

docker:
	docker build -t integrity-check:$(VERSION) .

release:
	goreleaser release --clean
