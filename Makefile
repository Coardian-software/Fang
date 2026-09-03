.PHONY: all build clean test lint fmt install quality conformance

BINARY=fang

all: build

build:
	go build -trimpath -ldflags="-s -w" -o $(BINARY) .

clean:
	rm -f $(BINARY)
	rm -rf ~/.fang/reports/*

test:
	go test ./...

lint:
	go vet ./...

fmt:
	go fmt ./...

install:
	go install -trimpath -ldflags="-s -w" .

dev:
	go run . --help

# Local-only quality gates; tests are never hosted in this repo.
quality: build lint test

conformance:
	go run ./_harness
