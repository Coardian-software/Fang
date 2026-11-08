.PHONY: all build clean test lint fmt install quality conformance security docker-smoke

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

quality: build lint test

security:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

docker-smoke:
	docker build --tag fang:smoke .
	docker run --rm fang:smoke --help >/dev/null

conformance:
	go run ./_harness
