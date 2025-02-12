.PHONY: build clean test

BINARY_NAME=netsentinel
VERSION=$(shell git describe --tags --always --dirty)
LDFLAGS=-ldflags "-X main.Version=${VERSION}"

build:
	go build ${LDFLAGS} -o bin/${BINARY_NAME} cmd/netsentinel/main.go

clean:
	rm -rf bin/
	go clean

test:
	go test -v ./...

lint:
	golangci-lint run

deps:
	go mod download
	go mod tidy

.DEFAULT_GOAL := build 