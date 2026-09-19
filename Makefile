SHELL := /bin/bash

.PHONY: frontend test lint build e2e clean

frontend:
	npm --prefix web run build

test: frontend
	go test -race -count=1 ./...
	npm --prefix web test -- --run

lint: frontend
	go vet ./...
	GOTOOLCHAIN=go1.26.6 go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run -c .golangci.yml ./...
	npm --prefix web run lint

build: frontend
	mkdir -p bin
	go build -o bin/openbao-authorizer ./cmd/server

e2e:
	go test -tags=e2e -count=1 -v ./e2e/openbao

clean:
	rm -rf bin web/dist
