GOLANGCI_LINT := golangci-lint

.PHONY: frontend test fmt lint build e2e clean

frontend:
	npm --prefix web run build

test: frontend
	go test -race -count=1 ./...
	npm --prefix web test -- --run

fmt:
	$(GOLANGCI_LINT) fmt -c .golangci.yml

lint:
	$(GOLANGCI_LINT) run -c .golangci.yml ./...
	npm --prefix web run lint

build: frontend
	mkdir -p bin
	go build -o bin/openbao-authorizer ./cmd/server

e2e:
	$(MAKE) -C e2e

clean:
	rm -rf bin web/dist
