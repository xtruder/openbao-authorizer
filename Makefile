GOLANGCI_LINT := golangci-lint

.PHONY: generate proto-check frontend test fmt lint build bin/openbao-authorizer bin/bao-cred e2e clean opencode-plugin-test install-opencode

generate:
	buf generate

# Fails when the committed generated code or the protos drift from buf's checks.
proto-check:
	buf lint
	buf format --diff --exit-code
	buf generate
	git diff --exit-code -- gen web/src/gen
	git status --porcelain -- gen web/src/gen | (! grep .)

frontend:
	npm --prefix web run build

test: frontend
	go test -race -count=1 ./...
	npm --prefix web test -- --run

fmt:
	$(GOLANGCI_LINT) run --fix -c .golangci.yml ./...

lint: frontend
	$(GOLANGCI_LINT) run -c .golangci.yml ./...
	npm --prefix web run lint

build: bin/openbao-authorizer bin/bao-cred

bin/openbao-authorizer: frontend
	mkdir -p $(@D)
	go build -o $@ ./cmd/openbao-authorizer

bin/bao-cred:
	mkdir -p $(@D)
	go build -o $@ ./cmd/bao-cred

e2e:
	$(MAKE) -C e2e

OPENCODE_PLUGIN_DIR := $(CURDIR)/integrations/opencode

opencode-plugin-test:
	cd $(OPENCODE_PLUGIN_DIR) && bun install --frozen-lockfile && bun test && bun run typecheck

# The plugin has no runtime dependencies, so opencode V2 loads it straight from
# this checkout. This only prints the opencode.json entry; it edits no config.
install-opencode:
	@printf '%s\n' \
		'Add this to opencode.json (global ~/.config/opencode/opencode.json or per project):' \
		'' \
		'  "plugins": [{' \
		'    "package": "$(OPENCODE_PLUGIN_DIR)",' \
		'    "options": {' \
		'      "address": "https://openbao.example.com",' \
		'      "authorizerUrl": "https://authorizer.example.com",' \
		'      "roleIdFile": "~/.config/opencode-openbao/role-id",' \
		'      "secretIdFile": "~/.config/opencode-openbao/secret-id"' \
		'    }' \
		'  }]' \
		'' \
		'See integrations/opencode/README.md for the options and OpenBao setup.'

clean:
	rm -rf bin web/dist
