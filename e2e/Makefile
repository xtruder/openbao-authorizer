SHELL := /bin/bash

.PHONY: e2e app openbao

ROOT := $(abspath ..)
OPENBAO_VERSION := 2.7.0-beta20260909
OPENBAO_TAG := v$(OPENBAO_VERSION)
MACHINE := $(shell uname -m)
ifeq ($(MACHINE),x86_64)
OPENBAO_ARCH := amd64
OPENBAO_SHA256 := 7531048975e8f669b83c28f0f949e11fde0587d1064ea77d612f88cd0713fd11
else ifeq ($(MACHINE),aarch64)
OPENBAO_ARCH := arm64
OPENBAO_SHA256 := 96558560ab53008a9b03d1872d7b219a2133b2fc5b9fa9fd5501abbdcf63271b
endif
OPENBAO_CACHE := $(ROOT)/.e2e/openbao
OPENBAO_ARCHIVE := openbao_$(OPENBAO_VERSION)_linux_$(OPENBAO_ARCH).tar.gz
OPENBAO_RELEASE_URL := https://github.com/openbao/openbao/releases/download/$(OPENBAO_TAG)
OPENBAO_BINARY := $(OPENBAO_CACHE)/bin/$(OPENBAO_TAG)/linux_$(OPENBAO_ARCH)/bao
APP_BINARY := $(ROOT)/bin/openbao-authorizer

e2e: app openbao
	OPENBAO_E2E_APP_BINARY="$(APP_BINARY)" OPENBAO_E2E_BAO_BINARY="$(OPENBAO_BINARY)" go test -tags=e2e -count=1 -v .

app:
	$(MAKE) -C "$(ROOT)" build

openbao:
	@set -euo pipefail; \
	if [[ -z "$(OPENBAO_ARCH)" ]]; then echo "unsupported Linux architecture: $(MACHINE)" >&2; exit 1; fi; \
	download_dir="$(OPENBAO_CACHE)/downloads/$(OPENBAO_TAG)"; \
	archive="$$download_dir/$(OPENBAO_ARCHIVE)"; \
	checksums="$$download_dir/checksums.txt"; \
	mkdir -p "$$download_dir" "$(dir $(OPENBAO_BINARY))"; \
	verify_checksums() { \
		local matches; \
		matches="$$(while read -r digest name extra; do name="$${name#\*}"; if [[ "$$name" == "$(OPENBAO_ARCHIVE)" && -z "$${extra:-}" ]]; then printf '%s\n' "$$digest"; fi; done < "$$checksums")"; \
		[[ "$$matches" != *$$'\n'* && "$$matches" == "$(OPENBAO_SHA256)" ]]; \
	}; \
	if [[ ! -s "$$checksums" ]] || ! verify_checksums; then \
		curl --fail --location --retry 3 --output "$$checksums.tmp" "$(OPENBAO_RELEASE_URL)/checksums.txt"; \
		mv "$$checksums.tmp" "$$checksums"; \
		verify_checksums; \
	fi; \
	if [[ ! -s "$$archive" ]] || ! printf '%s  %s\n' "$(OPENBAO_SHA256)" "$$archive" | sha256sum --check --status; then \
		curl --fail --location --retry 3 --output "$$archive.tmp" "$(OPENBAO_RELEASE_URL)/$(OPENBAO_ARCHIVE)"; \
		printf '%s  %s\n' "$(OPENBAO_SHA256)" "$$archive.tmp" | sha256sum --check --status; \
		mv "$$archive.tmp" "$$archive"; \
	fi; \
	mapfile -t entries < <(tar -tzf "$$archive"); \
	[[ "$${#entries[@]}" -eq 4 && "$${entries[0]}" == bao && "$${entries[1]}" == LICENSE && "$${entries[2]}" == README.md && "$${entries[3]}" == CHANGELOG.md ]]; \
	temporary="$(OPENBAO_BINARY).tmp.$$$$"; \
	trap 'rm -f "$$temporary"' EXIT; \
	tar -xOzf "$$archive" bao > "$$temporary"; \
	chmod 0755 "$$temporary"; \
	mv "$$temporary" "$(OPENBAO_BINARY)"
