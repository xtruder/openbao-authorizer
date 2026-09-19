#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

usage() {
  printf 'usage: %s <project-name> <owner/repository>\n' "${0##*/}" >&2
  exit 2
}

[[ $# -eq 2 ]] || usage
project="$1"
full_repository="$2"
[[ "${project}" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || {
  printf 'project name must match [a-z0-9][a-z0-9._-]*\n' >&2
  exit 2
}
[[ "${full_repository}" =~ ^[^/]+/[^/]+$ ]] || usage
repository="${full_repository#*/}"

config_dir="${OPENBAO_CONTROL_GROUP_CONFIG_DIR:-${HOME}/.config/openbao-authorizer}"
# shellcheck source=/dev/null
source "${config_dir}/bootstrap.env"
: "${BAO_ADDR:?BAO_ADDR is required in bootstrap.env}"
: "${BAO_TOKEN:?BAO_TOKEN is required in bootstrap.env}"
: "${GITHUB_APP_INSTALLATION_ID:?GITHUB_APP_INSTALLATION_ID is required in bootstrap.env}"

bao="${OPENBAO_BIN:-${HOME}/.local/lib/openbao-authorizer/bao}"
permissions="contents=write,pull_requests=write,issues=write,workflows=write,actions=read,metadata=read"
export BAO_ADDR BAO_TOKEN

"${bao}" write "github/permissionset/project-${project}" \
  installation_id="${GITHUB_APP_INSTALLATION_ID}" \
  repositories="${repository}" \
  permissions="${permissions}" >/dev/null

printf 'configured github/token/project-%s for %s\n' "${project}" "${full_repository}"
