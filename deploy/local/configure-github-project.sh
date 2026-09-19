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
owner="${full_repository%%/*}"
repository="${full_repository#*/}"

config_dir="${OPENBAO_AUTHORIZER_CONFIG_DIR:-${HOME}/.config/openbao-authorizer}"
# shellcheck source=/dev/null
source "${config_dir}/bootstrap.env"
: "${BAO_ADDR:?BAO_ADDR is required in bootstrap.env}"
: "${BAO_TOKEN:?BAO_TOKEN is required in bootstrap.env}"

case "${owner}" in
  xtruder)
    installation_id="${GITHUB_XTRUDER_INSTALLATION_ID:-${GITHUB_APP_INSTALLATION_ID:-}}"
    ;;
  offlinehacker)
    installation_id="${GITHUB_OFFLINEHACKER_INSTALLATION_ID:-}"
    ;;
  *)
    printf 'no configured GitHub App installation for owner %s\n' "${owner}" >&2
    exit 1
    ;;
esac
: "${installation_id:?GitHub installation ID is not configured for ${owner}}"

bao="${OPENBAO_BIN:-${HOME}/.local/lib/openbao-authorizer/bao}"
permissions='{"actions":"write","actions_variables":"write","administration":"write","agent_secrets":"write","agent_tasks":"write","agent_variables":"write","artifact_metadata":"write","attestations":"write","checks":"write","code_quality":"write","security_events":"write","codespaces":"write","codespaces_lifecycle_admin":"write","codespaces_metadata":"read","codespaces_secrets":"write","statuses":"write","contents":"write","copilot_agent_settings":"write","repository_custom_properties":"write","vulnerability_alerts":"write","dependabot_secrets":"write","deployments":"write","discussions":"write","environments":"write","issues":"write","license_compliance_alerts":"write","merge_queues":"write","metadata":"read","packages":"write","pages":"write","repository_projects":"write","pull_requests":"write","repository_advisories":"write","repo_secret_scanning_dismissal_requests":"write","secret_scanning_alerts":"write","secret_scanning_bypass_requests":"write","secrets":"write","repository_hooks":"write","workflows":"write"}'
payload="$(mktemp)"
trap 'rm -f "${payload}"' EXIT
jq -cn \
  --argjson installation_id "${installation_id}" \
  --arg account "${owner}" \
  --arg repository "${repository}" \
  --argjson permissions "${permissions}" \
  '{installation_id: $installation_id, org_name: $account, repositories: [$repository], permissions: $permissions}' >"${payload}"
export BAO_ADDR BAO_TOKEN
"${bao}" write "github/permissionset/project-${project}" @"${payload}" >/dev/null

printf 'configured github/token/project-%s for %s\n' "${project}" "${full_repository}"
