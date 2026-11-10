#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

: "${BAO_ADDR:?BAO_ADDR is required}"
: "${BAO_TOKEN:?BAO_TOKEN is required}"
: "${OPENBAO_BIN:?OPENBAO_BIN is required}"
: "${PROJECT_DIR:?PROJECT_DIR is required}"
: "${APP_CONFIG_FILE:?APP_CONFIG_FILE is required}"
: "${APP_ENCRYPTION_KEY:?APP_ENCRYPTION_KEY is required}"
: "${APPROVER_PASSWORD:?APPROVER_PASSWORD is required}"
: "${PUBLIC_ORIGIN:?PUBLIC_ORIGIN is required}"
: "${PLUGIN_DIRECTORY:?PLUGIN_DIRECTORY is required}"
: "${GITHUB_PLUGIN_SHA256:?GITHUB_PLUGIN_SHA256 is required}"
: "${GITHUB_APP_PRIVATE_KEY_FILE:?GITHUB_APP_PRIVATE_KEY_FILE is required}"

# Approvers' browsers call OpenBao directly to sign in, so this address must be
# reachable from them; it defaults to the address this script uses.
APPROVER_OPENBAO_ADDRESS="${APPROVER_OPENBAO_ADDRESS:-${BAO_ADDR}}"

export BAO_ADDR BAO_TOKEN

for _ in $(seq 1 100); do
  if "${OPENBAO_BIN}" status -format=json >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
"${OPENBAO_BIN}" status -format=json >/dev/null

if ! "${OPENBAO_BIN}" auth list -format=json | jq -e 'has("userpass/")' >/dev/null; then
  "${OPENBAO_BIN}" auth enable userpass >/dev/null
fi
if ! "${OPENBAO_BIN}" secrets list -format=json | jq -e 'has("kv/")' >/dev/null; then
  "${OPENBAO_BIN}" secrets enable -path=kv -version=2 kv >/dev/null
fi

cat "${PROJECT_DIR}/config/authorizer-policy.hcl" "${PROJECT_DIR}/deploy/local/authorizer-discover-policy.hcl" |
  "${OPENBAO_BIN}" policy write openbao-authorizer - >/dev/null
"${OPENBAO_BIN}" policy write openbao-authorizer-approver "${PROJECT_DIR}/config/approver-policy.hcl" >/dev/null
"${OPENBAO_BIN}" policy write named-identity "${PROJECT_DIR}/deploy/local/named-identity-policy.hcl" >/dev/null
"${OPENBAO_BIN}" policy write named-identity-minter "${PROJECT_DIR}/deploy/local/named-identity-minter-policy.hcl" >/dev/null
"${OPENBAO_BIN}" policy write agent-session "${PROJECT_DIR}/deploy/local/agent-session-policy.hcl" >/dev/null

# The PWA signs approvers in to OpenBao from the browser.
"${OPENBAO_BIN}" write sys/config/cors enabled=true allowed_origins="${PUBLIC_ORIGIN}" \
  allowed_headers=X-Vault-Token,X-Vault-Namespace,X-Vault-Request,Content-Type >/dev/null

# Named Tokens: `bao-cred auth <name>` mints one with entity alias <name>, so
# each name is one Named Identity. Orphan tokens outlive the minting human's
# token. OpenBao caps the period at the token mount's max TTL (768h by
# default). Tokens carry the project and global Grant policies, which the
# authorizer writes, so project and global Grants reach them. The "named"
# Requester Rule in app.hcl matches this role.
"${OPENBAO_BIN}" write auth/token/roles/named-identity \
  allowed_policies=named-identity,agent-grant-global allowed_policies_glob='agent-grant-project-*' \
  orphan=true renewable=true token_period=768h allowed_entity_aliases='*' >/dev/null
# Agent session tokens: a project's Named Token mints one per agent session,
# alias <project>.<session id>, as its child, so revoking the Named Token
# revokes its sessions. The "sessions" Requester Rule matches this role.
"${OPENBAO_BIN}" write auth/token/roles/agent-session \
  allowed_policies=agent-session,agent-grant-global allowed_policies_glob='agent-grant-project-*' \
  orphan=false renewable=true token_period=24h allowed_entity_aliases='*' >/dev/null

# Example secrets that the grantable rules in app.hcl let agents request.
"${OPENBAO_BIN}" kv put -mount=kv agents/example message="hello from OpenBao" >/dev/null

plugin_binary="${PLUGIN_DIRECTORY}/openbao-plugin-secrets-github"
actual_plugin_sha="$(sha256sum "${plugin_binary}" | cut -d' ' -f1)"
if [[ "${actual_plugin_sha}" != "${GITHUB_PLUGIN_SHA256}" ]]; then
  printf 'GitHub plugin SHA-256 mismatch: got %s\n' "${actual_plugin_sha}" >&2
  exit 1
fi
"${OPENBAO_BIN}" plugin register \
  -sha256="${GITHUB_PLUGIN_SHA256}" \
  -command=openbao-plugin-secrets-github \
  secret openbao-plugin-secrets-github >/dev/null
if ! "${OPENBAO_BIN}" secrets list -format=json | jq -e 'has("github/")' >/dev/null; then
  "${OPENBAO_BIN}" secrets enable -path=github -plugin-name=openbao-plugin-secrets-github plugin >/dev/null
fi

"${OPENBAO_BIN}" write auth/userpass/users/approver \
  password="${APPROVER_PASSWORD}" policies=openbao-authorizer-approver token_period=24h >/dev/null

approver_login="$("${OPENBAO_BIN}" write -format=json auth/userpass/login/approver password="${APPROVER_PASSWORD}")"
approver_entity="$(jq -er '.auth.entity_id' <<<"${approver_login}")"
"${OPENBAO_BIN}" write identity/group \
  name=local-approvers type=internal \
  member_entity_ids="${approver_entity}" \
  policies=openbao-authorizer-approver >/dev/null
"${OPENBAO_BIN}" token revoke "$(jq -er '.auth.client_token' <<<"${approver_login}")" >/dev/null

if [[ -n "${GITHUB_APP_ID:-}" || -e "${GITHUB_APP_PRIVATE_KEY_FILE}" ]]; then
  : "${GITHUB_APP_ID:?GITHUB_APP_ID is required when GitHub App setup is enabled}"
  [[ -r "${GITHUB_APP_PRIVATE_KEY_FILE}" ]] || {
    printf 'GitHub App private key is not readable: %s\n' "${GITHUB_APP_PRIVATE_KEY_FILE}" >&2
    exit 1
  }
  "${OPENBAO_BIN}" write github/config \
    app_id="${GITHUB_APP_ID}" \
    prv_key=@"${GITHUB_APP_PRIVATE_KEY_FILE}" \
    exclude_repository_metadata=true >/dev/null

  if [[ -n "${GITHUB_PERMISSION_SETS_FILE:-}" ]]; then
    jq -e '.permission_sets and .permission_profiles' "${GITHUB_PERMISSION_SETS_FILE}" >/dev/null
    jq -c '.permission_sets | to_entries[]' "${GITHUB_PERMISSION_SETS_FILE}" | while IFS= read -r entry; do
      name="$(jq -er '.key' <<<"${entry}")"
      profile="$(jq -er '.value.permissions_profile' <<<"${entry}")"
      permissionset_file="$(mktemp)"
      jq --arg profile "${profile}" --slurpfile config "${GITHUB_PERMISSION_SETS_FILE}" \
        '.value | del(.permissions_profile) + {permissions: $config[0].permission_profiles[$profile]}' \
        <<<"${entry}" >"${permissionset_file}"
      "${OPENBAO_BIN}" write "github/permissionset/${name}" @"${permissionset_file}" >/dev/null
      rm -f "${permissionset_file}"
    done
  fi
fi

# The authorizer does not renew its token; the dev server reprovisions it on
# every restart, well within this TTL.
authorizer_response="$("${OPENBAO_BIN}" write -format=json auth/token/create-orphan \
  policies=openbao-authorizer no_default_policy=true ttl=720h renewable=false)"
authorizer_token="$(jq -er '.auth.client_token' <<<"${authorizer_response}")"

config_directory="$(dirname "${APP_CONFIG_FILE}")"
install -d -m 0700 "${config_directory}"

# The dev user only mints Named Tokens with `bao-cred init`. It is separate
# from the approver because `bao login` leaves its token in ~/.vault-token,
# where agents can read it, and an approver token would let them approve
# their own requests.
if [[ ! -s "${config_directory}/dev-password" ]]; then
  openssl rand -base64 24 | tr -d '\n' >"${config_directory}/dev-password"
fi
chmod 0600 "${config_directory}/dev-password"
"${OPENBAO_BIN}" write auth/userpass/users/dev \
  password=@"${config_directory}/dev-password" policies=named-identity-minter token_period=24h >/dev/null
printf '%s\n' "${APP_ENCRYPTION_KEY}" >"${config_directory}/encryption-key"
printf '%s\n' "${authorizer_token}" >"${config_directory}/authorizer-token"
chmod 0600 "${config_directory}/encryption-key" "${config_directory}/authorizer-token"

temporary="${APP_CONFIG_FILE}.tmp.$$"
cat >"${temporary}" <<EOF
server {
  listen_address   = "127.0.0.1:18202"
  public_origin    = $(jq -Rn --arg value "${PUBLIC_ORIGIN}" '$value')
  insecure_cookies = false
  static_directory = ""
}
storage {
  database_path       = $(jq -Rn --arg value "${HOME}/.local/state/openbao-authorizer/app.db" '$value')
  encryption_key_file = "encryption-key"
}
openbao {
  address               = $(jq -Rn --arg value "${BAO_ADDR}" '$value')
  authorizer_token_file = "authorizer-token"
  approver_policy       = "openbao-authorizer-approver"
}
approver_login {
  openbao_address = $(jq -Rn --arg value "${APPROVER_OPENBAO_ADDRESS}" '$value')
  method "userpass" {}
  method "token" {}
}
requester "named" {
  token_role = "named-identity"
}
requester "sessions" {
  token_role = "agent-session"
}
grants {
  default_ttl = "8h"
  pending_ttl = "24h"
}
grantable "local-kv" {
  path         = "kv/data/agents/*"
  capabilities = ["read"]
  max_ttl      = "24h"
  description  = "Local example secrets."
  discover     = "kv/metadata/agents"
}
grantable "local-kv-metadata" {
  path         = "kv/metadata/agents/*"
  capabilities = ["read", "list"]
  max_ttl      = "24h"
}
grantable "github-token" {
  path         = "github/token/project-*"
  capabilities = ["read"]
  max_ttl      = "1h"
  description  = "GitHub App installation token for one project; the name selects org, repos and permissions."
  discover     = "github/permissionsets"
}
EOF
if [[ -n "${VAPID_PUBLIC_KEY:-}" || -n "${VAPID_PRIVATE_KEY:-}" || -n "${VAPID_SUBJECT:-}" ]]; then
  : "${VAPID_PUBLIC_KEY:?all VAPID settings are required together}"
  : "${VAPID_PRIVATE_KEY:?all VAPID settings are required together}"
  : "${VAPID_SUBJECT:?all VAPID settings are required together}"
  : "${PUSH_ALLOWED_HOST_SUFFIXES:?PUSH_ALLOWED_HOST_SUFFIXES is required with VAPID}"
  printf '%s\n' "${VAPID_PUBLIC_KEY}" >"${config_directory}/vapid-public-key"
  printf '%s\n' "${VAPID_PRIVATE_KEY}" >"${config_directory}/vapid-private-key"
  chmod 0600 "${config_directory}/vapid-public-key" "${config_directory}/vapid-private-key"
  cat >>"${temporary}" <<EOF
web_push {
  public_key_file      = "vapid-public-key"
  private_key_file     = "vapid-private-key"
  subject              = $(jq -Rn --arg value "${VAPID_SUBJECT}" '$value')
  allowed_host_suffixes = $(jq -Rn --arg value "${PUSH_ALLOWED_HOST_SUFFIXES}" '$value | split(",") | map(select(length > 0))')
}
EOF
fi
chmod 0600 "${temporary}"
mv -f "${temporary}" "${APP_CONFIG_FILE}"
