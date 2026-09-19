#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

: "${BAO_ADDR:?BAO_ADDR is required}"
: "${BAO_TOKEN:?BAO_TOKEN is required}"
: "${OPENBAO_BIN:?OPENBAO_BIN is required}"
: "${PROJECT_DIR:?PROJECT_DIR is required}"
: "${APP_ENV_FILE:?APP_ENV_FILE is required}"
: "${APP_ENCRYPTION_KEY:?APP_ENCRYPTION_KEY is required}"
: "${APPROVER_PASSWORD:?APPROVER_PASSWORD is required}"
: "${REQUESTER_PASSWORD:?REQUESTER_PASSWORD is required}"
: "${AGENT_PASSWORD:?AGENT_PASSWORD is required}"
: "${PUBLIC_ORIGIN:?PUBLIC_ORIGIN is required}"
: "${PLUGIN_DIRECTORY:?PLUGIN_DIRECTORY is required}"
: "${GITHUB_PLUGIN_SHA256:?GITHUB_PLUGIN_SHA256 is required}"
: "${GITHUB_APP_PRIVATE_KEY_FILE:?GITHUB_APP_PRIVATE_KEY_FILE is required}"

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

"${OPENBAO_BIN}" policy write openbao-authorizer-scanner "${PROJECT_DIR}/config/scanner-policy.hcl" >/dev/null
"${OPENBAO_BIN}" policy write openbao-authorizer-approver "${PROJECT_DIR}/config/approver-policy.hcl" >/dev/null
"${OPENBAO_BIN}" policy write openbao-authorizer-requester "${PROJECT_DIR}/deploy/local/requester-policy.hcl" >/dev/null
"${OPENBAO_BIN}" policy write openbao-authorizer-github-agent "${PROJECT_DIR}/deploy/local/github-agent-policy.hcl" >/dev/null

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
"${OPENBAO_BIN}" write auth/userpass/users/requester \
  password="${REQUESTER_PASSWORD}" policies=openbao-authorizer-requester >/dev/null
"${OPENBAO_BIN}" write auth/userpass/users/agent \
  password="${AGENT_PASSWORD}" policies=openbao-authorizer-github-agent >/dev/null

approver_login="$("${OPENBAO_BIN}" write -format=json auth/userpass/login/approver password="${APPROVER_PASSWORD}")"
requester_login="$("${OPENBAO_BIN}" write -format=json auth/userpass/login/requester password="${REQUESTER_PASSWORD}")"
agent_login="$("${OPENBAO_BIN}" write -format=json auth/userpass/login/agent password="${AGENT_PASSWORD}")"
approver_entity="$(jq -er '.auth.entity_id' <<<"${approver_login}")"
requester_entity="$(jq -er '.auth.entity_id' <<<"${requester_login}")"
agent_entity="$(jq -er '.auth.entity_id' <<<"${agent_login}")"

"${OPENBAO_BIN}" write identity/group \
  name=local-approvers type=internal \
  member_entity_ids="${approver_entity}" \
  policies=openbao-authorizer-approver >/dev/null
"${OPENBAO_BIN}" write identity/group \
  name=local-requesters type=internal \
  member_entity_ids="${requester_entity}" \
  policies=openbao-authorizer-requester >/dev/null
"${OPENBAO_BIN}" write identity/group \
  name=local-agents type=internal \
  member_entity_ids="${agent_entity}" \
  policies=openbao-authorizer-github-agent >/dev/null

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

scanner_response="$("${OPENBAO_BIN}" write -format=json auth/token/create-orphan \
  policies=openbao-authorizer-scanner no_default_policy=true ttl=24h renewable=false)"
scanner_token="$(jq -er '.auth.client_token' <<<"${scanner_response}")"

install -d -m 0700 "$(dirname "${APP_ENV_FILE}")"
temporary="${APP_ENV_FILE}.tmp.$$"
cat >"${temporary}" <<EOF
APP_ENCRYPTION_KEY=${APP_ENCRYPTION_KEY}
OPENBAO_SCANNER_TOKEN=${scanner_token}
OPENBAO_ADDRESS=${BAO_ADDR}
APPROVER_POLICY=openbao-authorizer-approver
EXPOSE_REQUEST_DATA=false
LISTEN_ADDRESS=127.0.0.1:18202
PUBLIC_ORIGIN=${PUBLIC_ORIGIN}
VAPID_PUBLIC_KEY=${VAPID_PUBLIC_KEY:-}
VAPID_PRIVATE_KEY=${VAPID_PRIVATE_KEY:-}
VAPID_SUBJECT=${VAPID_SUBJECT:-}
PUSH_ALLOWED_HOST_SUFFIXES=${PUSH_ALLOWED_HOST_SUFFIXES:-}
SCAN_INTERVAL=5s
SCAN_CONCURRENCY=8
EOF
chmod 0600 "${temporary}"
mv -f "${temporary}" "${APP_ENV_FILE}"

printf '%s\n' "${approver_login}" | jq -er '.auth.client_token' >"$(dirname "${APP_ENV_FILE}")/approver-token"
printf '%s\n' "${requester_login}" | jq -er '.auth.client_token' >"$(dirname "${APP_ENV_FILE}")/requester-token"
printf '%s\n' "${agent_login}" | jq -er '.auth.client_token' >"$(dirname "${APP_ENV_FILE}")/agent-token"
chmod 0600 "$(dirname "${APP_ENV_FILE}")/approver-token" "$(dirname "${APP_ENV_FILE}")/requester-token" "$(dirname "${APP_ENV_FILE}")/agent-token"
