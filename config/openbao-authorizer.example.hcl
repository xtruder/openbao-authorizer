server {
  listen_address   = "127.0.0.1:8080"
  public_origin    = "https://approvals.example.com"
  insecure_cookies = false
  static_directory = ""
  session_ttl      = "168h" # approver sessions; removing approver_policy takes effect at next login
}

storage {
  database_path       = "/var/lib/openbao-authorizer/app.db"
  encryption_key_file = "/run/secrets/openbao-authorizer-key"
}

openbao {
  address               = "https://openbao.example.com"
  namespace             = ""
  ca_file               = "/etc/ssl/certs/organization-openbao-ca.pem"
  authorizer_token_file = "/run/secrets/openbao-authorizer-token"
  approver_policy       = "openbao-authorizer-approver"
}

# Approvers sign in to OpenBao from the PWA, which then trades the token for an
# app session; the authorizer never sees their credentials. OpenBao must allow
# the public origin in sys/config/cors. Without method blocks only pasting a
# token is offered.
approver_login {
  openbao_address = "https://openbao.example.com" # as reachable from approvers' browsers
  namespace       = ""
  method "token" {}
  method "userpass" {
    mount = "userpass"
    label = "Username & password"
  }
  method "oidc" {
    mount = "oidc"
    label = "Single sign-on"
    role  = "" # empty uses the mount's default role; it must allow <public_origin>/oidc/callback
  }
}

# Requester Rules decide which tokens may file Grant Requests; the first match
# wins. token_role matches the token's role, auth_mount the auth mount it was
# issued from, so every token of that mount qualifies: don't share the mount with
# other machine logins. Tokens without an identity entity are always refused.
requester "opencode" {
  token_role = "opencode-session"
}

requester "ci" {
  auth_mount = "approle"
}

grants {
  default_ttl = "72h" # TTL when a request sets none; also the cap for rules without max_ttl
  pending_ttl = "24h" # undecided items expire after this
}

# Grantable Rules use OpenBao ACL path patterns: `+` matches one segment and a
# trailing `*` matches any suffix. Rules with a sys, auth, identity or cubbyhole
# segment (any position, any case, or a glob such as `s*`), a wildcard first
# segment, or sudo are rejected at startup. Requested paths with such a segment
# are always refused, so these KV keys can't be granted.
grantable "github-token" {
  path         = "github/token/project-*"
  capabilities = ["read"]
  max_ttl      = "8h"
}

grantable "project-secrets" {
  path         = "kv/data/projects/+/*"
  capabilities = ["read"]
  max_ttl      = "24h"
}
