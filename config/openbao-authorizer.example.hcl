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
  # Only tokens created through this token role are accepted as Session Tokens.
  session_token_role = "opencode-session"
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
