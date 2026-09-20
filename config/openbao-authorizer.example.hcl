server {
  listen_address   = "127.0.0.1:8080"
  public_origin    = "https://approvals.example.com"
  insecure_cookies = false
  static_directory = ""
}

storage {
  database_path       = "/var/lib/openbao-authorizer/app.db"
  encryption_key_file = "/run/secrets/openbao-authorizer-key"
}

openbao {
  address            = "https://openbao.example.com"
  namespace          = ""
  ca_file            = "/etc/ssl/certs/organization-openbao-ca.pem"
  service_token_file = "/run/secrets/openbao-authorizer-service-token"
  approver_policy    = "openbao-authorizer-approver"
}

reconciliation {
  interval = "15s"
}

requests {
  expose_data    = false
  require_reason = false
}

approval_context "github-token" {
  match_path = "github/token/{name}"
  read_path  = "github/permissionset/{name}"
}
