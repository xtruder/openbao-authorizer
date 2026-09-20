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
  scanner_token_file = "/run/secrets/openbao-scanner-token"
  approver_policy    = "openbao-authorizer-approver"
}

scanner {
  interval    = "15s"
  concurrency = 8
}

requests {
  expose_data = false
}

approval_context "github-token" {
  match_path = "github/token/{name}"
  read_path  = "github/permissionset/{name}"
}
