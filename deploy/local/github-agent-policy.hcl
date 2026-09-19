path "github/token/project-*" {
  capabilities = ["read"]

  control_group = {
    ttl               = "15m"
    self_auth_allowed = false

    factor "local-approvers" {
      controlled_capabilities = ["read"]

      identity {
        group_names = ["local-approvers"]
        approvals   = 1
      }
    }
  }
}
