path "kv/data/controlled" {
  capabilities = ["create", "update"]

  control_group = {
    ttl               = "30m"
    self_auth_allowed = false

    factor "local-approvers" {
      controlled_capabilities = ["create", "update"]

      identity {
        group_names = ["local-approvers"]
        approvals   = 1
      }
    }
  }
}
