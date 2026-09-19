path "kv/data/payroll" {
  capabilities = ["create", "update"]

  control_group = {
    ttl               = "5m"
    self_auth_allowed = false

    factor "payroll-approvers" {
      controlled_capabilities = ["create", "update"]

      identity {
        group_names = ["e2e-approvers"]
        approvals   = 1
      }
    }
  }
}
