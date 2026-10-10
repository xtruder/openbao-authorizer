# Policy for the authorizer's own OpenBao token. It performs every OpenBao
# write; human approver tokens only authenticate approvers.

# Read Requester entities' policies, and attach their grant policy. Entity updates may change only `policies`. OpenBao cannot restrict
# which policy names are set: allowed_parameters globs reject JSON lists and
# accept a comma-joined string with any names in it. The key-only form still
# blocks updates to name, metadata and disabled.
path "identity/entity/id/*" {
  capabilities = ["read", "update"]

  allowed_parameters = {
    "policies" = []
  }
}

# Write and delete one policy per Requester, one path block per Grant.
path "sys/policies/acl/agent-grant-*" {
  capabilities = ["create", "read", "update", "delete"]
}
