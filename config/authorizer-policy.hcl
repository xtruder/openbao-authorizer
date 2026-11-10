# Policy for the authorizer's own OpenBao token. It performs every OpenBao
# write; human approver tokens only authenticate approvers.

# The authorizer renews its own periodic token; it is created without the
# default policy, which would otherwise allow this.
path "auth/token/renew-self" {
  capabilities = ["update"]
}

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

# Write and delete the Grant policies, one path block per Grant: one per
# session-scope Requester, one per project (agent-grant-project-<name>) and
# agent-grant-global.
path "sys/policies/acl/agent-grant-*" {
  capabilities = ["create", "read", "update", "delete"]
}

# Each Grantable Rule with `discover` needs `list` on its discover path, e.g.:
# path "github/permissionsets" {
#   capabilities = ["list"]
# }
