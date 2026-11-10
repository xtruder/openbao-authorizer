# Appended to config/authorizer-policy.hcl locally: the discover paths of the
# grantable rules in app.hcl.
path "kv/metadata/agents" {
  capabilities = ["list"]
}

path "github/permissionsets" {
  capabilities = ["list"]
}
