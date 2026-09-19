path "auth/token/accessors" {
  capabilities = ["list", "sudo"]
}

path "sys/control-group/request" {
  capabilities = ["update"]

  required_parameters = ["accessor"]
  allowed_parameters = {
    "accessor" = []
  }
}

# Approval UI context only: permission sets contain fixed repository selectors
# and permission names, never GitHub tokens or the App private key.
path "github/permissionset/*" {
  capabilities = ["read"]
}
