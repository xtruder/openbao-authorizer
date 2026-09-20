path "auth/token/accessors" {
  capabilities = ["list", "sudo"]
}

path "sys/control-group/request" {
  capabilities = ["update"]
}

path "auth/token/revoke-accessor" {
  capabilities = ["update", "sudo"]
}
