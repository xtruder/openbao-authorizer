path "auth/token/accessors" {
  capabilities = ["list", "sudo"]
}

path "sys/control-group/request" {
  capabilities = ["update"]
}
