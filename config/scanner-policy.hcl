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
