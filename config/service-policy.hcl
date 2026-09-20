path "sys/control-group/request" {
  capabilities = ["update"]

  required_parameters = ["accessor"]
  allowed_parameters = {
    "accessor" = []
  }
}

path "auth/token/revoke-accessor" {
  capabilities = ["update", "sudo"]

  required_parameters = ["accessor"]
  allowed_parameters = {
    "accessor" = []
  }
}
