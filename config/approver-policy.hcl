path "sys/control-group/authorize" {
  capabilities = ["update"]

  required_parameters = ["accessor"]
  allowed_parameters = {
    "accessor" = []
  }
}
