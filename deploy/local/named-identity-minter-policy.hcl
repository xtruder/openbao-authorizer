# Humans holding this policy may mint Named Tokens with bao-cred auth, only
# through the named-identity token role, which pins their policies.
path "auth/token/create/named-identity" {
  capabilities = ["update"]
}
