# The opencode plugin's AppRole may only mint Session Tokens through the
# opencode-session token role, which pins their policies and entity aliases.
path "auth/token/create/opencode-session" {
  capabilities = ["update"]
}
