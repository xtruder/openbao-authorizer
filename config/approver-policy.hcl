# Marker policy for humans who may sign in to the authorizer PWA. The
# authorizer checks for this policy's name once, at login, and then revokes the
# login token; approver tokens never write to OpenBao. The stanza only keeps
# the policy non-empty.
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
