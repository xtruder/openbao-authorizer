# Baseline policy for Named Tokens minted through the named-identity token
# role. Named Identities start with no secret access; everything else arrives
# as Grants, through the agent-grant-project-<name> and agent-grant-global
# policies the token is minted with. Sites may add baseline paths here.
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# A project's Named Token mints the session tokens of its agent sessions.
path "auth/token/create/agent-session" {
  capabilities = ["update"]
}
