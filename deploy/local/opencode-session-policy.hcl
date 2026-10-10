# Baseline policy for Session Tokens minted through the opencode-session token
# role. Sessions start with no secret access; everything else arrives as
# Grants on their Session Identity. Sites may add baseline paths here. The
# stanza duplicates part of `default` only so the policy is not empty.
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
