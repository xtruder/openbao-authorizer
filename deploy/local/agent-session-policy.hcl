# Baseline policy for agent session tokens minted through the agent-session
# token role by a project's Named Token. Sessions start with no secret access;
# Grants arrive on the session's own entity and through the project and global
# Grant policies the token is minted with. The stanza duplicates part of
# `default` only so the policy is not empty.
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
