# Attach this policy to the identity used by Vault Guard or its Vault Agent.
path "kv/data/development/credentials" {
  capabilities = ["read"]
}
