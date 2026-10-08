# Split into three separately assigned policies. Replace the mount/prefix.
# Issuer: create-only immutable objects, plus pinned read for reconciliation.
path "secret/data/tokentimer/WORKSPACE/GROUP/bundles/*" {
  capabilities = ["create", "read"]
}

# Consumer: put this stanza in a separate policy, with no issuer policy.
# path "secret/data/tokentimer/WORKSPACE/GROUP/bundles/*" {
#   capabilities = ["read"]
# }

# Scanner: mandatory explicit denial, in the scanner's separate policy.
# path "secret/data/tokentimer/WORKSPACE/GROUP/bundles/*" {
#   capabilities = ["deny"]
# }
# path "secret/metadata/tokentimer/WORKSPACE/GROUP/bundles/*" {
#   capabilities = ["deny"]
# }

# No list, update, delete, destroy or metadata mutation rights are required.
