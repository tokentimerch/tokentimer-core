# Authenticate certificate-distribution agents to Vault

This Linux walkthrough provisions one issuer and one consumer with separate
AppRoles. Repeat the consumer procedure with a distinct role for each host.
It does not qualify an agent build or enable its experimental capabilities.
Use your own HTTPS Vault, trusted CA, KV v2 mount and real workspace/group UUIDs.
The operator needs the Vault CLI and `jq`. Never send these credentials to
TokenTimer's API, database, job payloads, dashboards or logs.

## 1. Create narrowly scoped roles as a Vault administrator

Run these commands with an administrative Vault identity on your management
host. Authenticate with your organization's normal method; do not deploy that
identity to an agent. Enable KV v2 at `secret` and AppRole at `approle` only if
those mounts do not already exist (`vault secrets list -detailed`, `vault auth list`).

```sh
export VAULT_ADDR=https://vault.example.test:8200
export VAULT_CACERT=/etc/vault/ca.pem
export WORKSPACE_ID=11111111-1111-4111-8111-111111111111
export GROUP_ID=22222222-2222-4222-8222-222222222222
export PREFIX="tokentimer/$WORKSPACE_ID/$GROUP_ID"
export ISSUER_ROLE="tt-issuer-$GROUP_ID"
export CONSUMER_ROLE="tt-consumer-a-$GROUP_ID"
umask 077

vault policy write "$ISSUER_ROLE" - <<EOF
path "secret/data/$PREFIX/bundles/*" {
  capabilities = ["create", "read"]
}
EOF
vault policy write "$CONSUMER_ROLE" - <<EOF
path "secret/data/$PREFIX/bundles/*" {
  capabilities = ["read"]
}
EOF
for role in "$ISSUER_ROLE" "$CONSUMER_ROLE"; do
  vault write "auth/approle/role/$role" \
    token_policies="$role" token_period=20m token_num_uses=0 \
    secret_id_ttl=24h secret_id_num_uses=0
done
```

The role's default policy supplies token self-renewal; it grants no access to
certificate material. Do not attach additional broad material policies. A
scanner must use its own identity with explicit `deny` on both
`secret/data/$PREFIX/bundles/*` and `secret/metadata/$PREFIX/bundles/*`.
Issuer and consumer roles need no list, update, delete, destroy or metadata rights.

## 2. Deliver role credentials and test login

For each role, generate files on the protected provisioning host. Substitute
`ROLE` for the issuer or that particular consumer. The JSON includes a SecretID;
keep it private. Retain its accessor in protected administrator inventory for
rotation. Deliver only `role-id` and `secret-id` through your secure provisioning
channel to the corresponding host.

```sh
export ROLE="$ISSUER_ROLE" # use $CONSUMER_ROLE for the consumer
install -d -m 0700 "$ROLE"
vault read -field=role_id "auth/approle/role/$ROLE/role-id" > "$ROLE/role-id"
vault write -f -format=json "auth/approle/role/$ROLE/secret-id" > "$ROLE/credential.json"
jq -r .data.secret_id "$ROLE/credential.json" > "$ROLE/secret-id"
jq -r .data.secret_id_accessor "$ROLE/credential.json" > "$ROLE/secret-id-accessor"
chmod 0600 "$ROLE/"*
```

On the issuer host use `/etc/tokentimer/vault-issuer`; on the consumer use
`/etc/tokentimer/vault-consumer-a`. Run Vault Agent and the corresponding
TokenTimer agent as the same dedicated, unprivileged OS account. Provision the
credential directory and `/run/tokentimer-vault/issuer` (or `consumer-a`) with
owner-only access. Set role/SecretID files to 0600 and their directories to 0700;
ensure the service account owns them. Recreate the `/run` directory at boot. Set `HOME` to the service account's own accessible home directory when starting Vault Agent; do not inherit `/root` from a privileged provisioning shell.

As that service account, test an issuer login without printing the token:

```sh
umask 077
vault write -format=json auth/approle/login \
  role_id=@/etc/tokentimer/vault-issuer/role-id \
  secret_id=@/etc/tokentimer/vault-issuer/secret-id \
  | jq -r .auth.client_token > /run/tokentimer-vault/issuer/login-test
VAULT_TOKEN="$(cat /run/tokentimer-vault/issuer/login-test)" \
  vault token lookup -format=json | jq '{renewable: .data.renewable, policies: .data.policies}'
VAULT_TOKEN="$(cat /run/tokentimer-vault/issuer/login-test)" vault token revoke -self
rm /run/tokentimer-vault/issuer/login-test
```

Repeat with the consumer's own paths. No administrative Vault token is needed
by either service account.

## 3. Start Vault Agent with a protected token sink

Create `/etc/tokentimer/vault-issuer/agent.hcl` with the following content.
For a consumer, replace **every** `vault-issuer`/`issuer` path with
`vault-consumer-a`/`consumer-a`; never share role credentials or sinks.

```hcl
pid_file = "/run/tokentimer-vault/issuer/agent.pid"
vault {
  address = "https://vault.example.test:8200"
  ca_cert = "/etc/vault/ca.pem"
}
auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path = "/etc/tokentimer/vault-issuer/role-id"
      secret_id_file_path = "/etc/tokentimer/vault-issuer/secret-id"
      remove_secret_id_file_after_reading = false
    }
  }
  sink "file" {
    config = {
      path = "/run/tokentimer-vault/issuer/token"
      mode = 384 # 0600: owner read/write only
    }
  }
}
```

```sh
vault agent -config=/etc/tokentimer/vault-issuer/agent.hcl
```

Supervise that command with your service manager, including restart after
failure and ownership/permission checks after reboot. The persistent SecretID
supports reauthentication after an Agent restart; rotate it before its 24-hour
expiry. A one-use SecretID requires a provisioner for every reauthentication.
Use an unwrapped file sink: TokenTimer expects a raw token, not a wrapping token.
Set the local material store's `tokenFile` to the issuer's sink on the issuer
and the consumer's sink on that consumer. The adapter rereads it per request.

## 4. Verify access without exposing a private-key bundle

Use an actual published material-version UUID for `VERSION_ID` and the same
`PREFIX` used by the local group policy. Run issuer and consumer checks on
their respective hosts; these commands print permissions, not credentials.

```sh
export VERSION_ID=33333333-3333-4333-8333-333333333333
VAULT_TOKEN="$(cat /run/tokentimer-vault/issuer/token)" \
  vault token capabilities "secret/data/$PREFIX/bundles/$VERSION_ID"
# Expected: create, read. No update/delete/list.
VAULT_TOKEN="$(cat /run/tokentimer-vault/consumer-a/token)" \
  vault token capabilities "secret/data/$PREFIX/bundles/$VERSION_ID"
# Expected: read only.
VAULT_TOKEN="$(cat /run/tokentimer-vault/consumer-a/token)" \
  vault kv get -format=json -version=1 "secret/$PREFIX/bundles/$VERSION_ID" > /dev/null
VAULT_TOKEN="$(cat /run/tokentimer-vault/consumer-a/token)" \
  vault token capabilities "secret/metadata/$PREFIX/bundles"
# Expected: deny. Repeat for another group's data path: deny.
```

Also verify that the scanner's identity reports `deny` on both the data and
metadata paths above. Do not test by printing or copying a bundle to a terminal.

## 5. Rotate credentials and verify reauthentication

As the Vault administrator, issue a new SecretID using step 2 and retain its
new accessor. Deliver the new SecretID to the correct host as `secret-id.new`,
set its owner and mode to match `secret-id`, then atomically rename it in the
same directory. Restart only that Vault Agent instance with the same config.
Confirm its sink exists with mode 0600 and repeat the access checks.

Destroy the old SecretID using its stored accessor:

```sh
vault write "auth/approle/role/$ROLE/secret-id-accessor/destroy" \
  secret_id_accessor="$OLD_SECRET_ID_ACCESSOR"
```

SecretID revocation blocks future logins; it does not revoke tokens already
issued. For compromise or a forced rotation, have the administrator revoke the
old issued token by its accessor (`vault token revoke -accessor "$OLD_TOKEN_ACCESSOR"`),
then confirm Vault Agent reauthenticates with the new SecretID. Repeat the
read/deny checks and a real approved rollout. Keep credentials and private keys
out of the evidence report; retain role names, policy checks, timestamps and
public served fingerprints instead. Never fabricate a successful job or receipt.

References: HashiCorp's [AppRole API](https://developer.hashicorp.com/vault/api-docs/auth/approle),
[Vault Agent AppRole method](https://developer.hashicorp.com/vault/docs/agent-and-proxy/autoauth/methods/approle),
and [file sink](https://developer.hashicorp.com/vault/docs/agent-and-proxy/autoauth/sinks/file).
