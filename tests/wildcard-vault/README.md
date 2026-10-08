# Isolated qualification fixtures

Run from the separate implementation checkout. Never point these commands at
the concurrent manual audit, a customer database or production credentials.
Project: `tt-wildcard-vault-20261008`. Containers have CPU/memory limits; run one
test runner and one image build at a time. No default integration stack is used.

```powershell
docker compose -p tt-wildcard-vault-20261008 -f tests/wildcard-vault/compose.yaml up -d postgres vault redis mail challtestsrv pebble
docker compose -p tt-wildcard-vault-20261008 -f tests/wildcard-vault/compose.yaml --profile qualification build lifecycle
New-Item -ItemType Directory -Force .scratch/wildcard | Out-Null
docker cp tt-wildcard-vault-20261008-pebble-1:/test/certs/pebble.minica.pem .scratch/wildcard/pebble-ca.pem
docker compose -p tt-wildcard-vault-20261008 -f tests/wildcard-vault/compose.yaml run --rm -e NODE_EXTRA_CA_CERTS=/repo/.scratch/wildcard/pebble-ca.pem lifecycle
```

The lifecycle scenario calls the production native issuer `executeJob`, performs
real DNS-01 with Certbot/Pebble, publishes and reads through the production Vault
adapter over a fixture HTTPS proxy, and installs/verifies two separate NGINX and
HAProxy processes. It executes two ACME orders total, including renewal. It
tests recovery, offline catch-up without another order, stale generation,
rollback, cross-workspace denial, unavailable lease before mutation, wrong SNI,
reload failure, local read-only reconciliation, drift and approved read-only
verification without install/reload. Fixture lease callbacks are injected here;
the PostgreSQL test separately exercises actual dispatch signatures, nonce,
claim, approval, lease policy, result replay and transactional promotion.
These tests do not claim an enrolled production agent release is qualified.

Pebble is a throwaway CA. Its root is generated at startup. This fixture obtains
only public CA certificates; it never obtains a CA private key. Certbot's
`--no-verify-ssl` flag is confined to this throwaway ACME fixture. Vault upstream
HTTP is confined to the fixture bridge; production adapter configuration requires
HTTPS. No production insecure-transport switch exists.

TLS listeners use container ports 8443/9443. `compose run --rm` does not publish
the declared 58443/59443 service ports; probes execute inside the runner. Other
loopback endpoints are PostgreSQL 57470, Vault 58200, Redis 57379, email UI 58025,
SMTP 51025, Pebble 58400/58500 and DNS fixture HTTP 58055/UDP 58053. Fixture
passwords/root tokens are public test values, never customer credentials.

`postgres.test.cjs` hard-requires 127.0.0.1:57470 and a
`wildcard_candidate_*` database. Use a fresh database for each run because the
signing-key encryption key is ephemeral. From PowerShell:

```powershell
$env:DB_HOST='127.0.0.1'; $env:DB_PORT='57470'
$env:DB_USER='wildcard_fixture'; $env:DB_PASSWORD='isolated-fixture-only'
$env:DB_NAME='wildcard_candidate_' + [guid]::NewGuid().ToString('N')
$env:NODE_ENV='test'; $env:CERTOPS_ENABLED='true'
docker compose -p tt-wildcard-vault-20261008 -f tests/wildcard-vault/compose.yaml exec -T postgres createdb -U wildcard_fixture $env:DB_NAME
node apps/api/migrations/migrate.js
node --test tests/wildcard-vault/postgres.test.cjs
```

For Cloud, first materialize its manifest mappings from the exact candidate Core
SHA. Create another fresh database, run
`../tokentimer-cloud/apps/saas/migrations/migrate.js`, set
`TT_WILDCARD_API_ROOT` to the absolute candidate Cloud `apps/saas` directory,
and run the same test. Quota enforcement is explicitly enabled even under
`NODE_ENV=test`. Additional assertions exercise the real Cloud outbox worker,
zero source allocation after quota rejection, frozen-workspace admission denial
and safe continuing-result acceptance. Clear `TT_WILDCARD_API_ROOT` for Core.

Agent adapter fault tests run with:

```powershell
$env:TT_WILDCARD_VAULT_REAL='1'
node --test --test-concurrency=1 packages/agent/src/material-store/material-store.test.js
```

The fixture URL is a test constructor option, not production configuration.
The remaining fault cases use bounded local HTTP fixtures.

Stop only this project's services when finished:

```powershell
docker compose -p tt-wildcard-vault-20261008 -f tests/wildcard-vault/compose.yaml --profile images --profile qualification down
```

Volumes remain for review. Destroy only these named volumes after explicitly
deciding their evidence is no longer needed. Never use global Docker cleanup.
