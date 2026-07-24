# Vendored dependencies for a self-contained agent package

The CertOps agent is distributed as a standalone directory/tarball installed by
`scripts/install-agent.sh`. That installer copies only `packages/agent`, so the
agent must not `require()` sibling monorepo paths such as `packages/log-scrub`
or `apps/api`.

These vendor copies keep the shipped package self-contained:

| Vendored file | Upstream source of truth |
| --- | --- |
| `log-scrub/secret-material.js` | `packages/log-scrub/secret-material.js` (`@tokentimer/log-scrub`) |
| `contracts/canonical-json.cjs` | `packages/contracts/certops/canonical-json.cjs` (`@tokentimer/contracts`) |
| `contracts/agent-protocol.schema.json` | `packages/contracts/certops/agent-protocol.schema.json` (`@tokentimer/contracts`; byte-identical, no attribution header) |

Refresh with:

```sh
node scripts/sync-vendor.js
```

`scripts/check-shipped-sources.js` and `scripts/vendor-sync.test.js` fail if the
copies drift or if shipped sources regain monorepo-relative imports.
