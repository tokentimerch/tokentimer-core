# Vendored dependencies for a self-contained agent package

The CertOps agent is distributed as a standalone directory/tarball installed by
`packages/agent/scripts/install-agent.sh`. That installer copies only
`packages/agent`, so the agent must not `require()` sibling monorepo paths such
as `packages/log-scrub` or `apps/api`.

These vendor copies keep the shipped package self-contained.

**Synced copies** (byte-for-byte from the monorepo):

| Vendored file | Upstream source of truth |
| --- | --- |
| `log-scrub/secret-material.js` | `packages/log-scrub/secret-material.js` (`@tokentimer/log-scrub`) |
| `contracts/canonical-json.cjs` | `packages/contracts/certops/canonical-json.cjs` (`@tokentimer/contracts`) |
| `contracts/agent-protocol.schema.json` | `packages/contracts/certops/agent-protocol.schema.json` (`@tokentimer/contracts`; byte-identical, no attribution header) |

**Generated artifacts** (compiled from the vendored schema above, not copied):

| Vendored file | Produced by |
| --- | --- |
| `contracts/agent-protocol-validator.generated.js` | `scripts/build-protocol-validator.js` — an AJV *standalone* validator |
| `ajv-runtime/ucs2length.js` | the same script; the one AJV runtime helper the generated validator requires |

The validator is precompiled precisely so that `ajv` and `ajv-formats` stay in
`devDependencies` and never enter the shipped runtime: the agent package has
**no** production `dependencies`, and an installed agent that tried to
`require("ajv")` would crash. Do not hand-edit either generated file.

Refresh with (from `packages/agent`):

```sh
pnpm run sync-vendor      # node scripts/sync-vendor.js
```

`sync-vendor` copies the three synced files and then chains into
`build-protocol-validator.js` automatically, so the generated validator can
never lag the schema it was compiled from.

`packages/agent/scripts/check-shipped-sources.js` (wired up as the package's
`build` script) and `packages/agent/scripts/vendor-sync.test.js` fail if the
copies drift or if shipped sources regain monorepo-relative imports.
