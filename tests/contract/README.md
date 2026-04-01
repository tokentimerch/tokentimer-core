# Contract Tests

Contract tests verify that `tokentimer-enterprise` and `tokentimer-cloud` remain compatible with `tokentimer-core` as they evolve independently.

## Purpose

These tests ensure:

1. **API Endpoints** - Core API contracts are stable
2. **Queue Schemas** - Message formats remain consistent
3. **Runtime Extensions** - Core auth-feature extension surface is stable
4. **Limits Policy** - Core oss limits policy remains stable

## Running Tests

```bash
# Run all contract tests
pnpm run check:contracts
pnpm run check:contracts:integrity
pnpm run test:contracts

# Run specific contract test file
node --test tests/contract/api-endpoints.test.js
node --test tests/contract/api-openapi-conformance.test.js
node --test tests/contract/queue-schemas.test.js
node --test tests/contract/queue-schemas-ajv.test.js
node --test tests/contract/auth-features-defaults.test.js
node --test tests/contract/limits-policy.test.js
```

## Test Categories

### 1. API Endpoint Tests (`api-endpoints.test.js`)

Verifies that core API endpoints:

- Return expected status codes
- Accept required parameters
- Return expected response structures
- Enforce authentication
- Enforce RBAC

**Tests**:

- Health check endpoint
- Session and CSRF contract endpoints
- Authentication (login/features)
- Protected endpoint authentication requirements

**Execution policy**:

- `CONTRACT_API_REQUIRED=1` enforces runtime API checks and fails if API is unavailable.
- `CONTRACT_API_REQUIRED=0` allows static-only jobs to skip runtime API checks.
- In CI, `CONTRACT_API_REQUIRED` must be explicitly set to `0` or `1`.

### 2. Queue Schema Tests (`queue-schemas.test.js`)

Verifies that queue message schemas:

- Have required fields defined
- Match JSON Schema specifications
- Validate correctly

**Schemas Tested**:

- Alert discovery messages
- Alert delivery messages
- Weekly digest messages

### 3. Runtime Extension Tests (`auth-features-defaults.test.js`)

Verifies that:

- Core exposes `/api/auth/features` route
- Core default auth feature flags remain stable
- Runtime extension expectations remain explicit

**Tests**:

- `/api/auth/features` route presence
- Default `saml: false` and `oidc: false` behavior

**Static Contract Artifacts**:

- `packages/contracts/runtime-extensions/plugin-context.contract.json`

### 4. Limits Policy Tests (`limits-policy.test.js`)

Verifies that:

- Core defaults remain oss-unlimited
- Workspace/member limit defaults stay unlimited
- Workspace creation policy remains core-agnostic

**Tests**:

- Token/alert oss limit defaults
- Workspace/member policy defaults
- Workspace creation behavior

### 5. API Static Specification (`packages/contracts/openapi/openapi.yaml`)

Verifies that:

- Core publishes a static OpenAPI baseline artifact
- Consumer repositories can pin and compare contract evolution

### 6. Contract Integrity Gate (`scripts/check-contracts-integrity.js`)

Verifies that:

- Contract namespace names are unique
- Contract entry identifiers are unique per namespace
- `existing` entry files are present and non-empty
- JSON contract artifacts are parseable
- OpenAPI artifact is structurally present and versioned

## Integration with CI

These tests run in CI for:

- `tokentimer-core` - Via `check:contracts`, `check:contracts:integrity`, `test:contracts` (static mode), and dedicated runtime API contract checks with `CONTRACT_API_REQUIRED=1`
- `tokentimer-enterprise` - Before release (verify core compatibility)
- `tokentimer-cloud` - Before deployment (verify core compatibility)

## Adding New Contract Tests

When adding breaking changes to core, add corresponding contract tests:

```javascript
// Example: New API endpoint contract
it("GET /api/v1/new-endpoint should return expected structure", async () => {
  const res = await fetch(`${API_BASE}/api/v1/new-endpoint`);
  const data = await res.json();

  assert.ok(data.expectedField);
  assert.strictEqual(typeof data.expectedField, "string");
});
```

## Contract Violations

If a contract test fails:

1. **Determine if it's a breaking change** - Does it affect existing consumers?
2. **Update version appropriately** - Breaking changes require MAJOR version bump
3. **Update contract tests** - Reflect new expectations
4. **Document in CHANGELOG** - Note the breaking change
5. **Update compatibility matrix** - In `compatibility.manifest.json` (variants)

## Philosophy

Contract tests are **not exhaustive integration tests**. They verify:

- ✅ Core interfaces remain stable
- ✅ Breaking changes are caught
- ✅ Runtime extension contracts stay explicit
- ✅ Message formats are consistent

They do **not** test:

- ❌ Full application logic
- ❌ Edge cases and error handling
- ❌ Performance
- ❌ UI functionality

For those, see `tests/integration/`.
