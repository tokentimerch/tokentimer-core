"use strict";
// Only this task's fixed loopback endpoints/databases. No .env loader.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const variants = { core: 57500, cloud: 57600, enterprise: 57700 };
const variant = process.argv[2];
assert.ok(Object.hasOwn(variants, variant));
const base = `http://127.0.0.1:${variants[variant]}`;
const pool = new Pool({
  host: "127.0.0.1",
  port: 57470,
  user: "wildcard_fixture",
  password: "isolated-fixture-only",
  database: `wildcard_candidate_${variant}_image`,
  max: 1,
});
const jar = new Map();
async function request(url, options = {}) {
  const response = await fetch(base + url, {
    ...options,
    headers: {
      Cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; "),
      ...options.headers,
    },
  });
  for (const cookie of response.headers.getSetCookie()) {
    const pair = cookie.split(";")[0],
      i = pair.indexOf("=");
    jar.set(pair.slice(0, i), pair.slice(i + 1));
  }
  return response;
}
async function main() {
  assert.equal((await request("/health")).status, 200);
  const schema = (
    await pool.query(
      "SELECT COUNT(*)::int n FROM information_schema.tables WHERE table_name='certops_consumer_deployments'",
    )
  ).rows[0];
  assert.equal(schema.n, 1);
  if (variant === "cloud") {
    const privateReject = await request(
      `/api/v1/workspaces/${crypto.randomUUID()}/certops/distribution-groups/${crypto.randomUUID()}/rollouts`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          privateKeyPem:
            "-----BEGIN PRIVATE KEY-----\nfixture-marker\n-----END PRIVATE KEY-----",
        }),
      },
    );
    assert.equal(
      privateReject.status,
      422,
      "Cloud must reject private material before auth/plan gates",
    );
  }
  const password = `Fixture-${crypto.randomUUID()}!`,
    email = `wildcard-${crypto.randomUUID()}@example.test`;
  const actor = (
    await pool.query(
      "INSERT INTO users(email,display_name,password_hash,auth_method,email_verified) VALUES($1,'Image fixture',$2,'local',true) RETURNING id",
      [email, await bcrypt.hash(password, 10)],
    )
  ).rows[0].id;
  const workspaceId = crypto.randomUUID();
  await pool.query(
    "INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'Image fixture',$2,$3)",
    [workspaceId, actor, variant === "cloud" ? "pro" : "oss"],
  );
  await pool.query(
    "INSERT INTO workspace_memberships(user_id,workspace_id,role,invited_by) VALUES($1,$2,'admin',$1)",
    [actor, workspaceId],
  );
  const csrfResponse = await request("/api/csrf-token");
  assert.equal(csrfResponse.status, 200);
  const csrf = (await csrfResponse.json()).csrfToken;
  const login = await request("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-csrf-token": csrf },
    body: JSON.stringify({ email, password }),
  });
  assert.equal(login.status, 200, "Production fixture login");
  const groups = await request(
    `/api/v1/workspaces/${workspaceId}/certops/distribution-groups`,
  );
  assert.equal(
    groups.status,
    200,
    "Base CertOps must be available to a workspace admin",
  );
  assert.deepEqual((await groups.json()).groups, []);
  const denied = await request(
    `/api/v1/workspaces/${crypto.randomUUID()}/certops/distribution-groups`,
  );
  assert.ok([403, 404].includes(denied.status));
  if (variant === "enterprise") {
    const report = await request(
      `/api/v1/workspaces/${workspaceId}/certops/compliance/report`,
    );
    assert.ok(
      [402, 403].includes(report.status),
      "Unlicensed compliance must remain gated while base CertOps works",
    );
  }
  console.log(
    JSON.stringify({
      passed: true,
      variant,
      checks: [
        "production_boot",
        "material_schema",
        "session_workspace_access",
        "cross_workspace_denial",
        ...(variant === "cloud" ? ["private_rejection_before_auth"] : []),
        ...(variant === "enterprise"
          ? ["base_certops_without_compliance_license"]
          : []),
      ],
    }),
  );
}
main()
  .catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  })
  .finally(() => pool.end());
