"use strict";
// Only this task's fixed loopback endpoints/databases. No .env loader.
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
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
    signal: AbortSignal.timeout(5000),
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
  const readyUntil = Date.now() + 60_000;
  let ready = false;
  while (Date.now() < readyUntil) {
    try {
      ready = (await request("/health")).status === 200;
      if (ready) break;
    } catch {
      /* A newly started production process may not be listening yet. */
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  assert.ok(ready, "Production API must become healthy within 60 seconds");
  const schema = (
    await pool.query(
      "SELECT COUNT(*)::int n FROM information_schema.tables WHERE table_name='certops_consumer_deployments'",
    )
  ).rows[0];
  assert.equal(schema.n, 1);
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
  if (variant === "cloud") {
    const postLoginCsrf = (await (await request("/api/csrf-token")).json())
      .csrfToken;
    await pool.query(
      "UPDATE workspaces SET plan='free',is_frozen=false WHERE id=$1",
      [workspaceId],
    );
    const privateReject = await request(
      `/api/v1/workspaces/${workspaceId}/certops/distribution-groups/${crypto.randomUUID()}/rollouts`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-csrf-token": postLoginCsrf,
        },
        body: JSON.stringify({
          privateKeyPem:
            "-----BEGIN PRIVATE KEY-----\nfixture-marker\n-----END PRIVATE KEY-----",
        }),
      },
    );
    assert.equal(
      privateReject.status,
      422,
      "Cloud must reject private material before feature/plan gates",
    );
    assert.equal(
      (await privateReject.json()).code,
      "PRIVATE_KEY_MATERIAL_REJECTED",
    );
    const admission = await request(
      `/api/v1/workspaces/${workspaceId}/certops/distribution-groups/${crypto.randomUUID()}/rollouts`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-csrf-token": postLoginCsrf,
        },
        body: "{}",
      },
    );
    assert.ok(
      [402, 403].includes(admission.status),
      "A Free workspace cannot admit a new rollout",
    );
    await pool.query(
      "UPDATE workspaces SET plan='pro',is_frozen=false WHERE id=$1",
      [workspaceId],
    );
  }
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
  if (process.argv.includes("--dashboard")) {
    const dashboard = `http://127.0.0.1:${variants[variant] + 1}`;
    const page = await fetch(`${dashboard}/certops/renewals`, {
      signal: AbortSignal.timeout(5000),
    });
    assert.equal(page.status, 200);
    const image = {
      core: "localhost:58600/core-dashboard:20261008",
      cloud: "cloud-web-runtime:wildcard-vault-20261008",
      enterprise: "enterprise-dashboard:wildcard-vault-20261008",
    }[variant];
    const matched = execFileSync(
      "docker",
      [
        "run",
        "--rm",
        "--name",
        "tt-wildcard-" + variant + "-dashboard-verify-20261008",
        "--network",
        "none",
        "--cpus",
        "0.25",
        "--memory",
        "64m",
        "--entrypoint",
        "sh",
        image,
        "-c",
        'grep -l "Certificate distribution" /usr/share/nginx/html/assets/*.js',
      ],
      { encoding: "utf8", timeout: 30000 },
    )
      .trim()
      .split("\n");
    assert.ok(matched.length);
    for (const file of matched) {
      assert.match(
        file,
        /^\/usr\/share\/nginx\/html\/assets\/[A-Za-z0-9_.-]+\.js$/,
      );
      const asset = await fetch(
        dashboard + file.replace("/usr/share/nginx/html", ""),
        { signal: AbortSignal.timeout(5000) },
      );
      assert.equal(asset.status, 200);
      assert.ok(
        (await asset.text()).includes("Certificate distribution"),
        "Served production JS must include the independent consumer matrix",
      );
    }
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
        ...(variant === "cloud" ? ["private_rejection_before_plan"] : []),
        ...(variant === "enterprise"
          ? ["base_certops_without_compliance_license"]
          : []),
        ...(process.argv.includes("--dashboard")
          ? ["served_dashboard_includes_consumer_matrix"]
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
