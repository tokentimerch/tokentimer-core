"use strict";
// Offline safety/contract tests, not Microsoft Azure qualification evidence.
const test = require("node:test"),
  assert = require("node:assert/strict");
const fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os");
const { spawnSync } = require("node:child_process");
const yaml = require("node:module").createRequire(
  require.resolve("mocha/package.json"),
)("js-yaml");
const subject = require("../infra/certops-azure-keyvault/policy");
const lab = require("../infra/certops-azure-keyvault/lab");
const scope = require("./certops-azure-scope-policy");
const reports = require("./certops-azure-keyvault-report");
const io = require("../tests/e2e/helpers/azure-keyvault-live-io.cjs");
const env = () => ({
  GITHUB_ACTIONS: "true",
  GITHUB_REPOSITORY: subject.REPOSITORY,
  GITHUB_REF: "refs/heads/main",
  GITHUB_SHA: "a".repeat(40),
  GITHUB_EVENT_NAME: "workflow_dispatch",
  GITHUB_RUN_ID: "12345678",
  GITHUB_RUN_ATTEMPT: "1",
  CERTOPS_AZURE_KEYVAULT_LAB_ENABLED: "true",
  LAB_LOCATION: "swedencentral",
  ...Object.fromEntries(
    [
      "AZURE_CLIENT_ID",
      "AZURE_TENANT_ID",
      "AZURE_SUBSCRIPTION_ID",
      "AZURE_KV_ISSUER_ROLE_ID",
      "AZURE_KV_ATTRIBUTES_ROLE_ID",
    ].map((key, i) => [key, `${i + 1}0000000-0000-4000-8000-000000000000`]),
  ),
});
const plan = () => subject.plan(env(), Date.now() - 60000, "test-nonce");
test("OIDC assertion accepts main only and rejects altered issuer, audience, subject, ref and SHA without writing credentials", async (t) => {
  const e = {
    ...env(),
    ACTIONS_ID_TOKEN_REQUEST_URL:
      "https://fixture.actions.githubusercontent.com/token",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "synthetic-request-token",
  };
  const original = {
    iss: "https://token.actions.githubusercontent.com",
    aud: "api://AzureADTokenExchange",
    sub: `repo:${subject.REPOSITORY}:environment:${subject.LAB_ENV}`,
    ref: e.GITHUB_REF,
    sha: e.GITHUB_SHA,
    exp: Math.floor(Date.now() / 1000) + 300,
  };
  let claims = { ...original };
  let requests = 0;
  const writes = [];
  t.mock.method(global, "fetch", async () => {
    requests++;
    return {
      status: 200,
      json: async () => ({
        value: `synthetic.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.signature`,
      }),
    };
  });
  t.mock.method(process.stdout, "write", () => true);
  t.mock.method(fs, "writeFileSync", (...args) => writes.push(args));
  t.mock.method(fs, "chmodSync", () => {});
  await io.assertion("synthetic-root", e);
  assert.equal(writes.length, 1);
  assert.equal(writes[0][2].mode, 0o600);
  for (const patch of [
    { ref: "refs/heads/feat/certops-distribution-extensions" },
    { ref: "refs/heads/other" },
    { ref: "refs/tags/main" },
    { sha: "b".repeat(40) },
    { iss: "https://foreign.test" },
    { aud: "foreign-audience" },
    { sub: `repo:${subject.REPOSITORY}:environment:certops-adcs-lab` },
  ]) {
    claims = { ...original, ...patch };
    await assert.rejects(io.assertion("synthetic-root", e), {
      code: "AZURE_KV_GITHUB_OIDC_CONTEXT_DENIED",
    });
  }
  claims = { ...original };
  const fetched = requests;
  for (const patch of [
    { GITHUB_REF: "refs/heads/feat/certops-distribution-extensions" },
    { GITHUB_REF: "refs/tags/main" },
    { GITHUB_EVENT_NAME: "pull_request" },
    { GITHUB_EVENT_NAME: "push" },
    { GITHUB_REPOSITORY: "foreign/core" },
  ])
    await assert.rejects(io.assertion("synthetic-root", { ...e, ...patch }), {
      code: "AZURE_KV_TRUSTED_MAIN_REQUIRED",
    });
  assert.equal(
    requests,
    fetched,
    "untrusted context must not fetch an assertion",
  );
  assert.equal(
    writes.length,
    1,
    "denied contexts must never write assertion files",
  );
});
const group = (p) => ({
  name: p.group,
  id: lab.groupId(p),
  tags: { ...p.tags },
});
const inventory = (p) => [
  {
    type: "Microsoft.KeyVault/vaults",
    name: p.vault,
    id: lab.vaultId(p),
    tags: p.tags,
  },
  ...Object.values(p.identities).map((row) => ({
    type: "Microsoft.ManagedIdentity/userAssignedIdentities",
    name: row.name,
    id: `${lab.groupId(p)}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/${row.name}`,
    tags: p.tags,
  })),
];
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tt-kvqual-policy-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}
function workflow(name) {
  return yaml.load(
    fs.readFileSync(path.join(__dirname, "../.github/workflows", name), "utf8"),
  );
}

test("permanent janitor preserves bootstrap protections using current main helpers and canonical private cleanup", () => {
  const name = "certops-azure-keyvault-janitor.yml",
    w = workflow(name);
  assert.deepEqual(scope.validate(name, w), []);
  assert.doesNotMatch(JSON.stringify(w), /LAB_ENABLED|sparse-checkout/);
  for (const mutate of [
    (w) => {
      w.jobs.cleanup.if =
        "github.ref == 'refs/heads/feat/certops-distribution-extensions'";
    },
    (w) => {
      w.jobs.cleanup.environment = subject.LAB_ENV;
    },
    (w) => {
      w.jobs.cleanup.env.AZURE_CLIENT_SECRET = "unexpected";
    },
    (w) => {
      w.on.push = {};
    },
    (w) => {
      delete w.on.schedule;
    },
    (w) => {
      w.on.schedule = [{ cron: "* * * * *" }];
    },
    (w) => {
      w.on.workflow_dispatch = { inputs: { ref: { type: "string" } } };
    },
    (w) => {
      w.jobs.cleanup.steps[0].with.ref = "b".repeat(40);
    },
    (w) => {
      w.jobs.cleanup.steps[0].with.repository = "foreign/core";
    },
    (w) => {
      w.jobs.cleanup.steps[3].run =
        "node infra/certops-azure-keyvault/lab.js provision";
    },
    (w) => {
      w.jobs.cleanup.steps[3].run = "az group delete --name production";
    },
    (w) => {
      w.jobs.cleanup.steps[2].if = "false";
    },
    (w) => {
      w.jobs.cleanup.steps[3].if = "false";
    },
    (w) => {
      w.jobs.cleanup.steps[4].if = "success()";
    },
    (w) => {
      w.jobs.cleanup.steps.push({ run: "az keyvault secret show" });
    },
    (w) => {
      w.jobs.cleanup["continue-on-error"] = true;
    },
    (w) => {
      w.jobs.cleanup.permissions.contents = "write";
    },
    (w) => {
      w.jobs.cleanup.env.AZURE_CLIENT_ID = "${{ vars.FOREIGN_CLIENT_ID }}";
    },
    (w) => {
      w.jobs.cleanup.env.CERTOPS_AZURE_KEYVAULT_LAB_ENABLED =
        "${{ vars.CERTOPS_AZURE_KEYVAULT_LAB_ENABLED }}";
    },
  ]) {
    const bad = structuredClone(w);
    mutate(bad);
    assert.ok(scope.validate(name, bad).length, mutate.toString());
  }
});

test("qualification rejects former feature-branch conditions, PR events and tags before credentials", () => {
  const name = "certops-azure-keyvault-qualification.yml",
    w = workflow(name);
  assert.deepEqual(scope.validate(name, w), []);
  for (const mutate of [
    (w) => {
      w.jobs.lab.if +=
        " || github.ref == 'refs/heads/feat/certops-distribution-extensions'";
    },
    (w) => {
      w.jobs.lab.if = "github.ref == 'refs/tags/main'";
    },
    (w) => {
      w.on.pull_request = {};
    },
    (w) => {
      w.on.pull_request_target = {};
    },
    (w) => {
      w.jobs.preflight.steps[0].run = w.jobs.preflight.steps[0].run.replace(
        'test "$GITHUB_REF" = refs/heads/main',
        "true",
      );
    },
  ]) {
    const bad = structuredClone(w);
    mutate(bad);
    assert.ok(scope.validate(name, bad).length, mutate.toString());
  }
});

test("janitor canonical scrub works from a clean checkout without installed dependencies", (t) => {
  const root = fixture(t),
    checkout = path.join(root, "checkout"),
    runner = path.join(root, "runner");
  fs.mkdirSync(runner);
  for (const file of [
    "tests/e2e/azure-keyvault-real.cjs",
    "tests/e2e/helpers/azure-keyvault-live-io.cjs",
    "infra/certops-azure-keyvault/policy.js",
    "infra/certops-azure-keyvault/lab.js",
    "scripts/certops-agent-package.js",
    "scripts/certops-azure-keyvault-report.js",
  ]) {
    const target = path.join(checkout, file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(path.resolve(__dirname, "..", file), target);
  }
  const staging = lab.privateRoot({ ...env(), RUNNER_TEMP: runner });
  fs.writeFileSync(path.join(staging, "owned-cache"), "synthetic-cache");
  const childEnv = { ...env(), RUNNER_TEMP: runner };
  delete childEnv.NODE_TEST_CONTEXT;
  const child = spawnSync(
    process.execPath,
    ["tests/e2e/azure-keyvault-real.cjs", "scrub"],
    {
      cwd: checkout,
      env: childEnv,
      encoding: "utf8",
      timeout: 10000,
      windowsHide: true,
    },
  );
  assert.equal(child.status, 0, child.stderr);
  assert.equal(fs.existsSync(staging), false);
  assert.equal(fs.existsSync(runner), true);
});

test("Key Vault provisioning rejects every untrusted ref, event, missing opt-in and invalid configuration", () => {
  for (const patch of [
    { GITHUB_REF: "refs/heads/feature" },
    { GITHUB_REF: "refs/heads/feat/certops-distribution-extensions" },
    { GITHUB_REF: "refs/tags/main" },
    { GITHUB_EVENT_NAME: "schedule" },
    { GITHUB_EVENT_NAME: "pull_request_target" },
    { GITHUB_REPOSITORY: "foreign/core" },
    { GITHUB_ACTIONS: "false" },
    { CERTOPS_AZURE_KEYVAULT_LAB_ENABLED: "" },
    { AZURE_CLIENT_ID: "client-secret" },
    { GITHUB_RUN_ID: "../adcs" },
    { LAB_LOCATION: "unexpected" },
  ])
    assert.throws(() => subject.plan({ ...env(), ...patch }));
  const p = plan();
  assert.equal(p.tags.purpose, subject.PURPOSE);
  assert.match(p.vault, /^ttkv[a-f0-9]{20}$/);
  assert.equal(
    Date.parse(p.tags.expiresAt) - Date.parse(p.tags.createdAt),
    7200000,
  );
  assert.notEqual(
    subject.plan(env()).vault,
    subject.plan(env()).vault,
    "soft-deleted names are never reused on retry",
  );
});
test("cleanup refuses AD CS, production, wrong subscription, altered ownership or invalid TTL", () => {
  const p = plan(),
    original = group(p);
  subject.ownedGroup(original, { subscriptionId: p.subscriptionId });
  for (const mutate of [
    (g) => {
      g.name = "tt-adcs-production";
    },
    (g) => {
      g.id = g.id.replace(p.subscriptionId, "other");
    },
    (g) => {
      g.tags.purpose = "certops-adcs";
    },
    (g) => {
      g.tags.repository = "foreign/core";
    },
    (g) => {
      g.tags.runId = "9999";
    },
    (g) => {
      g.tags.expiresAt = new Date(Date.now() + 86400000).toISOString();
    },
    (g) => {
      g.tags.vaultName = "production";
    },
  ]) {
    const bad = structuredClone(original);
    mutate(bad);
    assert.throws(() =>
      subject.ownedGroup(bad, { subscriptionId: p.subscriptionId }),
    );
  }
  assert.throws(() =>
    subject.ownedGroup(original, {
      subscriptionId: p.subscriptionId,
      expired: true,
    }),
  );
  subject.ownedGroup(original, {
    subscriptionId: p.subscriptionId,
    now: Date.parse(p.tags.expiresAt) + 1,
    expired: true,
  });
  assert.throws(() =>
    subject.ownedGroup(original, {
      subscriptionId: p.subscriptionId,
      runId: "9999",
      attempt: "1",
    }),
  );
});
test("complete cleanup inventory accepts exact owned resources and only their known FIC children", () => {
  const p = plan(),
    rows = inventory(p);
  subject.ownedResources(rows, p);
  const parent = rows[1],
    child = {
      type: parent.type + "/federatedIdentityCredentials",
      name: parent.name + "/github",
      id: parent.id + "/federatedIdentityCredentials/github",
    };
  subject.ownedResources([...rows, child], p);
  for (const bad of [
    { ...rows[0], tags: {} },
    { ...rows[0], name: "production-vault" },
    { ...parent, id: parent.id + "-foreign" },
    { ...child, name: parent.name + "/foreign" },
    { ...child, id: child.id + "-foreign" },
    { name: "vm", type: "Microsoft.Compute/virtualMachines" },
  ])
    assert.throws(() => subject.ownedResources([...rows, bad], p));
  assert.throws(() => subject.ownedResources([child], p));
  const changed = structuredClone(p);
  changed.identities.issuer.name = "foreign-identity";
  assert.throws(() => subject.ownedResources(rows, changed));
});
test("role definitions have exact read/write or read-only rights and no delete, purge, wildcard or ARM permissions", () => {
  for (const kind of ["issuer", "consumer", "attributes"]) {
    const role = {
      properties: {
        permissions: [
          {
            actions: [],
            notActions: [],
            dataActions: subject.ROLE_ACTIONS[kind],
            notDataActions: [],
          },
        ],
      },
    };
    subject.roleDefinition(role, kind);
    for (const patch of [
      { actions: ["*"] },
      { dataActions: ["Microsoft.KeyVault/vaults/secrets/*"] },
      {
        dataActions: [
          ...subject.ROLE_ACTIONS[kind],
          "Microsoft.KeyVault/vaults/secrets/delete",
        ],
      },
      { notDataActions: ["*"] },
    ]) {
      const bad = structuredClone(role);
      Object.assign(bad.properties.permissions[0], patch);
      assert.throws(() => subject.roleDefinition(bad, kind));
    }
  }
  assert.equal(
    subject.allowedPermission(
      [{ actions: ["Microsoft.Authorization/*"], notActions: ["*/delete"] }],
      "Microsoft.Authorization/roleAssignments/write",
    ),
    true,
  );
  assert.equal(
    subject.allowedPermission(
      [{ actions: ["*"], notActions: ["*/delete"] }],
      "Microsoft.Authorization/roleAssignments/delete",
    ),
    false,
  );
  assert.equal(
    subject.allowedPermission(
      [{ actions: ["Microsoft.KeyVault/vaults/read"] }],
      "Microsoft.Authorization/roleAssignments/write",
    ),
    false,
  );
});
test("protected environments require main only, independent approval and separate unattended cleanup", () => {
  const branches = { branch_policies: [{ name: "main", type: "branch" }] };
  const metadata = {
    name: subject.LAB_ENV,
    deployment_branch_policy: {
      custom_branch_policies: true,
      protected_branches: false,
    },
    protection_rules: [
      {
        type: "required_reviewers",
        prevent_self_review: true,
        reviewers: [{ reviewer: { id: 1 } }],
      },
    ],
  };
  subject.requireEnvironment(metadata, branches, subject.LAB_ENV);
  for (const rules of [
    [{ name: "feat/certops-distribution-extensions", type: "branch" }],
    [
      ...branches.branch_policies,
      { name: "feat/certops-distribution-extensions", type: "branch" },
    ],
  ])
    for (const name of [subject.LAB_ENV, subject.CLEANUP_ENV]) {
      assert.throws(
        () =>
          subject.requireEnvironment(
            {
              ...metadata,
              name,
              protection_rules:
                name === subject.LAB_ENV ? metadata.protection_rules : [],
            },
            { branch_policies: rules },
            name,
          ),
        { code: "AZURE_KV_ENVIRONMENT_MAIN_ONLY_REQUIRED" },
      );
    }
  for (const mutate of [
    (m) => {
      m.protection_rules = [];
    },
    (m) => {
      m.protection_rules[0].prevent_self_review = false;
    },
    (m) => {
      m.deployment_branch_policy.custom_branch_policies = false;
    },
  ]) {
    const bad = structuredClone(metadata);
    mutate(bad);
    assert.throws(() =>
      subject.requireEnvironment(bad, branches, subject.LAB_ENV),
    );
  }
  assert.throws(() =>
    subject.requireEnvironment(
      metadata,
      { branch_policies: [{ name: "*", type: "branch" }] },
      subject.LAB_ENV,
    ),
  );
  assert.throws(() =>
    subject.requireEnvironment(
      metadata,
      { branch_policies: [{ name: "main", type: "tag" }] },
      subject.LAB_ENV,
    ),
  );
  const cleanup = {
    ...metadata,
    name: subject.CLEANUP_ENV,
    protection_rules: [],
  };
  subject.requireEnvironment(cleanup, branches, subject.CLEANUP_ENV);
  assert.throws(() =>
    subject.requireEnvironment(
      { ...metadata, name: subject.CLEANUP_ENV },
      branches,
      subject.CLEANUP_ENV,
    ),
  );
});
test("janitor verifies actual GitHub owner workflow, source and manual main run", () => {
  const p = plan(),
    run = {
      id: Number(p.tags.runId),
      head_sha: p.tags.sourceSha,
      event: "workflow_dispatch",
      head_branch: "main",
      path: subject.WORKFLOW,
      run_attempt: 1,
      created_at: p.tags.createdAt,
    };
  subject.verifyRun(run, p.tags);
  for (const patch of [
    { event: "pull_request" },
    { head_branch: "feature" },
    { head_branch: "feat/certops-distribution-extensions" },
    { head_sha: "b".repeat(40) },
    { path: ".github/workflows/certops-enterprise-adcs-qualification.yml" },
    { id: 999 },
    { run_attempt: 0 },
  ])
    assert.throws(() => subject.verifyRun({ ...run, ...patch }, p.tags));
});
test("ARM absence is explicit; subscription/access failures never become successful cleanup", (t) => {
  const cp = require("node:child_process");
  const p = plan(),
    marker = "SENSITIVE_RESPONSE_MUST_NOT_ESCAPE";
  const mocked = t.mock.method(cp, "spawnSync", () => ({
    status: 1,
    stderr: `(ResourceGroupNotFound) ${marker}`,
  }));
  assert.equal(
    lab.arm("GET", lab.groupId(p), undefined, undefined, true),
    null,
  );
  mocked.mock.mockImplementation(() => ({
    status: 1,
    stderr: `(SubscriptionNotFound) ${marker}`,
  }));
  assert.throws(
    () => lab.arm("GET", lab.groupId(p), undefined, undefined, true),
    (error) =>
      error.code?.startsWith("AZURE_KV_ARM_REQUIRED_") &&
      !error.message.includes(marker),
  );
  assert.throws(() =>
    lab.arm("DELETE", "https://foreign/subscriptions/unsafe"),
  );
});
test("missing permission introspection names its actual minimum scope before any Azure mutation", async (t) => {
  const cp = require("node:child_process"),
    e = { ...env(), RUNNER_TEMP: fixture(t) },
    mutations = [];
  t.mock.method(cp, "spawnSync", (_file, args) => {
    if (args[0] === "account")
      return { status: 0, stdout: e.AZURE_SUBSCRIPTION_ID };
    if (args[args.indexOf("--method") + 1] !== "GET") mutations.push(args);
    return {
      status: 1,
      stderr: "(AuthorizationFailed) sensitive server details",
    };
  });
  await assert.rejects(lab.provision(e), {
    code: "AZURE_KV_ARM_REQUIRED_Microsoft_Authorization_permissions_read_AT_LAB_SUBSCRIPTION",
  });
  assert.equal(mutations.length, 0);
});
test("actual cleanup entry point authorizes deletion only after live ownership/run/inventory checks (offline ARM)", async (t) => {
  const cp = require("node:child_process"),
    p = plan(),
    e = env();
  const run = {
    id: Number(p.tags.runId),
    head_sha: p.tags.sourceSha,
    event: "workflow_dispatch",
    head_branch: "main",
    path: subject.WORKFLOW,
    run_attempt: 1,
    created_at: p.tags.createdAt,
  };
  let current = group(p),
    resources = inventory(p),
    partial = false,
    deleted = false;
  const deletes = [];
  t.mock.method(global, "fetch", async (url) => {
    assert.match(
      url,
      /^https:\/\/api\.github\.com\/repos\/tokentimerch\/tokentimer-core\/actions\/runs\//,
    );
    return { ok: true, json: async () => run };
  });
  t.mock.method(cp, "spawnSync", (_file, args) => {
    const method = args[args.indexOf("--method") + 1],
      url = args[args.indexOf("--uri") + 1];
    if (method === "DELETE") {
      deletes.push(url);
      deleted = true;
      return { status: 0, stdout: "{}" };
    }
    if (deleted) return { status: 1, stderr: "(ResourceGroupNotFound)" };
    return {
      status: 0,
      stdout: JSON.stringify(
        url.includes("/resources?")
          ? { value: resources, ...(partial ? { nextLink: "unread" } : {}) }
          : current,
      ),
    };
  });
  current.tags.purpose = "certops-adcs";
  await assert.rejects(lab.remove(p, e), {
    code: "AZURE_KV_FOREIGN_GROUP_DENIED",
  });
  assert.equal(deletes.length, 0);
  current = group(p);
  resources.push({
    type: "Microsoft.Compute/virtualMachines",
    name: "foreign",
  });
  await assert.rejects(lab.remove(p, e), {
    code: "AZURE_KV_FOREIGN_RESOURCE_DENIED",
  });
  assert.equal(deletes.length, 0);
  resources = inventory(p);
  partial = true;
  await assert.rejects(lab.remove(p, e), {
    code: "AZURE_KV_PARTIAL_RESOURCE_INVENTORY_DENIED",
  });
  assert.equal(deletes.length, 0);
  partial = false;
  await lab.remove(p, e);
  assert.deepEqual(deletes, [
    "https://management.azure.com" + lab.groupId(p) + "?api-version=2022-09-01",
  ]);
});
test("private state rejects path escapes, links through files and unfinished writes", (t) => {
  const temporary = fixture(t),
    e = { ...env(), RUNNER_TEMP: temporary };
  const root = lab.privateRoot(e);
  assert.equal(path.dirname(root), fs.realpathSync(temporary));
  assert.throws(() => lab.privateRoot({ ...e, GITHUB_RUN_ID: "../adcs" }));
  const file = path.join(root, "state.json");
  lab.save(file, { safe: true });
  assert.deepEqual(lab.load(file), { safe: true });
  fs.writeFileSync(file + ".new", "unfinished");
  assert.throws(() => lab.save(file, { overwrite: true }));
  assert.deepEqual(lab.load(file), { safe: true });
});
test("Azure workflow policy rejects privilege, ref, input, skip and artifact regressions", () => {
  const name = "certops-azure-keyvault-qualification.yml",
    original = workflow(name);
  assert.deepEqual(scope.validate(name, original), []);
  assert.deepEqual(
    require("./certops-workflow-security").validateWorkflow(original, name),
    [],
  );
  const mutations = [
    (w) => {
      w.on.push = {};
    },
    (w) => {
      w.jobs.lab.if = "always()";
    },
    (w) => {
      w.jobs.lab.environment = "certops-adcs-lab";
    },
    (w) => {
      w.jobs.lab.needs = [];
    },
    (w) => {
      w.permissions["id-token"] = "write";
    },
    (w) => {
      w.jobs.preflight.permissions.contents = "write";
    },
    (w) => {
      w.env = { AZURE_CLIENT_ID: "inherited" };
    },
    (w) => {
      w.jobs.preflight.environment = "certops-azure-keyvault-lab";
    },
    (w) => {
      w.jobs.lab.permissions.contents = "write";
    },
    (w) => {
      w.jobs.lab.env.AZURE_CLIENT_SECRET = "hidden";
    },
    (w) => {
      w.jobs.lab.steps[0].with.ref = "feature";
    },
    (w) => {
      w.jobs.lab.steps[0].uses = "actions/checkout@main";
    },
    (w) => {
      w.jobs.lab.env.TT_REAL_AZURE = "0";
    },
    (w) => {
      w.jobs.lab["continue-on-error"] = true;
    },
    (w) => {
      w.jobs.lab.steps.find((s) => s.run?.endsWith("lab.js cleanup")).if =
        "success()";
    },
    (w) => {
      w.jobs.lab.steps.find((s) => s.run?.endsWith("real.cjs run")).if =
        "false";
    },
    (w) => {
      w.jobs.lab.steps.find((s) => s.id === "evidence-check")[
        "continue-on-error"
      ] = true;
    },
    (w) => {
      w.jobs.lab.steps.find((s) =>
        s.uses?.startsWith("actions/upload-artifact@"),
      ).if = "always()";
    },
    (w) => {
      w.jobs.lab.steps.find((s) =>
        s.uses?.startsWith("actions/upload-artifact@"),
      ).with.path = "**/*";
    },
    (w) => {
      w.on.workflow_dispatch.inputs.ref = { type: "string" };
    },
    (w) => {
      w.jobs.lab["timeout-minutes"] = 300;
    },
  ];
  for (const mutate of mutations) {
    const bad = structuredClone(original);
    mutate(bad);
    assert.ok(scope.validate(name, bad).length, mutate.toString());
  }
  const cleanupName = "certops-azure-keyvault-janitor.yml",
    cleanup = workflow(cleanupName);
  assert.deepEqual(scope.validate(cleanupName, cleanup), []);
  for (const run of [
    "node infra/certops-azure-keyvault/lab.js provision",
    "az rest --method PUT --url unsafe",
    "az group delete --name production",
  ]) {
    const bad = structuredClone(cleanup);
    bad.jobs.cleanup.steps.push({ run });
    assert.ok(scope.validate(cleanupName, bad).length);
  }
  for (const run of [
    "node infra/certops-azure-keyvault/lab.js provision",
    "az keyvault secret show",
    "az identity create",
  ])
    assert.ok(
      scope.validate("unreviewed.yml", {
        jobs: { hidden: { steps: [{ run }] } },
      }).length,
    );
});
test("closed evidence schema rejects secrets, fabricated success, omissions and broad artifacts", (t) => {
  const report = reports.emptyReport("a".repeat(40), "b".repeat(64));
  const verify = (r) => reports.verify(r, { sourceSha: report.sourceSha });
  reports.verify(report, { requirePassed: false, sourceSha: report.sourceSha });
  assert.throws(() => verify(report));
  report.status = "passed";
  report.databaseCleanup = "completed";
  report.scenarios.forEach((row) => {
    row.status = "passed";
  });
  report.counts = reports.counts(report.scenarios);
  Object.assign(report.facts, {
    ambiguousPutAttempts: 1,
    recoveredProviderVersions: 1,
    acceptedProviderPins: 2,
    azure401Responses: 1,
    azure403Responses: 4,
    entraTokenExchanges: 4,
    exactPackageVerified: true,
  });
  verify(report);
  for (const mutate of [
    (r) => {
      r.bundle = "PRIVATE KEY";
    },
    (r) => {
      r.scenarios[0].details = "Bearer credential";
    },
    (r) => {
      r.unqualified = [];
    },
    (r) => {
      r.productionQualified = true;
    },
    (r) => {
      r.counts.skipped = 1;
    },
    (r) => {
      r.scenarios.pop();
    },
    (r) => {
      r.facts.recoveredProviderVersions = 2;
    },
    (r) => {
      r.facts.token = "sensitive";
    },
    (r) => {
      r.scenarios[0].status = "pending";
    },
  ]) {
    const bad = structuredClone(report);
    mutate(bad);
    assert.throws(() => verify(bad));
  }
  const root = fixture(t);
  fs.writeFileSync(
    path.join(root, "azure-keyvault-evidence.json"),
    JSON.stringify(report),
  );
  fs.writeFileSync(
    path.join(root, "azure-keyvault-cleanup.json"),
    JSON.stringify({
      schemaVersion: 1,
      sourceSha: report.sourceSha,
      cleanup: "completed",
      purgeRequested: false,
    }),
  );
  reports.artifactCheck(root, { sourceSha: report.sourceSha });
  fs.writeFileSync(path.join(root, "credentials.json"), "secret");
  assert.throws(() =>
    reports.artifactCheck(root, { sourceSha: report.sourceSha }),
  );
});
test("mandatory campaign and baseline fail closed outside a trusted configured run", () => {
  for (const [args, extra] of [
    [["tests/e2e/azure-keyvault-real.cjs", "run"], {}],
    [
      ["--test", "tests/e2e/material-providers-real.test.js"],
      { TT_AZURE_QUALIFICATION_REQUIRED: "1", TT_REAL_AZURE: "0" },
    ],
  ]) {
    const childEnv = { ...process.env, GITHUB_ACTIONS: "false", ...extra };
    delete childEnv.NODE_TEST_CONTEXT;
    const result = spawnSync(process.execPath, args, {
      cwd: path.resolve(__dirname, ".."),
      encoding: "utf8",
      timeout: 30000,
      env: childEnv,
    });
    assert.equal(result.status, 1);
    assert.match(result.stdout + result.stderr, /AZURE_KV_/);
    assert.doesNotMatch(result.stdout + result.stderr, /BEGIN.*PRIVATE KEY/);
  }
  const qualified =
    require("../packages/agent/src/capabilities/qualified-capabilities.json").qualified;
  for (const capability of [
    "material-store-azure-key-vault-v1",
    "windows-material-iis-v1",
  ])
    assert.equal(qualified.includes(capability), false);
});
test("offline fault-boundary contract preserves TLS and only loses successful owned responses", async (t) => {
  const https = require("node:https"),
    { EventEmitter } = require("node:events"),
    { PassThrough } = require("node:stream");
  const actual = https.request,
    forwarded = [];
  // Explicit simulated transport for this unit test only; the live entry point
  // installs the same boundary over native HTTPS to Microsoft Azure.
  https.request = (url, options, callback) => {
    forwarded.push({ host: new URL(url).hostname, options });
    const req = new EventEmitter();
    req.write = () => {};
    req.destroy = (error) => {
      if (error) req.emit("error", error);
      req.emit("close");
    };
    req.end = () =>
      process.nextTick(() => {
        const response = new PassThrough();
        response.statusCode = options.headers.Authorization?.includes("invalid")
          ? 401
          : 200;
        response.on("end", () => req.emit("close"));
        callback(response);
        response.end('{"actualUpstream":true}');
      });
    return req;
  };
  const boundary = new io.FaultBoundary(
    "ttkv" + "a".repeat(20) + ".vault.azure.net",
  ).install();
  t.after(() => {
    boundary.restore();
    https.request = actual;
  });
  const {
    requestJson,
  } = require("../packages/agent/src/material-store/transport");
  const url = new URL(`https://${boundary.host}/secrets/tt-${"b".repeat(64)}`);
  assert.equal((await requestJson(url)).status, 200);
  for (const kind of ["ambiguous-put", "reset-get", "timeout-get"]) {
    const fault = boundary.set(kind, url.pathname);
    await assert.rejects(
      requestJson(url, { method: kind === "ambiguous-put" ? "PUT" : "GET" }),
      { code: "material_store_unavailable" },
    );
    assert.equal(fault.used, true);
    if (kind === "ambiguous-put") assert.equal(fault.committed, true);
    boundary.clear();
  }
  boundary.set("real-401", url.pathname);
  assert.equal((await requestJson(url)).status, 401);
  assert.equal(
    (await requestJson(new URL("https://example.test/unchanged"))).json
      .actualUpstream,
    true,
  );
  assert.ok(forwarded.every((row) => row.options.rejectUnauthorized === true));
  assert.equal(boundary.puts.get(url.pathname), 1);
});
