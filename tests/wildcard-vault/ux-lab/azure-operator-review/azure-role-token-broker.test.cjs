"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { _offline: { broker, validateAssertion, requestEntra, roleTrust } } = require("./azure-role-token-broker.cjs");

const binding = {
  repositoryId: "456", ownerId: "123", runId: "789", sourceSha: "a".repeat(40), subjectFormat: "legacy",
  workflowRef: "tokentimerch/tokentimer-core/.github/workflows/certops-azure-operator-qualification.yml@refs/heads/main",
};
const epoch = 1_790_000_000_000;
const tenant = "00000000-0000-0000-0000-000000000000";
const clients = { issuer: "11111111-1111-1111-1111-111111111111", consumer: "22222222-2222-2222-2222-222222222222" };
const jwt = (role, jti, now = epoch, changes = {}, run = binding) => {
  const { environment, subject } = roleTrust(run, role);
  const claims = {
    iss: "https://token.actions.githubusercontent.com", aud: "api://AzureADTokenExchange", sub: subject, environment,
    repository: "tokentimerch/tokentimer-core", repository_id: run.repositoryId, repository_owner_id: run.ownerId,
    workflow_ref: run.workflowRef, event_name: "workflow_dispatch", ref: "refs/heads/main", sha: run.sourceSha,
    run_id: run.runId, run_attempt: "1", jti, iat: now / 1000, exp: now / 1000 + 300, ...changes,
  };
  return "c3ludGhldGlj." + Buffer.from(JSON.stringify(claims)).toString("base64url") + ".Zml4dHVyZQ";
};

function fixture() {
  const directories = ["/projection", "/issuer", "/consumer"];
  const files = new Map(directories.map((name, index) => [name, {
    uid: index ? 10000 + index : 0, dev: 1, ino: index + 1, mode: 0o700,
    isDirectory: () => true, isSymbolicLink: () => false,
  }]));
  files.set("/", { ...files.get("/projection"), ino: 0, mode: 0o755 });
  const values = new Map(), descriptors = new Map(), timers = new Map(), exchanges = [];
  let time = epoch, id = 0, deniedCode = 700213;
  const project = (role, jti) => values.set(`/projection/${role}.jwt`, jwt(role, jti, time));
  const fileStat = (uid, size) => ({ uid, size, nlink: 1, mode: 0o600, isFile: () => true, isSymbolicLink: () => false });
  for (const role of ["issuer", "consumer"]) project(role, role + "-1");
  const io = {
    lstatSync: key => files.get(key), statSync: key => files.get(key), realpathSync: key => key,
    openSync(file) { const raw = Buffer.from(values.get(file)); const fd = ++id;
      descriptors.set(fd, { ...fileStat(0, raw.length), raw }); return fd; },
    closeSync: fd => descriptors.delete(fd),
    fstatSync: fd => descriptors.get(fd),
    readSync(fd, target) { return descriptors.get(fd).raw.copy(target); },
    fchownSync(fd, uid) { descriptors.get(fd).uid = uid; },
    fchmodSync(fd, mode) { descriptors.get(fd).mode = mode; },
  };
  const subject = broker({ binding, projectionRoot: "/projection", deadlineMs: epoch + 3_600_000,
    issuer: { directory: "/issuer", tenantId: tenant, clientId: clients.issuer },
    consumer: { directory: "/consumer", tenantId: tenant, clientId: clients.consumer } }, {
    io, owner: 0, platform: "linux", now: () => time,
    setTimeout(fn, delay) { const timer = ++id; timers.set(timer, { fn, at: time + delay }); return timer; },
    clearTimeout: timer => timers.delete(timer),
    createSink({ directory, prepareOwner, acquire }) { return { async refresh() {
      const { accessToken, expiresOn } = await acquire();
      const fd = ++id; descriptors.set(fd, fileStat(0, 0)); prepareOwner(fd);
      files.set(directory + "/token.json", descriptors.get(fd)); descriptors.delete(fd);
      values.set(directory + "/token.json", accessToken);
      return { expiresOn };
    } }; },
    async request(_url, request) {
      const params = new URLSearchParams(request.body);
      const payload = params.get("client_assertion").split(".")[1];
      const { jti, environment } = JSON.parse(Buffer.from(payload, "base64url"));
      const role = environment.endsWith("-issuer") ? "issuer" : "consumer";
      const own = params.get("client_id") === clients[role];
      exchanges.push({ role, own, jti });
      return own ? { status: 200, json: { access_token: "synthetic_test_" + jti + "_token", expires_in: 600 } }
        : { status: 400, json: { error: "invalid_client", error_codes: [deniedCode] } };
    },
  });
  return { subject, values, files, timers, exchanges, project,
    async advance(ms) {
      time += ms;
      for (const [id, timer] of timers) if (timer.at <= time) { timers.delete(id); timer.fn(); }
      await new Promise(setImmediate);
    },
    setBadCode() { deniedCode = 700016; },
  };
}

test("binds the projected subject to a distinct environment, exact workflow, commit, run and attempt", () => {
  assert.equal(validateAssertion(jwt("issuer", "one"), binding, "issuer", epoch), "one");
  assert.throws(() => validateAssertion(jwt("issuer", "one"), binding, "consumer", epoch), /ASSERTION_REFUSED/);
  for (const changed of [{ exp: epoch / 1000 + 1 }, { run_attempt: "2" }, { run_id: "999" }, { workflow_ref: "foreign" },
    { sha: "b".repeat(40) }, { ref: "refs/heads/topic" }, { aud: "unexpected" }, { repository_id: "999" }])
    assert.throws(() => validateAssertion(jwt("issuer", "one", epoch, changed), binding, "issuer", epoch), /ASSERTION_REFUSED/);
  const immutable = { ...binding, subjectFormat: "immutable" };
  assert.equal(validateAssertion(jwt("consumer", "two", epoch, {}, immutable), immutable, "consumer", epoch), "two");
  assert.throws(() => validateAssertion(jwt("consumer", "two"), immutable, "consumer", epoch), /ASSERTION_REFUSED/);
});

test("observes both cross-role denials before setup and renews each sink off a fresh projection", async () => {
  const { subject, values, project, advance, exchanges, timers } = fixture();
  const starting = subject.start();
  assert.throws(() => subject.refresh("issuer"), /NOT_READY/);
  await starting;
  assert.equal(exchanges.filter(row => !row.own).length, 2);
  assert.equal(exchanges.slice(0, 4).filter(row => !row.own).length, 2);
  assert.equal(values.get("/issuer/token.json"), "synthetic_test_issuer-1_token");
  assert.equal(values.get("/consumer/token.json"), "synthetic_test_consumer-1_token");
  assert.deepEqual(subject.observations().map(row => row.tokenRenewals), [0, 0]);
  await advance(360_000);
  project("issuer", "issuer-2"); project("consumer", "consumer-2");
  await advance(120_000);
  assert.equal(values.get("/issuer/token.json"), "synthetic_test_issuer-2_token");
  assert.equal(values.get("/consumer/token.json"), "synthetic_test_consumer-2_token");
  const facts = subject.observations();
  assert.deepEqual(facts.map(row => row.tokenRenewals), [1, 1]);
  assert.notEqual(facts[0].subjectSha256, facts[1].subjectSha256);
  assert.doesNotMatch(JSON.stringify(facts), /synthetic_test|issuer-2|consumer-2/);
  await subject.stop();
  assert.equal(timers.size, 0);
  assert.equal(subject.signal.aborted, true);
});

test("wrong Entra denial and shared assertion fail closed before writing either sink", async () => {
  const wrong = fixture();
  wrong.setBadCode();
  await assert.rejects(wrong.subject.start(), /ADMISSION_FAILED/);
  assert.equal(wrong.subject.signal.aborted, true);
  assert.equal(wrong.values.has("/issuer/token.json"), false);
  const shared = fixture();
  shared.values.set("/projection/consumer.jwt", shared.values.get("/projection/issuer.jwt"));
  await assert.rejects(shared.subject.start(), /ADMISSION_FAILED/);
  assert.equal(shared.exchanges.length, 0);
  assert.equal(shared.values.has("/consumer/token.json"), false);
});

test("a replaced sink directory aborts broker refresh without exposing credentials", async () => {
  const { subject, files, values, advance, project } = fixture();
  await subject.start();
  await advance(120_000);
  project("issuer", "issuer-2");
  files.set("/issuer", { ...files.get("/issuer"), ino: 99 });
  await assert.rejects(subject.refresh("issuer"), { message: "AZURE_BROKER_REFRESH_FAILED" });
  assert.equal(subject.signal.aborted, true);
  assert.equal(values.get("/issuer/token.json"), "synthetic_test_issuer-1_token");
});

test("Entra transport keeps only the reviewed error shape and refuses oversized or foreign responses", async () => {
  const url = new URL(`https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`);
  const input = { method: "POST", headers: {}, body: "", timeoutMs: 10000, maxBytes: 32768 };
  const result = await requestEntra(url, input, async (_url, options) => {
    assert.equal(options.redirect, "error");
    return Response.json({ error: "invalid_client", error_codes: [700213, 700016],
      error_description: "synthetic diagnostic", access_token: "synthetic secret" }, { status: 400 });
  });
  assert.deepEqual(result, { status: 400, json: { error: "invalid_client", error_codes: [700213] } });
  await assert.rejects(requestEntra(new URL("https://example.test/"), input, () => { throw new Error("unexpected call"); }),
    { message: "AZURE_BROKER_ENTRA_REFUSED" });
  await assert.rejects(requestEntra(url, input, async () => new Response("x".repeat(32769), { status: 400 })),
    { message: "AZURE_BROKER_ENTRA_REFUSED" });
});
