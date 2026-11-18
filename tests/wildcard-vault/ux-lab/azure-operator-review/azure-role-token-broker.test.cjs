"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const { constants, createHash, verify, X509Certificate } = require("node:crypto");
const { existsSync, mkdtempSync, readFileSync, rmSync, rmdirSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join, resolve } = require("node:path");
const { _offline: { broker, validateAssertion, requestEntra, roleTrust, applicationNotFound } } = require("./azure-role-token-broker.cjs");

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

function fixture(certificates) {
  const directories = ["/projection", "/issuer", "/consumer"];
  const files = new Map(directories.map((name, index) => [name, {
    uid: index ? 10000 + index : 0, dev: 1, ino: index + 1, mode: 0o700,
    isDirectory: () => true, isSymbolicLink: () => false,
  }]));
  files.set("/", { ...files.get("/projection"), ino: 0, mode: 0o755 });
  const values = new Map(), descriptors = new Map(), timers = new Map(), exchanges = [];
  const start = certificates ? Date.now() : epoch;
  let time = start, id = 0, deniedCode = certificates ? 700027 : 700213;
  const project = (role, jti) => values.set(`/projection/${role}.jwt`, jwt(role, jti, time));
  const fileStat = (uid, size) => ({ uid, size, nlink: 1, mode: 0o600, isFile: () => true, isSymbolicLink: () => false });
  for (const role of ["issuer", "consumer"]) project(role, role + "-1");
  for (const [role, value] of Object.entries(certificates || {})) {
    values.set("/projection/" + role + ".cert.pem", value.certificatePem);
    values.set("/projection/" + role + ".key.pem", value.privateKeyPem);
  }
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
  const transport = certificates ? { certificateRoot: "/projection" } : { projectionRoot: "/projection" };
  const identity = role => ({ directory: "/" + role, tenantId: tenant, clientId: clients[role],
    certificateSha256: certificates?.[role].certificateSha256 });
  const subject = broker({ binding, ...transport, deadlineMs: start + 3_600_000,
    issuer: identity("issuer"), consumer: identity("consumer") }, {
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
    async request(url, request) {
      const params = new URLSearchParams(request.body);
      const [encodedHeader, payload, signature] = params.get("client_assertion").split(".");
      const { jti, environment, aud, iss, sub, iat, nbf, exp } = JSON.parse(Buffer.from(payload, "base64url"));
      let role;
      if (certificates) {
        const header = JSON.parse(Buffer.from(encodedHeader, "base64url"));
        role = Object.keys(certificates).find(name =>
          Buffer.from(certificates[name].certificateSha256, "hex").toString("base64url") === header["x5t#S256"]);
        assert.ok(role);
        assert.equal(header.alg, "PS256");
        assert.equal(aud, url.href);
        assert.equal(iss, params.get("client_id"));
        assert.equal(sub, iss);
        assert.equal(iat, nbf);
        assert.equal(exp - iat, 300);
        assert.equal(verify("sha256", Buffer.from(encodedHeader + "." + payload), {
          key: new X509Certificate(certificates[role].certificatePem).publicKey,
          padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
        }, Buffer.from(signature, "base64url")), true);
      } else {
        role = environment.endsWith("-issuer") ? "issuer" : "consumer";
      }
      const own = params.get("client_id") === clients[role];
      exchanges.push({ role, own, jti });
      return own ? { status: 200, json: { access_token: "synthetic_test_" + jti + "_token", expires_in: 600 } }
        : { status: certificates ? 401 : 400, json: { error: "invalid_client", error_codes: [deniedCode] } };
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

function makeCertificates(t) {
  let openssl = "openssl";
  if (process.platform === "win32") {
    const gitRoot = execFileSync("git", ["--exec-path"], { encoding: "utf8" }).trim();
    const bundled = resolve(gitRoot, "../../../usr/bin/openssl.exe");
    if (existsSync(bundled)) openssl = bundled;
  }
  const dir = mkdtempSync(join(tmpdir(), "tt-azure-broker-cert-"));
  const files = [];
  t.after(() => {
    for (const file of files) rmSync(file, { force: true });
    rmdirSync(dir);
  });
  function certificate(role, reuseKey = false) {
    const certificatePath = join(dir, role + ".cert.pem");
    const keyPath = join(dir, (reuseKey ? "issuer" : role) + ".key.pem");
    files.push(certificatePath);
    if (!reuseKey) files.push(keyPath);
    const keyArgs = reuseKey ? ["-key", keyPath] : ["-newkey", "rsa:2048", "-nodes", "-keyout", keyPath];
    execFileSync(openssl, ["req", "-x509", "-days", "1", "-subj", "/CN=" + role, "-out", certificatePath,
      ...keyArgs], { stdio: "ignore" });
    const certificatePem = readFileSync(certificatePath, "utf8");
    const privateKeyPem = readFileSync(keyPath, "utf8");
    const certificateSha256 = createHash("sha256").update(new X509Certificate(certificatePem).raw).digest("hex");
    return { certificatePem, privateKeyPem, certificateSha256 };
  }
  return { issuer: certificate("issuer"), consumer: certificate("consumer"),
    sharedKey: () => certificate("second-issuer", true) };
}

test("uses separate certificate claims and proves reciprocal denial before renewing each sink", async t => {
  const { issuer, consumer } = makeCertificates(t);
  const { subject, values, advance, exchanges, timers } = fixture({ issuer, consumer });
  t.after(() => subject.stop());
  await subject.start();
  assert.deepEqual(exchanges.slice(0, 4).map(({ role, own }) => [role, own]),
    [["issuer", true], ["consumer", true], ["issuer", false], ["consumer", false]]);
  assert.equal(new Set(exchanges.map(row => row.jti)).size, 6);
  const first = values.get("/issuer/token.json");
  await advance(480_000);
  assert.notEqual(values.get("/issuer/token.json"), first);
  const rows = subject.observations();
  assert.deepEqual(rows.map(row => row.tokenRenewals), [1, 1]);
  assert.notEqual(rows[0].subjectSha256, rows[1].subjectSha256);
  assert.doesNotMatch(JSON.stringify(rows), /synthetic_test|BEGIN|privateKey|certificatePem/);
  await subject.stop();
  assert.equal(timers.size, 0);
});

test("rejects certificate pin mismatch, a shared key under two certificates, and a wrong Entra rejection", async t => {
  const { issuer, consumer, sharedKey } = makeCertificates(t);
  assert.throws(() => fixture({ issuer, consumer: { ...consumer, certificateSha256: issuer.certificateSha256 } }),
    /CERTIFICATE_CREDENTIAL_REFUSED/);
  assert.throws(() => fixture({ issuer, consumer: sharedKey() }), /SHARED_CERTIFICATE_KEY_REFUSED/);
  const wrong = fixture({ issuer, consumer });
  wrong.setBadCode();
  t.after(() => wrong.subject.stop());
  await assert.rejects(wrong.subject.start(), /ADMISSION_FAILED/);
  assert.equal(wrong.values.has("/issuer/token.json"), false);
  assert.equal(wrong.values.has("/consumer/token.json"), false);
});

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
  const mismatch = await requestEntra(url, input, async () =>
    Response.json({ error: "invalid_client", error_codes: [700027, 700016] }, { status: 401 }));
  assert.deepEqual(mismatch, { status: 401, json: { error: "invalid_client", error_codes: [700027] } });
  const retired = await requestEntra(url, input, async () =>
    Response.json({ error: "invalid_client", error_codes: [700016, 700227] }, { status: 400 }), true);
  assert.deepEqual(retired, { status: 400, json: { error: "invalid_client", error_codes: [700016] } });
  await assert.rejects(requestEntra(new URL("https://example.test/"), input, () => { throw new Error("unexpected call"); }),
    { message: "AZURE_BROKER_ENTRA_REFUSED" });
  await assert.rejects(requestEntra(url, input, async () => new Response("x".repeat(32769), { status: 400 })),
    { message: "AZURE_BROKER_ENTRA_REFUSED" });
});

test("certificate retirement requires the exact Entra application-not-found code on HTTP 400 or 401", async () => {
  const url = new URL("https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token");
  const options = { method: "POST", headers: {}, body: "", timeoutMs: 10000, maxBytes: 32768 };
  const cases = [
    [400, { error: "unauthorized_client", error_codes: [700016] }, true],
    [401, { error_codes: [700016] }, true],
    [400, { error: "invalid_client", error_codes: [700027] }, false],
    [400, { error: "unauthorized_client", error_codes: [700011] }, false],
    [400, { error: "unauthorized_client", error_codes: ["700016"] }, false],
    [400, { error: "unauthorized_client", error_codes: [700016, "invalid"] }, false],
    [403, { error: "unauthorized_client", error_codes: [700016] }, false],
    [200, { error_codes: [700016] }, false],
  ];
  for (const [status, json, expected] of cases) {
    const observed = await requestEntra(url, options, async () =>
      Response.json({ ...json, error_description: "private diagnostic fixture" }, { status }), true);
    assert.equal(applicationNotFound(observed), expected, JSON.stringify({ status, json }));
    assert.doesNotMatch(JSON.stringify(observed), /private diagnostic/);
  }
  await assert.rejects(requestEntra(url, options, async () => Response.json([700016], { status: 400 }), true),
    /AZURE_BROKER_ENTRA_REFUSED/);
});
