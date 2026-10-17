"use strict";
/** Closed-proof and MailHog parsing controls. The test-mode email short-circuit
 * is invoked here and must not count as an SMTP receipt. No native client or CA. */
const assert = require("node:assert/strict");
const test = require("node:test");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const h = require("../tests/e2e/helpers/certops-acme-renewal-alert");
test("original renewal ownership survives missing or same-byte replaced receipts",()=>{
  const root=fs.mkdtempSync(path.resolve(__dirname,"../.build/native-alert-"));
  const marker=path.join(root,".native-renewal-alert-active"),saved=path.join(root,"original");
  try{
    const positive=h.registerOperation(root);positive.release();h.assertCleanupSafe(root);
    const operation=h.registerOperation(root);
    assert.throws(()=>h.assertCleanupSafe(root));
    fs.renameSync(marker,saved);
    assert.throws(()=>h.assertCleanupSafe(root));
    fs.writeFileSync(marker,fs.readFileSync(saved),{flag:"wx",mode:0o600});
    assert.throws(()=>operation.release());
    assert.throws(()=>h.assertCleanupSafe(root));
    // Even restoring a pathname must not erase the original unresolved owner.
    assert.throws(()=>h.assertCleanupSafe(root));
  }finally{for(const file of [marker,saved])fs.rmSync(file,{force:true});fs.rmdirSync(root);}
});
test("native renewal alert proof refuses partial evidence and unsupported claims", () => {
  const proof = { scope: h.SCOPE, jobId: crypto.randomUUID(), claimId: crypto.randomUUID(), certificateId: crypto.randomUUID(), alertId: "17", faultRequestCount: 2, servingFingerprint: Array(32).fill("AB").join(":"), ...Object.fromEntries(h.FLAGS.map(flag => [flag, true])) };
  assert.equal(h.verifyProof(proof), true);
  for (const flag of h.FLAGS) assert.throws(() => h.verifyProof({ ...proof, [flag]: false }));
  for (const delta of [{ extra: true }, { faultRequestCount: 0 }, { alertId: "017" }, { jobId: "not-a-job" }]) assert.throws(() => h.verifyProof({ ...proof, ...delta }));
  for (const source of h.REQUIRED_SOURCES) assert.ok(fs.statSync(path.resolve(__dirname, "..", source)).isFile(), source);
});
test("SMTP receipt requires fresh ID, exact recipient and actual job body", () => {
  const jobId = crypto.randomUUID(), recipient = "native@example.test";
  const row = { ID: "fresh", Content: { Headers: { To: [recipient], Subject: ["Certificate renewal failed"], "Content-Transfer-Encoding": ["quoted-printable"] }, Body: `Renewal job: ${jobId}` } };
  const options = { jobId, recipient, previous: new Set(["old"]) };
  const inbox=message=>({items:[message],total:1,count:1,start:0});
  assert.equal(h.matchingMessages(inbox(row), options).length, 1);
  assert.throws(()=>h.matchingMessages({...inbox(row),total:2},options));
  for (const changed of [{ ...row, ID: "old" }, { ...row, Content: { ...row.Content, Body: crypto.randomUUID() } }, { ...row, Content: { ...row.Content, Headers: { ...row.Content.Headers, To: ["foreign@example.test"] } } }]) assert.equal(h.matchingMessages(inbox(changed), options).length, 0);
  const mime = { ...row, Content: { ...row.Content, Body: "" }, MIME: { Parts: [{ Headers: { "Content-Transfer-Encoding": ["base64"] }, Body: Buffer.from(`Renewal job: ${jobId}`).toString("base64") }] } };
  assert.equal(h.matchingMessages(inbox(mime), options).length, 1);
});
test("SMTP observation endpoint cannot redirect qualification to external hosts", () => {
  assert.equal(h.localEndpoint("http://127.0.0.1:8025").port, "8025");
  for (const value of ["https://127.0.0.1", "http://foreign.example", "http://user:password@localhost", "http://localhost/?token=secret"]) assert.throws(() => h.localEndpoint(value));
});
test("test-mode simulated delivery does not count as the SMTP receipt", () => {
  const jobId = crypto.randomUUID();
  const recipient = "native-sim@example.test";
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "native-renewal-sim-"));
  const out = path.join(directory, "result.json");
  const started = Date.now();
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import { writeFileSync } from "node:fs";
    import { sendEmailNotification } from "./apps/worker/src/notify/email.js";
    const result = await sendEmailNotification({
      to: ${JSON.stringify(recipient)},
      subject: "Certificate renewal failed",
      text: "Renewal job: ${jobId}",
    });
    writeFileSync(process.env.NATIVE_RENEWAL_SIM_OUT, JSON.stringify({ nodeEnv: process.env.NODE_ENV, result }));
    process.exit(0);
  `], {
    cwd: path.resolve(__dirname, ".."),
    env: {
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot,
      PATHEXT: process.env.PATHEXT,
      NODE_ENV: "test",
      SMTP_HOST: "127.0.0.1",
      SMTP_PORT: "9",
      SMTP_SECURE: "false",
      SMTP_REQUIRE_TLS: "false",
      SMTP_USER: "simulated",
      SMTP_PASS: "simulated",
      NATIVE_RENEWAL_SIM_OUT: out,
    },
    encoding: "utf8",
    timeout: 20000,
    windowsHide: true,
  });
  try {
    assert.equal(child.status, 0, child.stderr || child.error?.message);
    assert.ok(Date.now() - started < 15000, "Test-mode email success must return before an SMTP attempt");
    const observed = JSON.parse(fs.readFileSync(out, "utf8"));
    assert.equal(observed.nodeEnv, "test");
    assert.deepEqual(observed.result, { success: true });
    const row = { ID: "planted", Content: { Headers: { To: [recipient], Subject: ["Certificate renewal failed"] }, Body: `Renewal job: ${jobId}` } };
    const planted = h.matchingMessages({ items: [row], total: 1, count: 1, start: 0 }, { jobId, recipient, previous: new Set() });
    assert.equal(planted.length, 1);
    assert.equal(h.independentReceipt({ nodeEnv: observed.nodeEnv, deliveryStatus: "sent", messages: planted }), false);
    assert.equal(h.independentReceipt({ nodeEnv: "production", deliveryStatus: "sent", messages: [] }), false);
    assert.equal(h.independentReceipt({ nodeEnv: "production", deliveryStatus: "sent", messages: planted }), true);
    const env = h.productionDeliveryEnv({ NODE_ENV: "test", SMTP_USER: "parent", SMTP_PASS: "parent", PATH: "kept" }, 1025);
    assert.equal(env.NODE_ENV, "production");
    assert.equal(env.SMTP_HOST, "127.0.0.1");
    assert.equal(env.SMTP_PORT, "1025");
    assert.equal(env.SMTP_USER, "");
    assert.equal(env.SMTP_PASS, "");
    assert.equal(env.PATH, "kept");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
test("native renewal alert proof stays bound to the prior certificate outbox", () => {
  const { MAIN } = require("./certops-acme-bulk-report");
  const event = require("./test-support/acme-stage-artifact.cjs").artifact().events.find((row) => row.name === MAIN);
  const proof = require("./test-support/acme-renewal-alert-proof.cjs").proof(event.nativeAcmeCertificateOutbox);
  h.verifyAgainstOutbox(proof, event.nativeAcmeCertificateOutbox);
  assert.throws(() => h.verifyAgainstOutbox({ ...proof, jobId: event.nativeAcmeCertificateOutbox.jobId }, event.nativeAcmeCertificateOutbox));
  event.nativeAcmeRenewalAlert = proof;
  const python = spawnSync("python", ["-c", [
    "import json,sys",
    "import certops_acme_renewal_alert_proof as proof",
    "event=json.load(sys.stdin)",
    "parsed=proof.fields(event)",
    "assert parsed[proof.FIELD]['jobId']==event[proof.FIELD]['jobId']",
    "event[proof.FIELD]['actualProductionDeliveryWorker']=False",
    "try:",
    "    proof.fields(event)",
    "except ValueError:",
    "    raise SystemExit(0)",
    "raise SystemExit('false delivery flag was accepted')",
  ].join("\n")], {
    cwd: __dirname,
    input: JSON.stringify(event),
    encoding: "utf8",
    timeout: 20000,
    windowsHide: true,
  });
  assert.equal(python.status, 0, python.stderr || python.stdout);
});
