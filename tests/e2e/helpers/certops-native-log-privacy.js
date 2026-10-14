/**
 * Qualify child-output confidentiality through a real allowlisted native reload job.
 * Imported by the native-agent fixture; actual child stdout/stderr contain generated
 * test-only secrets. Owned receipts prove emission, while real agent/API/PG oracles
 * require withholding. Child output is not advertised as streamed console content.
 */
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const assert = require("node:assert/strict");
async function qualifyNativeLogPrivacy({ gate, fixture, prefix, configDir, root, stop, start, wait, row, prohibited }) {
  const configFile = path.join(configDir, "config.json"), original = fs.readFileSync(configFile);
  const script = path.join(root, "privacy-child.cjs"), materialFile = path.join(root, "privacy-material.json");
  const secrets = [crypto.randomBytes(24).toString("hex"), crypto.randomBytes(24).toString("hex"), crypto.randomBytes(24).toString("base64")];
  for (const secret of secrets) prohibited.add(secret);
  fs.writeFileSync(materialFile, JSON.stringify(secrets), { mode: 0o600 });
  fs.writeFileSync(script, `"use strict";
const fs=require("node:fs"),path=require("node:path");
const secrets=JSON.parse(fs.readFileSync(process.argv[2],"utf8"));
fs.writeSync(1,"Public stdout marker password="+secrets[0]+"\\n");
fs.writeSync(2,"Public stderr marker Authorization: Bearer "+secrets[1]+"\\n-----BEGIN PRIVATE KEY-----\\n"+secrets[2]+"\\n-----END PRIVATE KEY-----\\n");
fs.writeFileSync(path.join(path.dirname(process.argv[2]),"privacy-"+process.argv[3]+".json"),JSON.stringify({pid:process.pid,stdoutEmitted:true,stderrEmitted:true}),{mode:0o600});
`, { mode: 0o600 });
  await gate.scenario("native-agent-child-output-confidentiality", async () => {
    try {
      await stop();
      const config = JSON.parse(original);
      config.policy.allowedCommands = Object.fromEntries(["validate", "reload"].map(mode => [`privacy-${mode}`, { argv: [process.execPath, script, materialFile, mode] }]));
      fs.writeFileSync(configFile, JSON.stringify(config), { mode: 0o600 }); start();
      const created = await fixture.request(`${prefix}/jobs`, "POST", { operation: "reload", subjectType: "domain", subjectId: "qualification.example.test", payload: { reloadService: "nginx", reloadCommandRefs: { validate: "privacy-validate", reload: "privacy-reload" } } });
      assert.equal(created.status, 201); const jobId = created.body.job.id;
      await wait(async () => ["succeeded", "failed", "rejected"].includes((await row(jobId)).status));
      assert.equal((await row(jobId)).status, "succeeded");
      const receipts = ["validate", "reload"].map(mode => JSON.parse(fs.readFileSync(path.join(root, `privacy-${mode}.json`), "utf8")));
      assert.equal(new Set(receipts.map(item => item.pid)).size, 2);
      assert.ok(receipts.every(item => item.stdoutEmitted === true && item.stderrEmitted === true));
      let logs;
      await wait(async () => { const response = await fixture.request(`${prefix}/jobs/${jobId}/agent-log`); assert.equal(response.status, 200); if (!response.body.logsComplete) return false; logs = response.body; return true; });
      assert.ok(logs.items.some(item => item.message.includes("reload succeeded")), "Actual generic execution marker must remain visible");
      const evidence = (await fixture.pool.query("SELECT * FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2", [fixture.workspaceId, jobId])).rows;
      const stored = JSON.stringify({ logs, evidence, job: await row(jobId) });
      for (const secret of secrets) assert.equal(stored.includes(secret), false, "Generated child-output secret must never reach API or PostgreSQL evidence");
      for (const marker of ["BEGIN PRIVATE KEY", "Public stdout marker", "Public stderr marker"]) assert.equal(stored.includes(marker), false, "Raw child output must remain withheld");
      gate.report.nativeChildOutputPrivacy = { executedChildren: 2, stdoutEmitted: true, stderrEmitted: true, rawChildOutputWithheld: true, genericExecutionMarkerPersisted: true, jobSucceeded: true };
    } finally { await stop(); fs.writeFileSync(configFile, original, { mode: 0o600 }); start(); }
  }, { oracle: "Real validate/reload child receipts prove stdout/stderr emission; raw child output is withheld while genuine successful execution console/evidence persists without fixture secrets" });
}
module.exports = { qualifyNativeLogPrivacy };
