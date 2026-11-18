"use strict";
// Preserve the installed-service observation outside the existing supporting
// UX report. The strict operator artifact still needs same-run teardown.
const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");
async function run() {
  assert.ok(process.platform === "linux" && process.getuid() === 0);
  const { main } = require("../journey.cjs");
  const output = process.env.TT_WILDCARD_UX_OUTPUT;
  const staged = JSON.parse(fs.readFileSync(path.join(output, "agent-package/harness-input.json"), "utf8"));
  const proof = await main({ nativeOpenBao: {
    packageArtifact: staged.packageArtifact, customerImage: process.env.TT_UX_CUSTOMER_IMAGE,
    apiAddress: "https://127.0.0.1:" + process.env.TT_UX_NATIVE_API_PORT,
    baoAddress: "https://127.0.0.1:" + process.env.TT_UX_NATIVE_BAO_PORT,
  } });
  assert.ok(proof.nativeService && proof.nativeOpenBaoFacts);
  fs.writeFileSync(path.join(output, "native-openbao-observation.json"), JSON.stringify({
    packageArtifact: staged.packageArtifact, runId: process.env.GITHUB_RUN_ID, sourceSha: process.env.GITHUB_SHA, ...proof,
  }) + "\n", { flag: "wx", mode: 0o600 });
}

run().catch(error => {
  const kind = error?.code === "ERR_ASSERTION" ? "assertion" : "error";
  const frames = typeof error?.stack === "string" ? error.stack.split("\n").slice(1, 11) : [];
  const location = /[\\/](native-openbao-journey\.cjs|journey\.cjs|qualification\.cjs|native-openbao-bootstrap\.cjs|native-service-observation\.cjs):(\d{1,5}):\d{1,4}\)?$/;
  const frame = frames.map(line => location.exec(line.trim())).find(Boolean);
  process.stderr.write(`OPENBAO_JOURNEY_FAILED ${kind}${frame ? ` ${frame[1]}:${frame[2]}` : ""}\n`);
  const publish = frames.find(line => /^\s*at (?:async )?publish \(/.test(line));
  const call = publish && location.exec(publish.trim());
  if (kind === "assertion" && call?.[1] === "journey.cjs" &&
      typeof error.message === "string" && error.message.length <= 262144) {
    try {
      const job = JSON.parse(error.message);
      const statuses = /^(succeeded|failed|blocked|rejected|cancelled|orphaned_unknown_effect)$/;
      const reasons = /^material_(auth_denied|auth_unavailable|store_config_invalid|provider_mismatch|scope_denied|destination_denied|platform_unqualified|execution_failed|store_unavailable|response_invalid|version_unavailable|intent_invalid|publication_uncertain|lease_unavailable|issuance_uncertain|cas_conflict)$/;
      if (job?.operation === "issue" && statuses.test(job.status)) {
        const reason = reasons.test(job.errorMessage) ? job.errorMessage : job.errorCode == null ? "none" : "other";
        process.stderr.write(`OPENBAO_PUBLISH_TERMINAL journey.cjs:${call[2]} ${job.status} ${reason}\n`);
      }
    } catch {}
  }
  process.exitCode = 1;
});
