"use strict";

/**
 * ACME issuer: one CSR-based order through the exec adapter in ../acme,
 * mapped onto the outcome vocabulary in ./index.js. An ACME order completes
 * within the job, so this issuer only returns issued, refused or failed and
 * has no retrieve().
 */

const fs = require("node:fs");
const path = require("node:path");

const { createAcmeAdapter, resolveCertificateOutputPaths } = require("../acme");
const { buildEvidenceItem } = require("../evidence");

/** Evidence metadata values cap at 512 chars (evidence/index.js
 * METADATA_VALUE_MAX_LENGTH); acme adapter excerpts cap at 1024, so they
 * must be re-truncated here or buildEvidenceItem throws and the real ACME
 * failure is lost behind a generic evidence-write error instead of reported. */
const EVIDENCE_METADATA_VALUE_MAX_CHARS = 512;

function boundMetadataExcerpt(value) {
  if (typeof value !== "string" || value.length === 0) return null;
  return value.slice(0, EVIDENCE_METADATA_VALUE_MAX_CHARS);
}

/**
 * Picks the most useful diagnostic text out of a failed ACME adapter run.
 * acme.sh (unlike certbot) writes most of its diagnostic detail, including
 * the reason a run was skipped or rejected, to stdout via its own `_info`
 * logger; only messages routed through `_err` land on stderr. A failure
 * message that only ever looks at stderrExcerpt therefore reports
 * "no stderr" for the exact acme.sh failures an operator most needs
 * explained (e.g. `RENEW_SKIP`), even though the real explanation was
 * captured and redacted right there in stdoutExcerpt. Prefers stderr when
 * both are present since certbot's own errors are conventionally there.
 * @param {{ stderrExcerpt?: string, stdoutExcerpt?: string }} renewal
 * @returns {string}
 */
function acmeFailureDetail(renewal) {
  const stderr = renewal.stderrExcerpt || "";
  const stdout = renewal.stdoutExcerpt || "";
  if (stderr) return stderr;
  if (stdout) return stdout;
  return "no output captured";
}

/**
 * Reads the certificate material an ACME run staged, preferring the
 * fullchain artifact: nearly every server expects leaf plus intermediates at
 * its certificate path, and a leaf-only deployment is what makes clients
 * report an incomplete chain. The leaf-only file stays a fallback for tools
 * (or CAs) that produced no chain artifact at all.
 *
 * @param {{ leafPath: string, fullchainPath: string }} paths
 * @returns {{ pem: string }|{ error: string }}
 */
function readStagedCertificateChain(paths) {
  const candidates = [paths.fullchainPath, paths.leafPath];
  const errors = [];
  for (const candidate of candidates) {
    try {
      const pem = fs.readFileSync(candidate, "utf8");
      if (pem.trim().length > 0) {
        return { pem };
      }
      errors.push(`${candidate} is empty`);
    } catch (err) {
      errors.push(err.message);
    }
  }
  return { error: errors.join("; ") };
}

/**
 * @param {object} params
 * @param {string} params.acmeKind "certbot" | "acme.sh"
 * @param {string[]} params.argv command profile argv the policy engine resolved
 * @param {string} params.caEndpoint ACME directory URL
 * @param {string|null} [params.preferredChain]
 * @param {{ eabKid: string, eabHmacKey: string }|null} [params.eabCredentials]
 * @param {string} params.stateDir agent state dir; ACME account state nests under it
 * @param {string} params.scratchDir directory for the job-scoped CSR and staged chain
 * @param {string} params.jobId names the scratch files and log lines
 * @param {(url: string) => object} params.checkCaEndpoint policy re-check
 * @param {Function} [params.execFileImpl] test seam for the ACME tool
 * @param {(message: string) => void} [params.info] progress logger
 */
function createAcmeIssuer({
  acmeKind,
  argv,
  caEndpoint,
  preferredChain = null,
  eabCredentials = null,
  stateDir,
  scratchDir,
  jobId,
  checkCaEndpoint,
  execFileImpl,
  info = () => {},
}) {
  async function submit({ csrPem, domains }) {
    fs.mkdirSync(scratchDir, { recursive: true });
    const csrPath = path.join(scratchDir, `${jobId}.csr.pem`);
    const stagedCertPath = path.join(scratchDir, `${jobId}.cert.pem`);
    const stagedCertPaths = resolveCertificateOutputPaths(stagedCertPath);
    try {
      fs.writeFileSync(csrPath, csrPem, { mode: 0o600 });
      info(
        `job ${jobId}: starting ACME order (${acmeKind}) against ${caEndpoint} for ${domains.join(", ")}`,
      );
      const adapter = createAcmeAdapter({
        kind: acmeKind,
        commandProfile: { argv },
        execFileImpl,
      });
      const renewalOpts = {
        caEndpoint,
        domains,
        csrPath,
        outCertPath: stagedCertPath,
        stateDir,
        checkCaEndpoint,
      };
      if (typeof preferredChain === "string" && preferredChain.length > 0) {
        renewalOpts.preferredChain = preferredChain;
      }
      if (eabCredentials) {
        renewalOpts.eabKid = eabCredentials.eabKid;
        renewalOpts.eabHmacKey = eabCredentials.eabHmacKey;
      }
      const renewal = await adapter.runRenewal(renewalOpts);
      if (renewal.allowed === false) {
        return {
          outcome: "refused",
          rejectionReason: renewal.rejectionReason,
          detail: String(renewal.detail),
        };
      }
      if (renewal.renewed !== true) {
        return {
          outcome: "failed",
          detail: `acme step failed with exit code ${renewal.exitCode}: ${acmeFailureDetail(renewal)}`,
          evidence: [
            buildEvidenceItem({
              eventType: "validation.failed",
              observedAt: new Date().toISOString(),
              summary: `ACME renewal step failed for job ${jobId} (exit code ${renewal.exitCode}).`,
              metadata: [
                { name: "step", value: "acme" },
                { name: "exitCode", value: renewal.exitCode },
                { name: "stderrExcerpt", value: boundMetadataExcerpt(renewal.stderrExcerpt) },
                { name: "stdoutExcerpt", value: boundMetadataExcerpt(renewal.stdoutExcerpt) },
              ],
            }),
          ],
        };
      }
      const passed = buildEvidenceItem({
        eventType: "validation.passed",
        observedAt: new Date().toISOString(),
        summary: `ACME renewal step succeeded for job ${jobId}.`,
        metadata: [{ name: "step", value: "acme" }, { name: "exitCode", value: renewal.exitCode }],
      });
      info(`job ${jobId}: ACME order succeeded`);

      const staged = readStagedCertificateChain(stagedCertPaths);
      if (staged.error) {
        return {
          outcome: "failed",
          detail: `acme step reported success but produced no certificate file: ${staged.error}`,
          evidence: [passed],
        };
      }
      return { outcome: "issued", certificatePem: staged.pem, evidence: [passed] };
    } finally {
      // The CSR is public but job-scoped, and a partially written chain
      // must never survive a failed order.
      fs.rmSync(csrPath, { force: true });
      for (const stagedArtifact of Object.values(stagedCertPaths)) {
        fs.rmSync(stagedArtifact, { force: true });
      }
    }
  }

  return Object.freeze({ kind: "acme", step: "acme", submit });
}

module.exports = { createAcmeIssuer };
