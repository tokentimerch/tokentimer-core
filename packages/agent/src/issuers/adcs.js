"use strict";

/**
 * AD CS issuer: certreq -submit / -retrieve plus tokentimer-adcs-cmc decode
 * (ADR-0014). Maps structural CMC + HRESULT signals onto the issuer outcome
 * vocabulary. Never parses certreq console text.
 *
 * Enrollment concurrency: submit/retrieve for the same enrollmentId share an
 * in-process mutex. A durable cross-process lock (W6) is still required before
 * production AD CS enrollment is enabled in the executor.
 */

const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");

const { decodeCmcResponse } = require("./cmc-helper");
const { mapAdcsDisposition } = require("./adcs-disposition");

const execFileAsync = promisify(execFile);

// Same patterns as enrollment-snapshot / signed-dispatch-payload contracts.
const CA_CONFIG_PATTERN =
  /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\\[A-Za-z0-9 ._()-]{1,64}$/;
const TEMPLATE_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/;
const JOB_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;

/** @type {Map<string, Promise<unknown>>} */
const enrollmentLocks = new Map();

async function withEnrollmentLock(enrollmentId, fn) {
  const key =
    typeof enrollmentId === "string" && enrollmentId.length > 0 ? enrollmentId : "__anonymous__";
  const prev = enrollmentLocks.get(key) || Promise.resolve();
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const chain = prev.then(() => gate, () => gate);
  enrollmentLocks.set(key, chain);
  await prev.catch(() => {});
  try {
    return await fn();
  } finally {
    release();
    if (enrollmentLocks.get(key) === chain) {
      enrollmentLocks.delete(key);
    }
  }
}

function derB64ToPem(derB64) {
  const body = String(derB64).replace(/\s+/g, "");
  const lines = body.match(/.{1,64}/g) || [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`;
}

function certificateFileToPem(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    const raw = fs.readFileSync(filePath);
    if (raw.length === 0) return null;
    const asText = raw.toString("utf8");
    if (asText.includes("-----BEGIN CERTIFICATE-----")) {
      return asText.trim().endsWith("-----END CERTIFICATE-----")
        ? asText
        : `${asText.trim()}\n`;
    }
    // certreq writes DER by default.
    return derB64ToPem(raw.toString("base64"));
  } catch {
    return null;
  }
}

function certreqExitCode(err) {
  // Node's execFile sets err.code to a string (ENOENT/ETIMEDOUT) on spawn
  // failures and to the numeric HRESULT/exit on a running process. Prefer
  // a numeric status when both exist.
  if (typeof err.status === "number") return err.status;
  if (typeof err.code === "number") return err.code;
  return null;
}

async function runCertreq(execFileImpl, argv, timeoutMs) {
  try {
    const result = await execFileImpl("certreq.exe", argv, {
      encoding: "utf8",
      timeout: timeoutMs,
      windowsHide: true,
      maxBuffer: 1024 * 1024,
    });
    return { exitCode: 0, stdout: result.stdout || "", stderr: result.stderr || "" };
  } catch (err) {
    return {
      exitCode: certreqExitCode(err),
      stdout: err.stdout || "",
      stderr: err.stderr || "",
      killed: Boolean(err.killed || err.signal),
      error: err.message,
    };
  }
}

/**
 * Fresh exclusive scratch dir for one certreq invocation. Prior .rsp/.cer/.p7b
 * under the same jobId must never be consulted: classifyAfterCertreq treats
 * existence as "this run wrote it", and CMC issued ignores the exit code.
 * @param {string} scratchDir
 * @param {string} jobId
 * @param {"submit"|"retrieve"} phase
 * @returns {Promise<string>}
 */
async function createInvocationWorkDir(scratchDir, jobId, phase) {
  return fsp.mkdtemp(path.join(scratchDir, `adcs-${jobId}-${phase}-`));
}

/**
 * @param {object} params
 * @param {string} params.caConfig host\\CA Name
 * @param {string} params.template template common name
 * @param {string} params.caKeySha256
 * @param {string} params.caCertPath PEM/DER CA cert for CMC verify
 * @param {string} params.helperPath tokentimer-adcs-cmc binary
 * @param {string} params.scratchDir
 * @param {string} params.jobId
 * @param {string} [params.enrollmentId]
 * @param {typeof execFileAsync} [params.execFileImpl]
 * @param {typeof decodeCmcResponse} [params.decodeCmcImpl]
 * @param {number} [params.timeoutMs]
 * @param {(message: string) => void} [params.info]
 */
function createAdcsIssuer({
  caConfig,
  template,
  caKeySha256,
  caCertPath,
  helperPath,
  scratchDir,
  jobId,
  enrollmentId,
  execFileImpl = execFileAsync,
  decodeCmcImpl = decodeCmcResponse,
  timeoutMs = 60_000,
  info = () => {},
}) {
  if (typeof caConfig !== "string" || !CA_CONFIG_PATTERN.test(caConfig)) {
    throw new TypeError("caConfig must match host\\CA Name (ADR-0014 / enrollment-snapshot)");
  }
  if (typeof template !== "string" || !TEMPLATE_PATTERN.test(template)) {
    throw new TypeError("template must match ^[A-Za-z0-9_.-]{1,64}$");
  }
  if (typeof caKeySha256 !== "string" || !/^[a-f0-9]{64}$/.test(caKeySha256)) {
    throw new TypeError("caKeySha256 must be 64 lowercase hex characters");
  }
  if (typeof caCertPath !== "string" || caCertPath.length === 0) {
    throw new TypeError("caCertPath is required");
  }
  if (typeof helperPath !== "string" || helperPath.length === 0) {
    throw new TypeError("helperPath is required");
  }
  if (typeof scratchDir !== "string" || scratchDir.length === 0) {
    throw new TypeError("scratchDir is required");
  }
  if (typeof jobId !== "string" || !JOB_ID_PATTERN.test(jobId)) {
    throw new TypeError("jobId must match ^[A-Za-z0-9_.:-]{1,128}$");
  }

  async function classifyAfterCertreq({ phase, cerPath, chainPath, rspPath, exitCode, killed }) {
    if (killed) {
      return {
        outcome: "uncertain",
        detail: "certreq was timed out or killed; submission state is unknown",
      };
    }

    const responsePresent = fs.existsSync(rspPath);
    const certificatePresent = fs.existsSync(cerPath);
    const chainPresent = fs.existsSync(chainPath);
    let cmc = null;

    if (responsePresent) {
      const decoded = await decodeCmcImpl({
        helperPath,
        responsePath: rspPath,
        caKeySha256,
        caCertPath,
        execFileImpl,
        timeoutMs,
      });
      if (decoded.ok && decoded.result) {
        cmc = decoded.result;
      } else {
        cmc = { disposition: "unknown", error: decoded.error || "CMC decode failed" };
      }
    }

    const mapped = mapAdcsDisposition({
      phase,
      responsePresent,
      certificatePresent,
      chainPresent,
      exitCode,
      cmc,
    });

    if (mapped.outcome === "issued") {
      // Only the CMC-exported leaf (hash-verified by tokentimer-adcs-cmc).
      if (typeof mapped.certificateDerB64 !== "string" || mapped.certificateDerB64.length === 0) {
        return {
          outcome: "uncertain",
          detail: "CMC reported issued but certificateDerB64 was missing",
        };
      }
      return {
        outcome: "issued",
        certificatePem: derB64ToPem(mapped.certificateDerB64),
      };
    }

    if (mapped.outcome === "pending") {
      return {
        outcome: "pending",
        requestId: mapped.requestId,
      };
    }

    return {
      outcome: mapped.outcome,
      detail: mapped.detail,
    };
  }

  async function submit({ csrPem }) {
    return withEnrollmentLock(enrollmentId, async () => {
      if (typeof csrPem !== "string" || !csrPem.includes("BEGIN CERTIFICATE REQUEST")) {
        return {
          outcome: "refused",
          rejectionReason: "invalid_csr",
          detail: "submit requires a PEM certificate request",
        };
      }

      const workDir = await createInvocationWorkDir(scratchDir, jobId, "submit");
      const reqPath = path.join(workDir, "request.req");
      const cerPath = path.join(workDir, "issued.cer");
      const chainPath = path.join(workDir, "chain.p7b");
      const rspPath = path.join(workDir, "submit-response.rsp");
      await fsp.writeFile(reqPath, csrPem, "utf8");

      info(`job ${jobId}: AD CS certreq -submit template=${template}`);
      const argv = [
        "-q",
        "-submit",
        "-config",
        caConfig,
        "-attrib",
        `CertificateTemplate:${template}`,
        reqPath,
        cerPath,
        chainPath,
        rspPath,
      ];
      const ran = await runCertreq(execFileImpl, argv, timeoutMs);
      return classifyAfterCertreq({
        phase: "submit",
        cerPath,
        chainPath,
        rspPath,
        exitCode: ran.exitCode,
        killed: ran.killed,
      });
    });
  }

  async function retrieve(requestId) {
    return withEnrollmentLock(enrollmentId, async () => {
      if (!Number.isInteger(requestId) || requestId < 1 || requestId > 0xffffffff) {
        return {
          outcome: "refused",
          rejectionReason: "invalid_request_id",
          detail: "retrieve requires a 32-bit unsigned RequestId",
        };
      }

      const workDir = await createInvocationWorkDir(scratchDir, jobId, "retrieve");
      const cerPath = path.join(workDir, "retrieved.cer");
      const chainPath = path.join(workDir, "chain.p7b");
      const rspPath = path.join(workDir, "retrieve-response.rsp");

      info(`job ${jobId}: AD CS certreq -retrieve requestId=${requestId}`);
      // PoC argv: certreq -q -retrieve -config <ca> <RequestId> <cer> <chain> <rsp>
      const argv = [
        "-q",
        "-retrieve",
        "-config",
        caConfig,
        String(requestId),
        cerPath,
        chainPath,
        rspPath,
      ];
      const ran = await runCertreq(execFileImpl, argv, timeoutMs);
      const outcome = await classifyAfterCertreq({
        phase: "retrieve",
        cerPath,
        chainPath,
        rspPath,
        exitCode: ran.exitCode,
        killed: ran.killed,
      });
      // Pend token on retrieve must match the journaled RequestId.
      if (outcome.outcome === "pending" && outcome.requestId !== requestId) {
        return {
          outcome: "uncertain",
          detail: `retrieve pend token ${outcome.requestId} differs from journaled RequestId ${requestId}`,
        };
      }
      return outcome;
    });
  }

  return Object.freeze({
    kind: "adcs",
    step: "adcs",
    submit,
    retrieve,
  });
}

module.exports = {
  createAdcsIssuer,
  derB64ToPem,
  certificateFileToPem,
  certreqExitCode,
  withEnrollmentLock,
  CA_CONFIG_PATTERN,
  TEMPLATE_PATTERN,
  JOB_ID_PATTERN,
  // test seam
  _enrollmentLocks: enrollmentLocks,
};
