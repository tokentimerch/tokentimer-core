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

function readPemIfPresent(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    const pem = fs.readFileSync(filePath, "utf8");
    return pem.trim().length > 0 ? pem : null;
  } catch {
    return null;
  }
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
    const code = typeof err.code === "number" ? err.code : typeof err.status === "number" ? err.status : null;
    return {
      exitCode: code,
      stdout: err.stdout || "",
      stderr: err.stderr || "",
      killed: Boolean(err.killed || err.signal),
      error: err.message,
    };
  }
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
  if (typeof caConfig !== "string" || !caConfig.includes("\\")) {
    throw new TypeError("caConfig must be host\\CA Name");
  }
  if (typeof template !== "string" || template.length === 0) {
    throw new TypeError("template is required");
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
  if (typeof jobId !== "string" || jobId.length === 0) {
    throw new TypeError("jobId is required");
  }

  async function classifyAfterCertreq({ phase, workDir, cerPath, rspPath, exitCode, killed }) {
    if (killed) {
      return {
        outcome: "uncertain",
        detail: "certreq was timed out or killed; submission state is unknown",
      };
    }

    const responsePresent = fs.existsSync(rspPath);
    const certificatePresent = fs.existsSync(cerPath);
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
      exitCode,
      cmc,
    });

    if (mapped.outcome === "issued") {
      // Prefer CMC-exported leaf; fall back to certreq .cer on disk.
      let certificatePem = null;
      if (mapped.certificateDerB64) {
        certificatePem = derB64ToPem(mapped.certificateDerB64);
      } else {
        certificatePem = readPemIfPresent(cerPath);
      }
      if (!certificatePem) {
        return {
          outcome: "uncertain",
          detail: "CMC reported issued but no certificate bytes were available",
        };
      }
      return {
        outcome: "issued",
        certificatePem,
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

      const workDir = path.join(scratchDir, `adcs-${jobId}`);
      await fsp.mkdir(workDir, { recursive: true });
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
        workDir,
        cerPath,
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

      const workDir = path.join(scratchDir, `adcs-${jobId}-retrieve-${requestId}`);
      await fsp.mkdir(workDir, { recursive: true });
      const cerPath = path.join(workDir, "retrieved.cer");
      const chainPath = path.join(workDir, "chain.p7b");
      const rspPath = path.join(workDir, "retrieve-response.rsp");

      info(`job ${jobId}: AD CS certreq -retrieve requestId=${requestId}`);
      const argv = [
        "-q",
        "-retrieve",
        String(requestId),
        "-config",
        caConfig,
        cerPath,
        chainPath,
        rspPath,
      ];
      const ran = await runCertreq(execFileImpl, argv, timeoutMs);
      const outcome = await classifyAfterCertreq({
        phase: "retrieve",
        workDir,
        cerPath,
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
  withEnrollmentLock,
  // test seam
  _enrollmentLocks: enrollmentLocks,
};
