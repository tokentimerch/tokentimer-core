"use strict";

/**
 * Read-only AD CS issuer preflight (ADR-0014 decision 5).
 * The agent contacts a CA only after a local enrollment rule names that
 * exact caConfig and template. Results are parsed fields, never command text.
 */

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");

const execFileAsync = promisify(execFile);

const CA_CONFIG_PATTERN =
  /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\\[A-Za-z0-9 ._()-]{1,64}$/;
const TEMPLATE_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/;
const SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1";
const EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000;
const IF_ENFORCEENCRYPTICERTREQUEST = 0x00000200;
const CALL_TIMEOUT_MS = 15000;
const JOB_BUDGET_MS = 60000;
const MAX_CA_CERTS = 8;

function notAllowlisted(message) {
  return {
    status: "rejected",
    rejectionReason: "issuer_not_allowlisted",
    errorMessage: message,
  };
}

function matchEnrollmentRule(rules, caConfig, template) {
  if (!Array.isArray(rules)) return null;
  return (
    rules.find((rule) => rule && rule.caConfig === caConfig && rule.template === template) || null
  );
}

function attributeValues(text, name) {
  const wanted = name.toLowerCase();
  const values = [];
  for (const line of String(text || "").split(/\r?\n/)) {
    const trimmed = line.trim();
    const eq = trimmed.indexOf("=");
    const colon = trimmed.indexOf(":");
    const sep = eq >= 0 && (colon < 0 || eq < colon) ? eq : colon;
    if (sep < 0) continue;
    if (trimmed.slice(0, sep).trim().toLowerCase() !== wanted) continue;
    const value = trimmed.slice(sep + 1).trim();
    if (value) values.push(value);
  }
  return values;
}

function oidList(values) {
  const oids = [];
  for (const value of values) {
    for (const part of value.split(/[\s,;]+/)) {
      if (/^\d+(?:\.\d+)+$/.test(part)) oids.push(part);
    }
  }
  return oids;
}

function exactlyServerAuth(oids) {
  return oids.length === 1 && oids[0] === SERVER_AUTH_OID;
}

function templateIdentities(text) {
  const names = [];
  const seen = new Set();
  for (const key of ["cn", "TemplatePropCommonName"]) {
    for (const value of attributeValues(text, key)) {
      const token = String(value).split(/[\s,;]+/)[0];
      if (!TEMPLATE_PATTERN.test(token) || seen.has(token)) continue;
      seen.add(token);
      names.push(token);
    }
  }
  return names;
}

function unreadableTemplate() {
  return {
    verdict: "unreadable",
    reasons: ["template_unreadable"],
    schemaVersion: null,
    templateOid: null,
    minimalKeySize: null,
    asymmetricAlgorithm: null,
    enrolleeSuppliesSubject: null,
  };
}

function parseTemplateDump(text, expectedTemplate) {
  if (typeof expectedTemplate === "string") {
    const identities = templateIdentities(text);
    if (identities.length !== 1 || identities[0] !== expectedTemplate) {
      return unreadableTemplate();
    }
  }
  const schemaRaw = attributeValues(text, "msPKI-Template-Schema-Version");
  const ekuRaw = attributeValues(text, "pKIExtendedKeyUsage");
  if (schemaRaw.length === 0 && ekuRaw.length === 0) {
    return unreadableTemplate();
  }
  const reasons = [];
  const schemaVersion = /^\d+$/.test(schemaRaw[0] || "") ? Number(schemaRaw[0]) : null;
  if (schemaVersion == null) reasons.push("template_unreadable");
  else if (schemaVersion === 1) reasons.push("schema_version_1");
  const eku = oidList(ekuRaw);
  if (!exactlyServerAuth(eku)) reasons.push("eku_not_server_auth_only");
  const appRaw = attributeValues(text, "msPKI-Certificate-Application-Policy");
  if (appRaw.length > 0 && !exactlyServerAuth(oidList(appRaw))) {
    reasons.push("application_policy_not_server_auth_only");
  }
  const uniqueReasons = [...new Set(reasons)].slice(0, 4);
  const oid = attributeValues(text, "msPKI-Cert-Template-OID")[0] || null;
  const keyRaw = attributeValues(text, "msPKI-Minimal-Key-Size")[0];
  const nameFlag = attributeValues(text, "msPKI-Certificate-Name-Flag")[0];
  const algorithm = attributeValues(text, "msPKI-Asymmetric-Algorithm")[0] || null;
  const parsed = /^\d+$/.test(nameFlag || "") ? Number(nameFlag) : null;
  return {
    verdict: uniqueReasons.length === 0 ? "safe" : uniqueReasons.includes("template_unreadable") ? "unreadable" : "unsafe",
    reasons: uniqueReasons,
    schemaVersion,
    templateOid: oid && /^[0-2](\.(0|[1-9][0-9]{0,9})){1,63}$/.test(oid) ? oid : null,
    minimalKeySize: /^\d+$/.test(keyRaw || "") ? Number(keyRaw) : null,
    asymmetricAlgorithm: algorithm && /^[A-Za-z0-9_]{1,32}$/.test(algorithm) ? algorithm : null,
    enrolleeSuppliesSubject: parsed == null ? null : (parsed & 0x1) === 0x1,
  };
}

function parseRegDword(text) {
  const match = String(text || "").match(/REG_DWORD\s*=\s*(0x[0-9a-fA-F]+|\d+)/i);
  if (!match) return null;
  const raw = match[1];
  const value = raw.toLowerCase().startsWith("0x") ? Number.parseInt(raw, 16) : Number(raw);
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) return null;
  return value;
}

function parseCaCheck(editText, interfaceText, operatorAttested) {
  const editFlags = parseRegDword(editText);
  const interfaceFlags = parseRegDword(interfaceText);
  if (editFlags == null || interfaceFlags == null) {
    return {
      verdict: "unreadable",
      reasons: ["flags_unreadable"],
      operatorAttested: operatorAttested === true,
    };
  }
  const reasons = [];
  if ((editFlags & EDITF_ATTRIBUTESUBJECTALTNAME2) !== 0) {
    reasons.push("subject_alt_name_attribute_enabled");
  }
  if ((interfaceFlags & IF_ENFORCEENCRYPTICERTREQUEST) === 0) {
    reasons.push("encrypted_requests_not_enforced");
  }
  return {
    verdict: reasons.length === 0 ? "safe" : "unsafe",
    reasons,
    operatorAttested: false,
  };
}

function parseCertCount(text) {
  const match = String(text || "").match(/(?:certificate\s+count|cert\s+count|certcount)\s*[:=]\s*(\d+)/i);
  if (!match) return null;
  const count = Number(match[1]);
  if (!Number.isInteger(count) || count < 0 || count > 32) return null;
  return count;
}

function certificateFromDer(der) {
  let parsed;
  try {
    parsed = new crypto.X509Certificate(der);
  } catch (_error) {
    return null;
  }
  const spki = parsed.publicKey.export({ type: "spki", format: "der" });
  return {
    certificateB64: Buffer.from(der).toString("base64"),
    keySha256: crypto.createHash("sha256").update(spki).digest("hex"),
    // Standard certificate thumbprint (SHA-1 of the DER), not a password hash.
    // codeql[js/weak-cryptographic-algorithm]
    thumbprintSha1: crypto.createHash("sha1").update(der).digest("hex").toUpperCase(),
    notBefore: parsed.validFrom ? new Date(parsed.validFrom).toISOString() : null,
    notAfter: parsed.validTo ? new Date(parsed.validTo).toISOString() : null,
  };
}

function runCertutil(execFileImpl, argv, timeoutMs) {
  const run = execFileImpl || execFileAsync;
  return run("certutil.exe", argv, {
    encoding: "buffer",
    timeout: timeoutMs,
    windowsHide: true,
    maxBuffer: 256 * 1024,
  });
}

async function runCertutilPreflight({
  caConfig,
  template,
  operatorAttested = false,
  execFileImpl,
  budgetMs = JOB_BUDGET_MS,
}) {
  const started = Date.now();
  function call(argv) {
    const remaining = budgetMs - (Date.now() - started);
    if (remaining <= 0) {
      const error = new Error("adcs-preflight time budget exhausted");
      error.code = "ADCS_PREFLIGHT_TIMEOUT";
      throw error;
    }
    return runCertutil(execFileImpl, argv, Math.min(CALL_TIMEOUT_MS, remaining));
  }
  function textOf(result) {
    const stdout = result && result.stdout != null ? result.stdout : result;
    return Buffer.isBuffer(stdout) ? stdout.toString("utf8") : String(stdout || "");
  }

  let templateText = "";
  let editText = "";
  let interfaceText = "";
  let countText = "";
  try {
    templateText = textOf(await call(["-config", caConfig, "-dstemplate", template]));
    editText = textOf(await call(["-config", caConfig, "-getreg", "policy\\EditFlags"]));
    interfaceText = textOf(await call(["-config", caConfig, "-getreg", "CA\\InterfaceFlags"]));
    countText = textOf(await call(["-config", caConfig, "-cainfo", "certcount"]));
  } catch (_error) {
    return {
      preflightResult: {
        caConfig,
        template,
        templateCheck: parseTemplateDump(templateText, template),
        caCheck: {
          verdict: "unreadable",
          reasons: ["ca_unreachable"],
          operatorAttested: operatorAttested === true,
        },
        caCertificates: [],
      },
    };
  }

  const count = parseCertCount(countText);
  const caCertificates = [];
  if (count != null) {
    const limit = Math.min(count, MAX_CA_CERTS);
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "tt-adcs-preflight-"));
    try {
      for (let index = 0; index < limit; index += 1) {
        const certPath = path.join(dir, `${index}.cer`);
        try {
          await call(["-config", caConfig, "-ca.cert", String(index), certPath]);
          const der = await fs.readFile(certPath);
          const parsed = certificateFromDer(der);
          if (parsed && parsed.notBefore && parsed.notAfter) caCertificates.push(parsed);
        } catch (_certError) {
          // One unreadable certificate does not become a safe pin.
        }
      }
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  }

  return {
    preflightResult: {
      caConfig,
      template,
      templateCheck: parseTemplateDump(templateText, template),
      caCheck: parseCaCheck(editText, interfaceText, operatorAttested),
      caCertificates,
    },
  };
}

async function executeAdcsPreflight({ job, rules, probe, execFileImpl } = {}) {
  const caConfig = job && job.caConfig;
  const template = job && job.template;
  if (job && job.mode === "dry_run") {
    return {
      status: "blocked",
      errorMessage: "adcs-preflight has no dry-run mode",
    };
  }
  if (
    !job ||
    job.transport !== "dcom" ||
    typeof caConfig !== "string" ||
    !CA_CONFIG_PATTERN.test(caConfig) ||
    typeof template !== "string" ||
    !TEMPLATE_PATTERN.test(template)
  ) {
    return notAllowlisted(
      "adcs-preflight was refused before any CA contact because caConfig, template, or transport is not acceptable",
    );
  }
  const rule = matchEnrollmentRule(rules, caConfig, template);
  if (!rule) {
    return notAllowlisted(
      "adcs-preflight was refused before any CA contact because no local enrollment rule names this caConfig and template",
    );
  }
  const run = probe || runCertutilPreflight;
  let probed;
  try {
    probed = await run({
      caConfig,
      template,
      operatorAttested: rule.operatorAttested === true,
      execFileImpl,
    });
  } catch (_error) {
    return {
      status: "failed",
      errorMessage: "adcs-preflight could not read the CA",
    };
  }
  if (!probed || !probed.preflightResult) {
    return {
      status: "failed",
      errorMessage: "adcs-preflight could not read the CA",
    };
  }
  return {
    status: "succeeded",
    preflightResult: probed.preflightResult,
  };
}

module.exports = {
  EDITF_ATTRIBUTESUBJECTALTNAME2,
  IF_ENFORCEENCRYPTICERTREQUEST,
  executeAdcsPreflight,
  matchEnrollmentRule,
  parseCaCheck,
  parseTemplateDump,
  runCertutilPreflight,
};
