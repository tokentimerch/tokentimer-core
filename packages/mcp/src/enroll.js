"use strict";

// `tokentimer-mcp enroll`: redeem a one-time setup code for a connection
// credential and store it safely (ADR-0015 section 12).
//
// Rules this command keeps:
//  - The setup code is read from stdin or a hidden prompt, never from the
//    command line, where other users could see it in a process list.
//  - The credential is written to a private file and is never printed.
//  - The code is spent exactly once. If the outcome is unknown, the command
//    says so and explains how to recover, instead of retrying a spent code.
//  - Every message is fixed text. Nothing from the server's reply is echoed.

const crypto = require("node:crypto");
const { ToolError, buildUrl, readCapped } = require("./apiClient");
const { CREDENTIAL_PATTERN, ConfigError, resolveBaseUrl, serverAddressOf } = require("./config");
const {
  CredentialStoreError,
  checkDestination,
  defaultCredentialPath,
  writeCredential,
} = require("./credentialStore");

const GRANT_PATTERN = /^ttopg_[a-f0-9]{16}_[a-f0-9]{64}$/;
const REDEEM_PATH = "/api/v1/operator/enroll/redeem";
const TIMEOUT_MS = 20000;
const MAX_RESPONSE_BYTES = 65536;

const USAGE = [
  "Usage: tokentimer-mcp enroll [--api-url <url>] [--credential-file <path>] [--replace]",
  "",
  "Redeems a one-time setup code from TokenTimer (Connect an assistant) and",
  "stores the resulting credential in a private file.",
  "",
  "  --api-url <url>          TokenTimer API address (or set TOKENTIMER_API_URL)",
  "  --credential-file <path> where to store the credential (default: your user config directory)",
  "  --replace                overwrite an existing credential file",
  "",
  "The setup code is read from standard input or a hidden prompt. It is never",
  "accepted as an argument.",
].join("\n");

class UsageError extends Error {}

// Anything shaped like a setup code, wherever it sits in the arguments: as a
// word, as a flag value, or after an equals sign. It is already visible to
// anything that lists processes, so it is never accepted.
const CODE_ANYWHERE = /ttopg_[a-f0-9]{8,}/i;

function parseArgs(argv) {
  const options = { apiUrl: null, credentialFile: null, replace: false, help: false };
  if (argv.some((arg) => CODE_ANYWHERE.test(String(arg)))) {
    throw new UsageError(
      "Do not pass the setup code as an argument: it can be seen by other users. " +
        "That code should be treated as exposed: revoke it in TokenTimer and create a new one.",
    );
  }
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const [flag, inline] = arg.startsWith("--") && arg.includes("=") ? [arg.slice(0, arg.indexOf("=")), arg.slice(arg.indexOf("=") + 1)] : [arg, null];
    const takeValue = () => {
      if (inline !== null) return inline;
      i += 1;
      if (i >= argv.length || argv[i].startsWith("--")) throw new UsageError(`${flag} needs a value`);
      return argv[i];
    };
    if (flag === "--api-url") options.apiUrl = takeValue();
    else if (flag === "--credential-file") options.credentialFile = takeValue();
    else if (flag === "--replace") options.replace = true;
    else if (flag === "--help" || flag === "-h") options.help = true;
    else throw new UsageError(`Unknown argument: ${flag.startsWith("--") ? flag : "(positional)"}`);
  }
  return options;
}

// What each failure means, by the fixed code the API returns. Anything not in
// this table gets a generic line, so a reply can never put text in front of the user.
const REDEEM_MESSAGES = Object.freeze({
  OPERATOR_ENROLLMENT_INVALID: "That setup code is not valid. Check that you copied all of it.",
  OPERATOR_ENROLLMENT_USED: "That setup code was already used. Create a new one in TokenTimer.",
  OPERATOR_ENROLLMENT_EXPIRED: "That setup code has expired. Create a new one in TokenTimer.",
  OPERATOR_ENROLLMENT_REVOKED: "That setup code was revoked. Create a new one in TokenTimer.",
  OPERATOR_ENROLLMENT_AUTHORITY_LOST:
    "The person who created that setup code no longer has the access it needs. Ask them to check their role, then create a new code.",
  OPERATOR_ENROLLMENT_RATE_LIMITED: "Too many attempts. Wait a few minutes and try again.",
  OPERATOR_INTERFACE_DISABLED: "This TokenTimer server does not have the assistant interface turned on.",
});

const UNKNOWN_OUTCOME =
  "Could not confirm whether setup finished. The code may have been used and a connection created. " +
  "Open Connect an assistant in TokenTimer: if a connection from this setup exists and was never used, " +
  "revoke it, then create a new setup code and run this again.";

async function redeem({ config, grant, fetchImpl }) {
  const correlationId = crypto.randomUUID();
  const url = buildUrl(config, REDEEM_PATH);
  let response;
  try {
    response = await fetchImpl(url, {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(config.requestTimeoutMs),
      headers: {
        Authorization: `Bearer ${grant}`,
        Accept: "application/json",
        "X-Request-Id": correlationId,
      },
    });
  } catch (_error) {
    // The request may or may not have reached the server.
    return { outcome: "unknown" };
  }

  let text = "";
  try {
    text = await readCapped(response, config.maxResponseBytes, correlationId);
  } catch (_error) {
    return { outcome: response.ok ? "unknown" : "failed", status: response.status, code: null };
  }
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (_error) {
    /* handled below */
  }
  if (response.status === 201 && body && typeof body.credential === "string") {
    return { outcome: "created", body };
  }
  if (response.ok) return { outcome: "unknown" };
  const code = typeof body?.code === "string" ? body.code : null;
  return { outcome: "failed", status: response.status, code };
}

function describeFailure({ status, code }) {
  if (code && Object.hasOwn(REDEEM_MESSAGES, code)) return REDEEM_MESSAGES[code];
  if (status === 404) return "This TokenTimer server does not have the assistant interface turned on.";
  if (status === 429) return REDEEM_MESSAGES.OPERATOR_ENROLLMENT_RATE_LIMITED;
  return "TokenTimer could not complete setup.";
}

async function readSetupCode({ stdin, readSecret }) {
  if (stdin.isTTY) return (await readSecret("Setup code (input is hidden): ")).trim();
  const chunks = [];
  let total = 0;
  for await (const chunk of stdin) {
    total += chunk.length;
    if (total > 4096) throw new UsageError("The setup code on standard input is too long");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8").split(/\r?\n/)[0].trim();
}

function clientSnippet({ apiUrl, file }) {
  return JSON.stringify(
    {
      mcpServers: {
        tokentimer: {
          command: "tokentimer-mcp",
          env: { TOKENTIMER_API_URL: apiUrl, TOKENTIMER_MCP_CREDENTIAL_FILE: file },
        },
      },
    },
    null,
    2,
  );
}

async function runEnroll({
  argv = [],
  env = process.env,
  stdin = process.stdin,
  stdout = process.stdout,
  stderr = process.stderr,
  fetchImpl = globalThis.fetch,
  readSecret,
  store = writeCredential,
  check = checkDestination,
} = {}) {
  const say = (line = "") => stdout.write(`${line}\n`);
  const fail = (line) => stderr.write(`tokentimer-mcp: ${line}\n`);

  let options;
  try {
    options = parseArgs(argv);
  } catch (error) {
    fail(error.message);
    stderr.write(`${USAGE}\n`);
    return 2;
  }
  if (options.help) {
    say(USAGE);
    return 0;
  }

  let target;
  try {
    const { origin, basePath } = resolveBaseUrl(options.apiUrl || env.TOKENTIMER_API_URL);
    target = { origin, basePath };
  } catch (error) {
    fail(error instanceof ConfigError ? error.message.replace("TOKENTIMER_API_URL", "The API address (--api-url or TOKENTIMER_API_URL)") : "The API address is not valid");
    return 2;
  }
  const config = { ...target, requestTimeoutMs: TIMEOUT_MS, maxResponseBytes: MAX_RESPONSE_BYTES };
  const file = options.credentialFile || env.TOKENTIMER_MCP_CREDENTIAL_FILE || defaultCredentialPath({ env });

  let grant;
  try {
    grant = await readSetupCode({ stdin, readSecret });
  } catch (error) {
    fail(error instanceof UsageError ? error.message : "The setup code could not be read");
    return 2;
  }
  if (!GRANT_PATTERN.test(grant)) {
    fail(REDEEM_MESSAGES.OPERATOR_ENROLLMENT_INVALID);
    return 1;
  }

  // Check the destination before spending the code, so a path problem cannot
  // burn it. Nothing is written by this check.
  try {
    check(file, { replace: options.replace });
  } catch (error) {
    fail(error instanceof CredentialStoreError ? error.message : "The credential location cannot be used");
    return 2;
  }

  let result;
  try {
    result = await redeem({ config, grant, fetchImpl });
  } catch (error) {
    if (error instanceof ToolError) {
      fail("The API address is not usable for setup.");
      return 2;
    }
    result = { outcome: "unknown" };
  }
  if (result.outcome === "unknown") {
    fail(UNKNOWN_OUTCOME);
    return 1;
  }
  if (result.outcome === "failed") {
    fail(describeFailure(result));
    return 1;
  }

  const { credential, connection } = result.body;
  if (!CREDENTIAL_PATTERN.test(credential)) {
    fail("TokenTimer returned something that is not a valid credential. Revoke the new connection and start again.");
    return 1;
  }

  let stored;
  try {
    // Bound to this server, so the file can never be released to another.
    stored = store(file, credential, { replace: options.replace, binding: serverAddressOf(config) });
  } catch (error) {
    // The code is spent and the credential exists only in memory. Say exactly
    // what happened and how to recover, without echoing anything sensitive.
    const detail = error instanceof CredentialStoreError ? ` ${error.message}.` : "";
    fail(
      `Setup succeeded but the credential could not be saved.${detail} ` +
        "Revoke the new connection in TokenTimer and run setup again with a new code.",
    );
    return 1;
  }

  const expires = connection && typeof connection.expiresAt === "string" ? connection.expiresAt : null;
  say("Connected.");
  say(`  Connection: ${connection && typeof connection.name === "string" ? JSON.stringify(connection.name) : "(unnamed)"}`);
  if (expires) say(`  Expires:    ${expires}`);
  say(`  Credential: stored in ${stored}`);
  say("");
  say("Add this to your assistant's MCP configuration:");
  say(clientSnippet({ apiUrl: config.origin + config.basePath, file: stored }));
  return 0;
}

module.exports = { USAGE, parseArgs, runEnroll, UsageError, REDEEM_MESSAGES, UNKNOWN_OUTCOME };
