"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { Readable } = require("node:stream");
const { UNKNOWN_OUTCOME, REDEEM_MESSAGES, parseArgs, runEnroll, UsageError } = require("./enroll");
const { CredentialStoreError } = require("./credentialStore");

const GRANT = `ttopg_${"0123456789abcdef"}_${"c".repeat(64)}`;
const CREDENTIAL = `ttopc_${"fedcba9876543210"}_${"d".repeat(64)}`;
const API = "https://tokentimer.example.com";

let dir;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-mcp-enroll-"));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function sink() {
  const chunks = [];
  return { write: (text) => chunks.push(String(text)), text: () => chunks.join("") };
}

function pipedInput(text) {
  const stream = Readable.from([Buffer.from(text)]);
  stream.isTTY = false;
  return stream;
}

function reply(status, body, { headers = {} } = {}) {
  return () =>
    Promise.resolve(
      new Response(typeof body === "string" ? body : JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json", ...headers },
      }),
    );
}

const success = reply(201, {
  connection: { id: "550e8400-e29b-41d4-a716-446655440001", name: "laptop", expiresAt: "2026-11-18T12:00:00.000Z" },
  credential: CREDENTIAL,
});

async function enroll({ argv, input = `${GRANT}\n`, fetchImpl = success, env = {}, extra = {} } = {}) {
  const stdout = sink();
  const stderr = sink();
  const calls = [];
  const file = path.join(dir, "credential");
  const code = await runEnroll({
    argv: argv || ["--api-url", API, "--credential-file", file],
    env: { PATH: process.env.PATH, ...env },
    stdin: pipedInput(input),
    stdout,
    stderr,
    fetchImpl: (url, options) => {
      calls.push({ url: String(url), options });
      return fetchImpl(url, options);
    },
    readSecret: () => Promise.reject(new Error("a piped run must not prompt")),
    ...extra,
  });
  return { code, stdout: stdout.text(), stderr: stderr.text(), calls, file };
}

const noSecrets = (result) => {
  for (const text of [result.stdout, result.stderr]) {
    assert.ok(!text.includes(GRANT), "the setup code was printed");
    assert.ok(!text.includes(CREDENTIAL), "the credential was printed");
    assert.ok(!text.includes("c".repeat(20)) && !text.includes("d".repeat(20)), "secret material was printed");
  }
};

describe("enroll: arguments", () => {
  it("parses the flags in both spellings", () => {
    assert.deepEqual(parseArgs(["--api-url", API, "--credential-file", "/x", "--replace"]), {
      apiUrl: API,
      credentialFile: "/x",
      replace: true,
      help: false,
    });
    assert.deepEqual(parseArgs([`--api-url=${API}`, "--credential-file=/y"]), {
      apiUrl: API,
      credentialFile: "/y",
      replace: false,
      help: false,
    });
    assert.equal(parseArgs(["--help"]).help, true);
  });

  it("refuses a setup code on the command line and tells the person to treat it as exposed", () => {
    for (const argv of [[GRANT], ["--api-url", API, GRANT], [`--api-url=${GRANT}`]]) {
      assert.throws(() => parseArgs(argv), (error) => {
        assert.ok(error instanceof UsageError);
        assert.match(error.message, /Do not pass the setup code as an argument/);
        assert.match(error.message, /revoke it/);
        assert.ok(!error.message.includes(GRANT), "and the message must not repeat it");
        return true;
      });
    }
  });

  it("rejects unknown flags, stray words and missing values", () => {
    for (const argv of [["--nope"], ["extra"], ["--api-url"], ["--api-url", "--replace"], ["--credential-file"]]) {
      assert.throws(() => parseArgs(argv), UsageError, JSON.stringify(argv));
    }
  });

  it("shows usage and exits 2 on a bad argument, without reading input or calling the network", async () => {
    const result = await enroll({ argv: [GRANT] });
    assert.equal(result.code, 2);
    assert.match(result.stderr, /Usage: tokentimer-mcp enroll/);
    assert.equal(result.calls.length, 0);
    noSecrets(result);
  });

  it("prints help and exits 0", async () => {
    const result = await enroll({ argv: ["--help"] });
    assert.equal(result.code, 0);
    assert.match(result.stdout, /one-time setup code/);
  });
});

describe("enroll: a successful setup", () => {
  it("redeems once, stores the credential, and prints neither secret", async () => {
    const result = await enroll();
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.calls.length, 1);
    assert.equal(result.calls[0].url, `${API}/api/v1/operator/enroll/redeem`);
    assert.equal(result.calls[0].options.method, "POST");
    assert.equal(result.calls[0].options.redirect, "error");
    assert.equal(result.calls[0].options.headers.Authorization, `Bearer ${GRANT}`);
    assert.equal(fs.readFileSync(result.file, "utf8"), `${CREDENTIAL}\n`);
    assert.match(result.stdout, /Connected\./);
    assert.match(result.stdout, /"laptop"/);
    assert.match(result.stdout, /2026-11-18/);
    noSecrets(result);
  });

  it("prints a client configuration that points at the file, not at the secret", async () => {
    const result = await enroll();
    const start = result.stdout.indexOf("{");
    const snippet = JSON.parse(result.stdout.slice(start));
    const server = snippet.mcpServers.tokentimer;
    assert.equal(server.command, "tokentimer-mcp");
    assert.equal(server.env.TOKENTIMER_API_URL, API);
    assert.equal(server.env.TOKENTIMER_MCP_CREDENTIAL_FILE, path.resolve(result.file));
    assert.ok(!("TOKENTIMER_MCP_CREDENTIAL" in server.env), "the secret must not be in client config");
  });

  it("reads the code from the first line of piped input, ignoring the rest", async () => {
    const result = await enroll({ input: `${GRANT}\nignored garbage\n` });
    assert.equal(result.code, 0);
    assert.equal(result.calls[0].options.headers.Authorization, `Bearer ${GRANT}`);
    // A second run needs its own file: the first one now exists and is protected.
    const crlf = await enroll({
      input: `${GRANT}\r\n`,
      argv: ["--api-url", API, "--credential-file", path.join(dir, "second-credential")],
    });
    assert.equal(crlf.code, 0);
  });

  it("prompts for the code only on an interactive terminal, and uses the hidden prompt", async () => {
    const prompts = [];
    const tty = Readable.from([]);
    tty.isTTY = true;
    const result = await enroll({
      extra: {
        stdin: tty,
        readSecret: (prompt) => {
          prompts.push(prompt);
          return Promise.resolve(`  ${GRANT}  `);
        },
      },
    });
    assert.equal(result.code, 0);
    assert.equal(prompts.length, 1);
    assert.match(prompts[0], /hidden/);
  });

  it("takes the address from the environment when no flag is given", async () => {
    const result = await enroll({
      argv: ["--credential-file", path.join(dir, "credential")],
      env: { TOKENTIMER_API_URL: API },
    });
    assert.equal(result.code, 0);
    assert.ok(result.calls[0].url.startsWith(API));
  });
});

describe("enroll: failures before the code is spent", () => {
  it("refuses a plain-http address (except localhost) and never sends the code", async () => {
    const result = await enroll({ argv: ["--api-url", "http://tokentimer.example.com", "--credential-file", path.join(dir, "c")] });
    assert.equal(result.code, 2);
    assert.match(result.stderr, /https/);
    assert.equal(result.calls.length, 0);
    noSecrets(result);
    const local = await enroll({ argv: ["--api-url", "http://localhost:4000", "--credential-file", path.join(dir, "c2")] });
    assert.equal(local.code, 0);
  });

  it("refuses a missing or malformed code without calling the network", async () => {
    for (const input of ["", "\n", "not-a-code\n", `${GRANT}x\n`, `ttopc_${"a".repeat(16)}_${"b".repeat(64)}\n`, GRANT.slice(0, -1)]) {
      const result = await enroll({ input });
      assert.equal(result.code, 1, JSON.stringify(input));
      assert.match(result.stderr, /not valid/);
      assert.equal(result.calls.length, 0, JSON.stringify(input));
    }
  });

  it("stops before spending the code if the credential file already exists, and leaves it alone", async () => {
    const file = path.join(dir, "credential");
    fs.writeFileSync(file, "EXISTING\n");
    const result = await enroll({ argv: ["--api-url", API, "--credential-file", file] });
    assert.equal(result.code, 2);
    assert.match(result.stderr, /already exists/);
    assert.equal(result.calls.length, 0, "the one-time code must not be burned on a path problem");
    assert.equal(fs.readFileSync(file, "utf8"), "EXISTING\n");
    const replaced = await enroll({ argv: ["--api-url", API, "--credential-file", file, "--replace"] });
    assert.equal(replaced.code, 0);
    assert.equal(fs.readFileSync(file, "utf8"), `${CREDENTIAL}\n`);
  });

  it("stops before spending the code if the location is unusable", async () => {
    const blocker = path.join(dir, "blocker");
    fs.writeFileSync(blocker, "x");
    const result = await enroll({ argv: ["--api-url", API, "--credential-file", path.join(blocker, "credential")] });
    assert.equal(result.code, 2);
    assert.equal(result.calls.length, 0);
  });
});

describe("enroll: the server refuses", () => {
  const cases = [
    [401, "OPERATOR_ENROLLMENT_INVALID"],
    [409, "OPERATOR_ENROLLMENT_USED"],
    [410, "OPERATOR_ENROLLMENT_EXPIRED"],
    [410, "OPERATOR_ENROLLMENT_REVOKED"],
    [403, "OPERATOR_ENROLLMENT_AUTHORITY_LOST"],
    [429, "OPERATOR_ENROLLMENT_RATE_LIMITED"],
  ];
  for (const [status, code] of cases) {
    it(`explains ${code} in fixed words, stores nothing and prints no secret`, async () => {
      const result = await enroll({ fetchImpl: reply(status, { error: "SERVER_TEXT_SENTINEL", code }) });
      assert.equal(result.code, 1);
      assert.ok(result.stderr.includes(REDEEM_MESSAGES[code]), result.stderr);
      assert.ok(!result.stderr.includes("SERVER_TEXT_SENTINEL"), "the server's text must never be shown");
      assert.equal(fs.existsSync(result.file), false);
      noSecrets(result);
    });
  }

  it("says the interface is off on a 404, and falls back to a generic line for anything unknown", async () => {
    const off = await enroll({ fetchImpl: reply(404, { error: "SENTINEL", code: "OPERATOR_INTERFACE_DISABLED" }) });
    assert.match(off.stderr, /not have the assistant interface turned on/);
    const odd = await enroll({ fetchImpl: reply(500, { error: "SENTINEL", code: "SOMETHING_NEW" }) });
    assert.equal(odd.code, 1);
    assert.match(odd.stderr, /could not complete setup/);
    assert.ok(!odd.stderr.includes("SENTINEL") && !odd.stderr.includes("SOMETHING_NEW"));
    const html = await enroll({ fetchImpl: reply(502, "<html>bad gateway</html>") });
    assert.equal(html.code, 1);
    assert.ok(!html.stderr.includes("html"));
  });
});

describe("enroll: when the outcome is unknown", () => {
  it("says so and explains how to recover, for a network failure", async () => {
    const result = await enroll({ fetchImpl: () => Promise.reject(new TypeError("fetch failed: ECONNRESET")) });
    assert.equal(result.code, 1);
    assert.ok(result.stderr.includes(UNKNOWN_OUTCOME));
    assert.match(result.stderr, /revoke it/);
    assert.ok(!result.stderr.includes("ECONNRESET"));
    assert.equal(fs.existsSync(result.file), false);
  });

  it("treats a timeout, a cut-off reply and an unreadable success the same way", async () => {
    for (const fetchImpl of [
      () => Promise.reject(Object.assign(new Error("t"), { name: "TimeoutError" })),
      reply(201, "not json at all"),
      reply(200, { ok: true }),
      reply(201, { connection: {}, credential: 42 }),
    ]) {
      const result = await enroll({ fetchImpl });
      assert.equal(result.code, 1);
      assert.ok(result.stderr.includes(UNKNOWN_OUTCOME), result.stderr);
    }
  });

  it("does not retry: the one-time code is sent at most once", async () => {
    const result = await enroll({ fetchImpl: () => Promise.reject(new Error("boom")) });
    assert.equal(result.calls.length, 1);
  });

  it("refuses to store something that is not a connection credential", async () => {
    const result = await enroll({ fetchImpl: reply(201, { connection: { name: "x" }, credential: `ttopg_${"a".repeat(16)}_${"b".repeat(64)}` }) });
    assert.equal(result.code, 1);
    assert.match(result.stderr, /not a valid credential/);
    assert.equal(fs.existsSync(result.file), false);
  });
});

describe("enroll: the code is spent but the credential cannot be saved", () => {
  it("says exactly that, names how to recover, and still prints no secret", async () => {
    const result = await enroll({
      extra: {
        store: () => {
          throw new CredentialStoreError("The credential file could not be written safely");
        },
      },
    });
    assert.equal(result.code, 1);
    assert.match(result.stderr, /Setup succeeded but the credential could not be saved/);
    assert.match(result.stderr, /Revoke the new connection/);
    assert.equal(result.calls.length, 1);
    noSecrets(result);
  });

  it("does not leak an unexpected error's text", async () => {
    const result = await enroll({
      extra: {
        store: () => {
          throw new Error(`EACCES: permission denied, open '/secret/path' ${CREDENTIAL}`);
        },
      },
    });
    assert.equal(result.code, 1);
    assert.ok(!result.stderr.includes("/secret/path"));
    noSecrets(result);
  });
});
