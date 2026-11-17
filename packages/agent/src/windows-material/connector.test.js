"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const {
  createWindowsConnector,
  validateWindowsBinding,
  validateWindowsKey,
} = require("./index");
const { readProtectedFile } = require("../material-store");
const binding = {
  connector: "windows-material-iis-v1",
  serviceAccountSids: [],
  target: {
    type: "windows-iis",
    reference: "iis-customer",
    store: "My",
    binding: {
      site: "Customer",
      address: "127.0.0.1",
      port: 443,
      sniHost: "valid.example.com",
      store: "My",
    },
  },
  probes: [{ dialAddress: "127.0.0.1", port: 443, sni: "valid.example.com" }],
};

test("Windows IIS accepts qualified key algorithms and rejects P-521 before native execution", () => {
  for (const namedCurve of ["prime256v1", "secp384r1", "secp521r1"]) {
    const { publicKey } = crypto.generateKeyPairSync("ec", { namedCurve });
    if (namedCurve === "secp521r1")
      assert.throws(() => validateWindowsKey(publicKey), {
        code: "material_windows_algorithm_unsupported",
      });
    else assert.doesNotThrow(() => validateWindowsKey(publicKey));
  }
  const { publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  assert.doesNotThrow(() => validateWindowsKey(publicKey));
});

test("activation reports bounded conflict and inventory errors without exposing details", async (t) => {
  const stateDir=fs.mkdtempSync(path.join(os.tmpdir(),"tt-win-conflict-"));
  t.after(() => fs.rmSync(stateDir,{recursive:true,force:true}));
  for (const [reason, expected] of [
    ["WILDCARD_PRECEDENCE_CONFLICT","material_windows_wildcard_conflict"],
    ["QUERY_FAILED","material_windows_binding_inventory_unavailable"],
    ["BIND_FAILED","material_windows_activation_failed"],
  ]) {
    let calls=0;
    const connector=createWindowsConnector({binding,stateDir,
      execFileImpl:(_file,_args,_options,callback)=>{calls++;callback(null,JSON.stringify({ok:true}),"");},
      deployBinding:async()=>({ok:false,code:reason,detail:"sensitive-address-canary"}),
    });
    await assert.rejects(connector.activate({certificatePem:"unused"}), error => {
      assert.equal(error.code,expected);
      assert.doesNotMatch(error.message,/sensitive-address-canary/);
      return true;
    });
    assert.equal(calls,1,"commit is not attempted after a rejected bind");
  }
});
test("verification refuses a wildcard masked by a conflicting specific IP without activating", async (t) => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-win-verify-mask-"));
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  const certificatePem = fs.readFileSync(path.join(__dirname, "../verify/fixtures/selfsigned.crt.pem"), "utf8");
  const thumbprint = new crypto.X509Certificate(certificatePem).fingerprint.replace(/:/g, "");
  const items = [["0.0.0.0:443", thumbprint], ["10.2.3.4:443", "AA".repeat(20)]].map(([key, hash]) =>
    ({ kind: "SslBindingInfo", key, values: { SslCertHash: Array.from(Buffer.from(hash, "hex")) } }));
  const target = { ...binding, target: { ...binding.target, binding: { ...binding.target.binding, address: "*", sniHost: undefined } } };
  let activations = 0;
  const connector = createWindowsConnector({ binding: target, stateDir,
    deployBinding: async () => { activations++; throw new Error("must not activate"); },
    execFileImpl: (_file, args, _options, callback) => callback(null,
      JSON.stringify(String(args.at(-1)).includes("SslBindingInfo") ? { items } : { ok: true }), ""),
  });
  assert.equal(await connector.verify({ certificatePem, fingerprintSha256: "a".repeat(64) }), false);
  assert.equal(activations, 0);
});
test("Windows connector permits only the exact typed IIS rebind surface", () => {
  const policy = {
    checkTargetScope: (ref) => ({ allowed: ref === "iis-customer" }),
  };
  assert.doesNotThrow(() => validateWindowsBinding(binding, policy));
  for (const change of [
    { activationMode: "restart" },
    { connector: "powershell" },
    { serviceAccountSids: ["S-1-5-11"] },
    {
      target: {
        ...binding.target,
        store: "Root",
        binding: { ...binding.target.binding, store: "Root" },
      },
    },
    { target: { ...binding.target, reference: "other-customer" } },
    { probes: [{ ...binding.probes[0], port: 8443 }] },
  ])
    assert.throws(() =>
      validateWindowsBinding({ ...binding, ...change }, policy),
    );
});
test("fixed Windows helper receives only a protected file path; errors and outputs cannot expose staging", async (t) => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-win-connector-"));
  t.after(() => fs.rmSync(stateDir, { recursive: true, force: true }));
  let input,
    fail = false;
  const connector = createWindowsConnector({
    binding,
    stateDir,
    execFileImpl: (file, args, options, callback) => {
      assert.equal(path.win32.isAbsolute(file), true);
      assert.ok(file.endsWith("powershell.exe"));
      assert.ok(args.includes("-File"));
      assert.equal(args.includes("-Command"), false);
      assert.equal(args.includes("-EncodedCommand"), false);
      assert.equal(options.windowsHide, true);
      input = args.at(-1);
      const value = JSON.parse(readProtectedFile(input));
      assert.equal(value.operation, "preflight");
      assert.equal(value.binding.site, "Customer");
      if (fail)
        callback(
          new Error("private-password-canary"),
          "",
          "private-password-canary",
        );
      else
        callback(
          null,
          JSON.stringify({ ok: true, password: "private-password-canary" }),
        );
    },
  });
  assert.deepEqual(await connector.preflight(), { ok: true });
  assert.equal(fs.existsSync(input), false);
  fail = true;
  await assert.rejects(
    connector.preflight(),
    (error) =>
      error.code === "material_windows_preflight_failed" &&
      !error.message.includes("canary"),
  );
  assert.equal(fs.existsSync(input), false);
});
