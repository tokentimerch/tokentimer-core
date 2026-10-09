"use strict";

// Real-host verification for real machine-store listing, the real http.sys
// binding query (full list, both IP- and hostname-keyed bindings), real
// cross-referenced inventory, and agreement between that query and raw
// `netsh http show sslcert` output on an English-language host.
//
// Usage: node windows-discovery-inventory.js <workDir>

const path = require("node:path");
const fs = require("node:fs");
const { execFileSync } = require("node:child_process");

const {
  listMachineStoreCertificates,
  listHttpSysBindings,
  discoverWindowsCertificateInventory,
} = require("C:\\TokenTimerAgentTest\\src\\windows-discovery\\index.js");

async function main() {
  const workDir = process.argv[2] || "C:\\TokenTimerAgentTest\\work";

  console.log("=== real machine store My listing ===");
  const storeResult = await listMachineStoreCertificates({ store: "My" });
  if (!storeResult.ok) {
    console.log("FAIL: listMachineStoreCertificates failed ->", JSON.stringify(storeResult));
    process.exitCode = 1;
    return;
  }
  console.log(`parsed ${storeResult.certificates.length} certificate(s) from the real store`);
  fs.writeFileSync(path.join(workDir, "discovery-store.json"), JSON.stringify(storeResult, null, 2));

  const cngCert = storeResult.certificates.find((c) => c.thumbprint === "DAA61C502810CA0952DF77A0D4194C32085B5ABD");
  if (!cngCert) {
    console.log("FAIL: could not find the real CNG-issued cert in the parsed store output");
    process.exitCode = 1;
  } else {
    console.log("OK: found the real CA-issued cert, parsed record:", JSON.stringify(cngCert));
    if (cngCert.hasPrivateKey !== true) {
      console.log("FAIL: expected hasPrivateKey:true for a CNG-enrolled cert with its key in the store");
      process.exitCode = 1;
    } else {
      console.log("OK: hasPrivateKey correctly true, read from the store's own HasPrivateKey flag");
    }
  }

  console.log("");
  console.log("=== command audit: confirm no key-export attempt was made during discovery ===");
  const auditedCalls = [];
  const auditingExecFileImpl = (file, args, opts, cb) => {
    auditedCalls.push([file, ...args].join(" "));
    return require("node:child_process").execFile(file, args, opts, cb);
  };
  await listMachineStoreCertificates({ store: "My", execFileImpl: auditingExecFileImpl });
  console.log("commands run:", auditedCalls.join(" | "));
  const hasExportAttempt = auditedCalls.some((c) => /-exportpfx|-exportcert|Export-P?fxCertificate/i.test(c));
  if (hasExportAttempt) {
    console.log("FAIL: an export-related command was issued during discovery");
    process.exitCode = 1;
  } else {
    console.log("OK: no key-export command anywhere in the audit trail");
  }

  console.log("");
  console.log("=== real http.sys binding query (full list) ===");
  const bindingsResult = await listHttpSysBindings();
  if (!bindingsResult.ok) {
    console.log("FAIL: listHttpSysBindings failed ->", JSON.stringify(bindingsResult));
    process.exitCode = 1;
    return;
  }
  console.log(`parsed ${bindingsResult.bindings.length} binding(s):`, JSON.stringify(bindingsResult.bindings, null, 2));
  fs.writeFileSync(path.join(workDir, "discovery-bindings.json"), JSON.stringify(bindingsResult, null, 2));

  console.log("");
  console.log("=== independent ground truth: raw netsh http show sslcert (full, unfiltered) ===");
  const rawNetsh = execFileSync("netsh", ["http", "show", "sslcert"], { encoding: "utf8" });
  fs.writeFileSync(path.join(workDir, "discovery-raw-netsh.txt"), rawNetsh);
  const rawIpPortCount = (rawNetsh.match(/^\s*IP:port\s*:/gm) || []).length;
  const rawHostnamePortCount = (rawNetsh.match(/^\s*Hostname:port\s*:/gm) || []).length;
  console.log(`raw netsh output contains ${rawIpPortCount} "IP:port" block(s) and ${rawHostnamePortCount} "Hostname:port" block(s)`);

  console.log("");
  console.log("=== agreement check: binding query vs raw netsh ===");
  const queried = bindingsResult.bindings;
  const ipPortCount = queried.filter((b) => b.keyedBy === "ipport").length;
  const hostnamePortCount = queried.filter((b) => b.keyedBy === "hostnameport").length;
  const rawThumbprints = (rawNetsh.match(/\b[0-9a-f]{40}\b/gi) || []).map((t) => t.toUpperCase()).sort();
  const queriedThumbprints = queried.map((b) => b.thumbprint).sort();
  if (rawIpPortCount + rawHostnamePortCount === 0 && queried.length > 0) {
    console.log("NOTE: raw netsh output has no English labels (non-English host); counts not compared");
  } else if (ipPortCount !== rawIpPortCount || hostnamePortCount !== rawHostnamePortCount) {
    console.log(
      `FAIL: the query found ${ipPortCount} IP-keyed and ${hostnamePortCount} hostname-keyed binding(s), ` +
        `netsh shows ${rawIpPortCount} and ${rawHostnamePortCount}`,
    );
    process.exitCode = 1;
  } else {
    console.log("OK: the query and netsh agree on the number of bindings of each kind");
  }
  if (JSON.stringify(rawThumbprints) !== JSON.stringify(queriedThumbprints)) {
    console.log("FAIL: certificate hashes differ ->", JSON.stringify({ rawThumbprints, queriedThumbprints }));
    process.exitCode = 1;
  } else {
    console.log("OK: the query and netsh report the same certificate hashes");
  }

  console.log("");
  console.log("=== real cross-referenced inventory ===");
  const inventoryResult = await discoverWindowsCertificateInventory({ store: "My" });
  if (!inventoryResult.ok) {
    console.log("FAIL: discoverWindowsCertificateInventory failed ->", JSON.stringify(inventoryResult));
    process.exitCode = 1;
    return;
  }
  fs.writeFileSync(path.join(workDir, "discovery-inventory.json"), JSON.stringify(inventoryResult, null, 2));
  const cngInv = inventoryResult.certificates.find((c) => c.thumbprint === "DAA61C502810CA0952DF77A0D4194C32085B5ABD");
  console.log("real CA-issued cert's cross-referenced boundAt:", JSON.stringify(cngInv && cngInv.boundAt));
  if (!cngInv || !cngInv.boundAt.includes("0.0.0.0:8443")) {
    console.log("FAIL: expected boundAt to include 0.0.0.0:8443 (the real IIS bind-verify target)");
    process.exitCode = 1;
  } else {
    console.log("OK: cross-referenced inventory correctly shows the cert bound at 0.0.0.0:8443");
  }
  if (!cngInv || !cngInv.boundAt.includes("0.0.0.0:9443")) {
    console.log("NOTE: 9443 not present in boundAt for this cert (expected -- 9443 uses a different cert)");
  }
}

main().catch((err) => {
  console.error("UNCAUGHT ERROR:", err);
  process.exitCode = 1;
});
