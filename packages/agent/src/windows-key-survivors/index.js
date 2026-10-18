"use strict";
/** Metadata-only machine-store survivor guard for irreversible CNG key deletion.
 * Uses the shipped chain helper's Crypt32 mode; never opens private/hardware keys.
 * Missing helpers, malformed output, cancellation and incomplete enumeration defer.
 */
const { execFile } = require("node:child_process");
const { resolveAdcsChainHelperPath } = require("../issuers/chain-helper");
const { isAgentOwnedContainerName } = require("../windows-cert-store");
function validateResult(value) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("Invalid survivor result");
  for (const key of Object.keys(value))
    if (
      ![
        "complete",
        "shared",
        "storesScanned",
        "certificatesScanned",
        "matches",
        "reason",
      ].includes(key)
    )
      throw new Error("Unexpected survivor field");
  if (
    value.complete !== true ||
    typeof value.shared !== "boolean" ||
    value.reason !== undefined
  )
    throw new Error("Incomplete survivor inventory");
  for (const [field, max] of [
    ["storesScanned", 512],
    ["certificatesScanned", 100000],
    ["matches", 100000],
  ])
    if (
      !Number.isInteger(value[field]) ||
      value[field] < 0 ||
      value[field] > max
    )
      throw new Error("Unbounded survivor counts");
  if (
    value.storesScanned < 1 ||
    value.matches > value.certificatesScanned ||
    value.shared !== value.matches > 0
  )
    throw new Error("Inconsistent survivor result");
  return value;
}
async function inspectMachineKeySurvivors({
  containerName,
  store,
  thumbprint,
  signal,
  execFileImpl = execFile,
  helperPath,
  timeoutMs = 30000,
} = {}) {
  const hasExclusion = store !== undefined || thumbprint !== undefined;
  if (
    !isAgentOwnedContainerName(containerName) ||
    (hasExclusion &&
      (typeof store !== "string" ||
        !/^[A-Za-z0-9 _.-]{1,64}$/.test(store) ||
        /^\.+$/.test(store) ||
        typeof thumbprint !== "string" ||
        !/^[a-f0-9]{40}$/i.test(thumbprint)))
  )
    throw new TypeError("Invalid owned key reference");
  if (signal?.aborted) return { ok: false, shared: true, reason: "aborted" };
  const resolved = resolveAdcsChainHelperPath(
    helperPath ? { overridePath: helperPath } : {},
  );
  if (resolved.error)
    return { ok: false, shared: true, reason: "helper_unavailable" };
  return new Promise((resolve) => {
    try {
      execFileImpl(
        resolved.path,
        [
          "--key-survivors",
          "--container",
          containerName,
          ...(hasExclusion
            ? [
                "--exclude-store",
                store,
                "--exclude-thumbprint",
                thumbprint.toUpperCase(),
              ]
            : []),
        ],
        {
          windowsHide: true,
          timeout: timeoutMs,
          maxBuffer: 4096,
          ...(signal ? { signal } : {}),
        },
        (error, stdout) => {
          if (error || signal?.aborted) {
            resolve({
              ok: false,
              shared: true,
              reason: signal?.aborted ? "aborted" : "inventory_failed",
            });
            return;
          }
          try {
            const result = validateResult(JSON.parse(stdout));
            resolve({ ok: true, ...result });
          } catch {
            resolve({
              ok: false,
              shared: true,
              reason: "inventory_unreadable",
            });
          }
        },
      );
    } catch {
      resolve({ ok: false, shared: true, reason: "inventory_failed" });
    }
  });
}
module.exports = { inspectMachineKeySurvivors, validateResult };
