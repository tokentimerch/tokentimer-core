"use strict";
// Supporting identity parser tests only; no native discovery qualification.
const test = require("node:test");
const assert = require("node:assert/strict");
const {
  parseUnprivilegedIdentity,
  verifyObservedScans,
} = require("../tests/e2e/helpers/certops-native-file-discovery");
function status(
  uid = "1001 1001 1001 1001",
  gid = "1002 1002 1002 1002",
  cap = "0000000000000000",
) {
  return `Name:\tnode\nUid:\t${uid}\nGid:\t${gid}\nCapEff:\t${cap}\n`;
}
test("native discovery requires all four unprivileged UID/GID identities and zero capabilities", () => {
  assert.deepEqual(parseUnprivilegedIdentity(status(), 1001, 1002), {
    uid: 1001,
    gid: 1002,
    effectiveCapabilities: "0",
  });
});
test("root, filesystem-UID bypass, capability, missing and duplicate identity fields refuse", () => {
  for (const value of [
    status("0 0 0 0"),
    status("1001 1001 1001 0"),
    status(undefined, "1002 1002 0 1002"),
    status(undefined, undefined, "0000000000000002"),
    status().replace(/^Uid:.*\n/m, ""),
    status() + "Uid:\t1001 1001 1001 1001\n",
  ]) {
    assert.throws(() => parseUnprivilegedIdentity(value, 1001, 1002));
  }
  assert.throws(() => parseUnprivilegedIdentity(status("0 0 0 0"), 0, 1002));
});

function observations() {
  const positiveFingerprint = "a".repeat(64),
    negativeFingerprint = "b".repeat(64);
  const positivePath = "/owned/discovery/server.crt",
    agentId = "owned-agent";
  return {
    positiveFingerprint,
    negativeFingerprint,
    positivePath,
    agentId,
    targetHost: "host",
    preparedAt: "2026-10-15T10:00:00.000Z",
    rows: [1, 2].map((second) => ({
      observed_at: `2026-10-15T10:00:0${second}.000Z`,
      metadata: {
        agentId,
        targetHost: "host",
        filePath: positivePath,
        fingerprintSha256: positiveFingerprint,
      },
    })),
    inventory: {
      pagination: { limit: 100, offset: 0, total: 1 },
      items: [
        {
          fingerprintSha256: positiveFingerprint,
          locations: [
            {
              locationKind: "filesystem",
              sourceRef: `${agentId}/host/${positivePath}`,
            },
          ],
        },
      ],
    },
  };
}
test("scan oracle requires repeated positive evidence and exact public inventory location", () => {
  assert.equal(verifyObservedScans(observations()).positiveScanCount, 2);
  for (const mutate of [
    (value) => {
      value.rows.pop();
    },
    (value) => {
      value.rows[1].observed_at = value.rows[0].observed_at;
    },
    (value) => {
      value.rows[0].metadata.filePath = "/foreign/server.crt";
    },
    (value) => {
      value.rows[0].metadata.agentId = "foreign-agent";
    },
    (value) => {
      value.rows[0].metadata.targetHost = "foreign-host";
    },
    (value) => {
      value.inventory.items[0].locations[0].sourceRef = `${value.agentId}/foreign-host/${value.positivePath}`;
    },
    (value) => {
      value.rows.push({
        metadata: { fingerprintSha256: value.negativeFingerprint },
      });
    },
    (value) => {
      value.inventory.items = [];
    },
    (value) => {
      value.inventory.pagination.total = 101;
    },
    (value) => {
      value.inventory.pagination.offset = 100;
    },
    (value) => {
      value.inventory.items[0].locations[0].sourceRef =
        "foreign-agent/host/elsewhere";
    },
    (value) => {
      value.inventory.items.push({
        fingerprintSha256: value.negativeFingerprint,
      });
    },
  ]) {
    const value = observations();
    mutate(value);
    assert.throws(() => verifyObservedScans(value));
  }
});
