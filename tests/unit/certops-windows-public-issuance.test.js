"use strict";
/* Portable API payload and report-oracle checks only. The production request
 * normalizer must accept all five Windows profiles without a filesystem path;
 * the actual authenticated HTTP and native CNG/IIS journey runs elsewhere. */
const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const {
  buildPublicWindowsIssue,
  verifyPublicIssuanceFacts,
} = require("../e2e/helpers/certops-windows-public-issuance");
const {
  normalizeIssuanceRequest,
} = require("../../apps/api/services/certops/issuance");
const facts = () => ({
  anonymousAdmissionRefused: true,
  viewerAdmissionRefused: true,
  authorizedAdmissionCreated: true,
  authorizedRole: "workspace_manager",
  idempotentSameJob: true,
  publicRequesterPreserved: true,
  serverDerivedOsStoreKeyMode: true,
  publicPayloadPreserved: true,
  nativeJobSucceeded: true,
  nativeCngIisTrustedTlsVerified: true,
  ownedActorCleanup: true,
  anonymousStatus: 403,
  viewerStatus: 403,
  createStatus: 201,
  replayStatus: 201,
  source: "api",
  mode: "real",
});
test("public Windows issue payloads follow actual API store binding contract for all profiles", () => {
  for (const keyProfile of [
    { keyAlgorithm: "rsa", keySize: 2048 },
    { keyAlgorithm: "rsa", keySize: 3072 },
    { keyAlgorithm: "rsa", keySize: 4096 },
    { keyAlgorithm: "ecdsa", keySize: 256 },
    { keyAlgorithm: "ecdsa", keySize: 384 },
  ]) {
    const input = buildPublicWindowsIssue({
      workspaceId: "02c23288-dd32-4c9d-9020-44359bdc0119",
      keyProfile,
      domain: "owned.example.test",
      site: "Owned fixture",
      port: 24443,
      caEndpoint: "https://127.0.0.1:14000/dir",
    });
    assert.equal(
      input.route,
      "/api/v1/workspaces/02c23288-dd32-4c9d-9020-44359bdc0119/certops/jobs",
    );
    assert.equal(input.body.operation, "issue");
    assert.deepEqual(input.body.payload.keyAlgorithm, keyProfile.keyAlgorithm);
    const value = normalizeIssuanceRequest(input.body);
    assert.equal(value.targetType, "windows-iis");
    assert.equal(value.certPath, null);
    assert.equal(value.windowsTarget.store, "My");
    assert.deepEqual(value.windowsTarget.binding, {
      site: "Owned fixture",
      port: 24443,
      sniHost: "owned.example.test",
    });
    assert.equal(input.body.payload.keyMode, undefined);
    assert.equal(input.body.payload.certificateId, undefined);
    assert.throws(() =>
      normalizeIssuanceRequest({
        ...input.body,
        payload: { ...input.body.payload, certPath: "C:/injected.pem" },
      }),
    );
    assert.throws(() =>
      normalizeIssuanceRequest({
        ...input.body,
        payload: { ...input.body.payload, certificateId: "client-assigned" },
      }),
    );
  }
});
test("public Windows evidence cannot omit admission requester native verification or cleanup", () => {
  assert.equal(verifyPublicIssuanceFacts(facts()), true);
  for (const change of [
    { authorizedRole: "admin" },
    { authorizedAdmissionCreated: false },
    { viewerStatus: 201 },
    { createStatus: 202 },
    { anonymousStatus: 200 },
    { idempotentSameJob: false },
    { publicRequesterPreserved: false },
    { serverDerivedOsStoreKeyMode: false },
    { nativeCngIisTrustedTlsVerified: false },
    { ownedActorCleanup: false },
  ])
    assert.throws(() => verifyPublicIssuanceFacts({ ...facts(), ...change }));
});
test("Windows reporter refuses a legacy service-only journey with no admission proof", () => {
  const {
      windowsPublicIssueProof,
    } = require("../../scripts/certops-stack-reporter"),
    root = fs.mkdtempSync(
      path.join(os.tmpdir(), "certops-public-issue-proof-"),
    );
  try {
    const scope = "real-agent-windows-acme-iis/rsa-2048",
      name =
        "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence";
    assert.throws(() => windowsPublicIssueProof(scope, name, root));
    fs.mkdirSync(path.join(root, "qualification-results"));
    fs.writeFileSync(
      path.join(
        root,
        "qualification-results/windows-public-issue-rsa-2048.json",
      ),
      JSON.stringify(facts()),
    );
    assert.deepEqual(windowsPublicIssueProof(scope, name, root), facts());
    assert.equal(
      windowsPublicIssueProof("agent-protocol-api-worker", name, root),
      undefined,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
