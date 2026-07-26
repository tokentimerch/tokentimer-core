"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  redactAuditTopologyForRole,
  AUDIT_TOPOLOGY_FIELDS_BY_ACTION,
} = require("../../apps/api/routes/workspaces.js")._test;

// Guards against the leak a third external review found: CERTOPS_RENEWAL_PROFILE_DERIVED
// and CERTOPS_CERTIFICATE_ISSUED carry the same deployment topology (certPath, caEndpoint,
// commandRef, DNS zone/provider, deployedCertPath) that the renewal-profile read routes
// gate behind workspace_manager. GET /api/v1/audit only requires membership, so a viewer
// could read that topology through the audit feed even though the profile routes refuse
// them. This is the read-time guard that closes that second, unguarded path.

function derivedRow(overrides = {}) {
  return {
    action: "CERTOPS_RENEWAL_PROFILE_DERIVED",
    metadata: {
      profileId: "profile-1",
      profileName: "Derived: app.example.com",
      commandRef: "issue.dns",
      caEndpoint: "https://acme-v02.api.letsencrypt.org/directory",
      certPath: "/etc/ssl/certs/app.pem",
      dnsProvider: "cloudflare",
      dnsZone: "example.com",
      keyAlgorithm: "ecdsa",
    },
    ...overrides,
  };
}

function issuedRow(overrides = {}) {
  return {
    action: "CERTOPS_CERTIFICATE_ISSUED",
    metadata: {
      managedCertificateId: "cert-1",
      commonName: "app.example.com",
      deployedCertPath: "/etc/ssl/certs/app.pem",
      fingerprintSha256: "abc123",
    },
    ...overrides,
  };
}

describe("audit topology redaction", () => {
  it("strips every field named for the row's action from a viewer's response", () => {
    const redacted = redactAuditTopologyForRole(derivedRow(), "viewer");

    for (const field of AUDIT_TOPOLOGY_FIELDS_BY_ACTION.CERTOPS_RENEWAL_PROFILE_DERIVED) {
      assert.equal(
        Object.prototype.hasOwnProperty.call(redacted.metadata, field),
        false,
        `${field} must not reach a viewer`,
      );
    }
    // Non-topology fields survive: the row is still useful for "what happened, to what".
    assert.equal(redacted.metadata.profileId, "profile-1");
    assert.equal(redacted.metadata.profileName, "Derived: app.example.com");
    assert.equal(redacted.metadata.keyAlgorithm, "ecdsa");
  });

  it("marks a redacted row rather than leaving an ambiguous absence", () => {
    const redacted = redactAuditTopologyForRole(derivedRow(), "viewer");
    assert.equal(redacted.metadata.topologyRedacted, true);
  });

  it("redacts CERTOPS_CERTIFICATE_ISSUED's deployedCertPath for a viewer", () => {
    const redacted = redactAuditTopologyForRole(issuedRow(), "viewer");

    assert.equal(
      Object.prototype.hasOwnProperty.call(redacted.metadata, "deployedCertPath"),
      false,
    );
    assert.equal(redacted.metadata.commonName, "app.example.com");
  });

  it("leaves a manager's response untouched", () => {
    const row = derivedRow();
    const redacted = redactAuditTopologyForRole(row, "workspace_manager");

    assert.deepEqual(redacted, row);
  });

  it("leaves an admin's response untouched", () => {
    const row = issuedRow();
    const redacted = redactAuditTopologyForRole(row, "admin");

    assert.deepEqual(redacted, row);
  });

  it("passes through actions with no registered topology fields unchanged", () => {
    const row = {
      action: "CERTOPS_JOB_CREATED_MANUAL",
      metadata: { operation: "renew", subjectType: "managed_certificate" },
    };
    const redacted = redactAuditTopologyForRole(row, "viewer");

    assert.deepEqual(redacted, row);
  });

  it("does not throw on a row with no metadata", () => {
    const row = { action: "CERTOPS_RENEWAL_PROFILE_DERIVED", metadata: null };
    assert.deepEqual(redactAuditTopologyForRole(row, "viewer"), row);
  });

  it("does not mutate the original row or its metadata object", () => {
    const row = derivedRow();
    const originalMetadata = row.metadata;
    redactAuditTopologyForRole(row, "viewer");

    assert.equal(row.metadata, originalMetadata);
    assert.equal(row.metadata.certPath, "/etc/ssl/certs/app.pem");
  });
});
