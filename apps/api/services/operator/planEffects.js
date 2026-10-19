"use strict";

// What a renew request would do, as plain facts (ADR-0015 section 6).
//
// The effect is computed from the certificate and its stored renewal profile
// by the same materializer the dashboard's renew button uses, so a preview can
// never promise something the real path would refuse. It names no agent, path,
// key reference or free-form note, and it is hashed canonically so the
// submission can prove it is the thing that was previewed.

const crypto = require("node:crypto");
const { untrustedText } = require("./projections");

const PLAN_TTL_MS = 10 * 60 * 1000;
const APPROVAL_TTL_MS = 24 * 60 * 60 * 1000;

// Stable JSON: keys sorted at every level, so equal content always hashes equally.
function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.keys(value)
      .sort()
      .reduce((out, key) => {
        out[key] = canonicalize(value[key]);
        return out;
      }, {});
  }
  return value;
}

function hashPlan({ operation, workspaceId, connectionId, subjectId, boundFingerprint, boundProfileId, effect }) {
  // Everything the plan is bound to is inside the hash, so a plan cannot be
  // replayed against another certificate, connection or workspace.
  const body = JSON.stringify(
    canonicalize({ operation, workspaceId, connectionId, subjectId, boundFingerprint, boundProfileId, effect }),
  );
  return crypto.createHash("sha256").update(body, "utf8").digest("hex");
}

// Renewal needs approval by someone other than the requester. That is a
// property of every request from a connection, not of the certificate.
function renewEffect({ certificate, workspacePaused, requireApprovalAlways }) {
  const warnings = [];
  if (workspacePaused) warnings.push("CertOps is paused for this workspace, so a request cannot be submitted until it resumes.");
  if (requireApprovalAlways) warnings.push("This workspace requires approval for every job.");
  return {
    operation: "renew",
    lifecycleEffect: "renews_certificate",
    issuerEffect: "contacts_issuer",
    standingRenewal: {
      createsAutomaticRenewal: false,
      futureRenewalsNeedApproval: requireApprovalAlways === true,
    },
    approvalAuthority: "other_manager_or_admin",
    warnings,
    target: {
      commonName: untrustedText(certificate.commonName),
      notAfter: certificate.notAfter ? new Date(certificate.notAfter).toISOString() : null,
    },
  };
}

module.exports = { APPROVAL_TTL_MS, PLAN_TTL_MS, canonicalize, hashPlan, renewEffect };
