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

function hashPlan({ operation, workspaceId, connectionId, subjectId, boundFingerprint, boundProfileId, intentHash, effect }) {
  // Everything the plan is bound to is inside the hash, so a plan cannot be
  // replayed against another certificate, connection or workspace.
  // Advisory availability warnings do not change the authorized effect. A
  // pause/resume must block/defer work, not invalidate otherwise valid consent.
  const { warnings: _warnings, ...resolvedEffect } = effect;
  const body = JSON.stringify(
    canonicalize({ operation, workspaceId, connectionId, subjectId, boundFingerprint, boundProfileId, intentHash, effect: resolvedEffect }),
  );
  return crypto.createHash("sha256").update(body, "utf8").digest("hex");
}

// The material version identifier is allocated per deliberate submission.
// Everything that determines execution, including the profile snapshot and
// publication destination/revision, remains bound to the preview.
function hashRenewalIntent(payload) {
  const intent = { ...payload };
  if (intent.publication) {
    intent.publication = { ...intent.publication };
    delete intent.publication.materialVersionId;
  }
  return crypto.createHash("sha256").update(JSON.stringify(canonicalize(intent)), "utf8").digest("hex");
}

// The workspace policy decides whether this submission needs another person.
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
    approvalAuthority: requireApprovalAlways === true ? "other_manager_or_admin" : "none",
    warnings,
    target: {
      commonName: untrustedText(certificate.common_name),
      notAfter: certificate.not_after ? new Date(certificate.not_after).toISOString() : null,
    },
  };
}

module.exports = { APPROVAL_TTL_MS, PLAN_TTL_MS, canonicalize, hashPlan, hashRenewalIntent, renewEffect };
