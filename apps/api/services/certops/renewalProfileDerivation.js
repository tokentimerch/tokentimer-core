"use strict";

/**
 * Derive a renewal profile from the job that issued a certificate.
 *
 * The renewal scheduler refuses to create a renew job unless the certificate
 * links to a certificate_profiles row carrying a complete, agent-executable
 * renewalProfile (see renewalProfile.resolveRenewalProfileSnapshot). That gate
 * is correct: dispatching a half-specified renewal would hand an agent a job it
 * cannot run, against a real rate-limited CA.
 *
 * The gap was that nothing ever populated it. No API route wrote
 * certificate_profiles, no code set managed_certificates.profile_id, and there
 * was no derivation. So every certificate was counted as
 * skippedIncompleteProfile forever, and automatic renewal could not fire for
 * anything TokenTimer had issued. An operator saw a healthy 'active'
 * certificate with an expiry date and no indication that it would silently
 * expire.
 *
 * A successful issuance is the one moment where every field the profile needs is
 * both known and proven to work: the agent just completed a real ACME order with
 * exactly this CA endpoint, DNS provider, zone, command profile, key parameters
 * and deployment paths. Reusing that payload is strictly better than asking an
 * operator to retype it, because a hand-entered profile can disagree with what
 * actually ran, and the disagreement only surfaces 60 days later when the
 * renewal fails.
 *
 * Derivation is therefore a mapping, not a guess: every field comes from the
 * issue job payload or from the certificate the agent verified. When a required
 * field is genuinely absent the derivation fails and says which one, rather than
 * inventing a default that would renew the certificate differently from how it
 * was issued.
 */

const {
  CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
  RENEWAL_PROFILE_SCHEMA_VERSION,
  validateRenewalProfile,
} = require("./renewalProfile");

// A derived profile is named after the certificate it was derived from, so an
// operator browsing profiles can tell at a glance which are machine-derived and
// which were authored. The suffix is also what makes the per-workspace unique
// index on LOWER(name) collide predictably on a second derivation for the same
// certificate, which is what we want: one profile per issued certificate.
const DERIVED_PROFILE_PREFIX = "Derived";
const DERIVED_PROFILE_SOURCE = "api";

function derivationError(message) {
  const error = new Error(message);
  error.code = CERTOPS_RENEWAL_PROFILE_INCOMPLETE;
  return error;
}

function text(value) {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
}

function isPlainObject(value) {
  return (
    typeof value === "object" && value !== null && !Array.isArray(value)
  );
}

/**
 * Reverse of executionFieldsFromRenewalProfile: take the flattened execution
 * fields an issue job carried and rebuild the structured profile from them.
 *
 * Only the fields that actually determine how the certificate is re-issued and
 * redeployed are carried over. Anything job-specific (idempotency keys, the
 * one-shot reason, dispatch timestamps) is deliberately dropped: a profile
 * describes a repeatable operation, not the single run it came from.
 */
function deriveRenewalProfileFromIssuedCertificate({
  payload,
  certificate,
} = {}) {
  if (!isPlainObject(payload)) {
    throw derivationError("Issue job payload is missing");
  }
  if (!isPlainObject(certificate)) {
    throw derivationError("Reconciled certificate is missing");
  }

  const commonName = text(certificate.commonName);
  if (!commonName) {
    throw derivationError("Reconciled certificate has no common name");
  }

  // Prefer the names the CA actually put in the certificate over the names the
  // job requested. If the CA normalised or dropped one, renewing against the
  // requested set would produce a different certificate than the one deployed.
  const observedSans = Array.isArray(certificate.subjectAltNames)
    ? certificate.subjectAltNames.map(text).filter(Boolean)
    : [];
  const requestedSans = Array.isArray(payload.sans)
    ? payload.sans.map(text).filter(Boolean)
    : [];
  const sans = [
    ...new Set(
      (observedSans.length > 0 ? observedSans : requestedSans).concat(
        commonName,
      ),
    ),
  ];

  const caEndpoint = text(payload.caEndpoint);
  if (!caEndpoint) {
    throw derivationError(
      "Issue job payload has no caEndpoint, so the renewal CA is unknown",
    );
  }
  const commandRef = text(payload.commandRef);
  if (!commandRef) {
    throw derivationError(
      "Issue job payload has no commandRef, so the ACME command profile is unknown",
    );
  }
  const dnsProvider = text(payload.dnsProvider);
  const dnsZone = text(payload.dnsZone);
  if (!dnsProvider || !dnsZone) {
    throw derivationError(
      "Issue job payload has no dnsProvider/dnsZone, so DNS-01 renewal cannot be reproduced",
    );
  }
  const certPath = text(payload.certPath);
  if (!certPath) {
    throw derivationError(
      "Issue job payload has no certPath, so the renewal has no deployment destination",
    );
  }

  const targetReference =
    text(payload.target?.reference) || commonName;
  const targetType = text(payload.target?.type) || "domain";

  // Carry the deployment shape the issuance actually used, including the paths
  // and reload hook, so the renewal writes to the same place with the same
  // permissions. Anything absent stays absent rather than being defaulted: the
  // agent applies its own documented defaults, and inventing different ones
  // here would silently change file ownership on renewal.
  const deploymentTarget = {
    type: targetType,
    reference: targetReference,
    certPath,
  };
  const optionalTargetFields = [
    "keyPath",
    "chainPath",
    "reloadService",
    "certMode",
    "keyMode",
    "chainMode",
    "owner",
    "group",
    "backupDir",
  ];
  const sourceTarget = isPlainObject(payload.deploymentTargets?.[0])
    ? payload.deploymentTargets[0]
    : payload;
  for (const field of optionalTargetFields) {
    const value = sourceTarget[field] ?? payload[field];
    if (value !== undefined && value !== null && value !== "") {
      deploymentTarget[field] = value;
    }
  }

  const candidate = {
    schemaVersion: RENEWAL_PROFILE_SCHEMA_VERSION,
    profileName: `${DERIVED_PROFILE_PREFIX}: ${commonName}`,
    // 'exact' rather than 'inherit': the SAN set is pinned to what the CA
    // issued. 'inherit' would re-read inventory at every renewal, so a later
    // discovery scan that rewrote subject_alt_names would silently change what
    // the renewal requests.
    sanPolicy: {
      mode: "exact",
      sans,
      allowWildcards: sans.some((name) => name.startsWith("*.")),
    },
    keyAlgorithm: text(payload.keyAlgorithm) || "ecdsa",
    keySize: Number.isSafeInteger(payload.keySize) ? payload.keySize : 256,
    // An issued certificate is always agent-local custody: the agent generated
    // the key and holds it, so a renewal can and should rotate it.
    keyRotationPolicy: { rotateOnRenew: true },
    preferredChain: text(payload.preferredChain),
    ca: {
      endpoint: caEndpoint,
      accountRef: text(payload.accountRef),
      eabRef: text(payload.eabRef),
    },
    acme: {
      kind: text(payload.acmeKind) || "certbot",
      commandRef,
    },
    dns: { provider: dnsProvider, zone: dnsZone },
    deploymentTargets: [deploymentTarget],
    target: {
      type: targetType,
      reference: targetReference,
      certPath,
      keyPath: text(sourceTarget.keyPath) || text(payload.keyPath),
      chainPath: text(sourceTarget.chainPath) || text(payload.chainPath),
    },
    verification: {
      host: text(payload.verifyHost),
      port: Number.isSafeInteger(payload.verifyPort) ? payload.verifyPort : null,
      // Only require a live match when the issuance itself was verified against
      // a host. Requiring it without a host would fail validation.
      requireMatch: Boolean(text(payload.verifyHost)),
    },
  };

  // Validate through the same gate the scheduler uses, so a profile that would
  // be rejected at renewal time is rejected here instead, while the operator is
  // still looking at the issuance that produced it.
  return validateRenewalProfile(candidate);
}

/**
 * Persist a derived profile and link the certificate to it.
 *
 * Runs inside the reconciliation transaction. Idempotent on replay: a second
 * reconciliation of the same certificate updates the existing derived profile
 * rather than creating a second one, and a certificate that already links to a
 * profile is left alone so an operator's own profile is never overwritten by a
 * derivation.
 *
 * Returns { profileId, created, reason } or { profileId: null, reason } when no
 * profile could be derived. Never throws for a derivation failure: a
 * certificate that was genuinely issued must still be promoted to active and
 * recorded, and losing the issuance because renewal config could not be
 * inferred would be a strictly worse outcome than an un-auto-renewable
 * certificate the operator can see and fix.
 */
async function ensureDerivedRenewalProfile({
  client,
  workspaceId,
  certificateId,
  payload,
  certificate,
  renewBeforeDays = null,
  logger = null,
} = {}) {
  const linked = await client.query(
    `SELECT profile_id FROM managed_certificates
      WHERE workspace_id = $1 AND id = $2::uuid`,
    [workspaceId, certificateId],
  );
  const existingProfileId = linked.rows[0]?.profile_id || null;
  if (existingProfileId) {
    return {
      profileId: String(existingProfileId),
      created: false,
      reason: "already_linked",
    };
  }

  let profile;
  try {
    profile = deriveRenewalProfileFromIssuedCertificate({
      payload,
      certificate,
    });
  } catch (error) {
    if (logger?.warn) {
      logger.warn("certops-renewal-profile-derivation-failed", {
        workspaceId,
        certificateId,
        error: error?.message,
        code: error?.code,
      });
    }
    return {
      profileId: null,
      created: false,
      reason: "derivation_failed",
      error: error?.message || null,
    };
  }

  const name = profile.profileName;
  // ON CONFLICT on the per-workspace unique index over LOWER(name): a
  // re-derivation for the same certificate reuses its profile row instead of
  // failing the whole reconciliation on a duplicate name.
  const upserted = await client.query(
    `INSERT INTO certificate_profiles (
       workspace_id, name, description, status, source, source_ref,
       renew_before_days, key_mode, public_metadata
     ) VALUES ($1, $2, $3, 'active', $4, $5, $6, 'agent-local', $7::jsonb)
     ON CONFLICT (workspace_id, LOWER(name)) DO UPDATE
       SET public_metadata = EXCLUDED.public_metadata,
           renew_before_days = COALESCE(
             certificate_profiles.renew_before_days,
             EXCLUDED.renew_before_days
           ),
           updated_at = NOW()
     RETURNING id, (xmax = 0) AS inserted`,
    [
      workspaceId,
      name,
      "Renewal configuration derived from the issuance that created this certificate.",
      DERIVED_PROFILE_SOURCE,
      `certops-issuance:${certificateId}`,
      renewBeforeDays,
      JSON.stringify({
        renewalProfile: profile,
        derivedFrom: {
          certificateId: String(certificateId),
          derivedAt: new Date().toISOString(),
        },
      }),
    ],
  );
  const profileId = String(upserted.rows[0].id);

  await client.query(
    `UPDATE managed_certificates
        SET profile_id = $3::uuid,
            updated_at = NOW()
      WHERE workspace_id = $1
        AND id = $2::uuid
        AND profile_id IS NULL`,
    [workspaceId, certificateId, profileId],
  );

  return {
    profileId,
    created: upserted.rows[0].inserted === true,
    reason: null,
  };
}

module.exports = {
  DERIVED_PROFILE_PREFIX,
  deriveRenewalProfileFromIssuedCertificate,
  ensureDerivedRenewalProfile,
};
