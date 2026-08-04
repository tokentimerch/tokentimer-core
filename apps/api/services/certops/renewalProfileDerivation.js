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
const { isTrustAnchorOperation } = require("./jobs");
const { writeAudit } = require("../audit");

// A derived profile is named after the certificate it was derived from, so an
// operator browsing profiles can tell at a glance which are machine-derived and
// which were authored. The name embeds certificateId (not just the common
// name) so the per-workspace unique index on LOWER(name) collides predictably
// on a second derivation for the *same* certificate, and never for a different
// certificate that happens to share a common name: one profile per issued
// certificate, not one profile per common name. Two certificates with the same
// CN (load-balanced pairs, blue/green, edge plus origin) are a routine
// operational shape, and sharing a profile between them would make the
// auto-renew switch and lead time apply to both from a single certificate's
// control, which is not the mental model the rest of the product uses.
const DERIVED_PROFILE_PREFIX = "Derived";
const DERIVED_PROFILE_SOURCE = "api";

/**
 * public_metadata flag marking a profile as operator-owned.
 *
 * Not certificate_profiles.source: its CHECK has no 'derived' value, which is
 * why derivation writes the generic 'api', so source cannot tell a derived row
 * from an operator-authored one at all. public_metadata needs no migration and
 * is where the operator's edited fields already live, so ownership travels with
 * the thing it protects.
 */
const OPERATOR_OWNED_METADATA_KEY = "operatorOwned";

// Reasons ensureDerivedRenewalProfile reports instead of throwing.
const DERIVATION_REASON_ALREADY_LINKED = "already_linked";
const DERIVATION_REASON_DERIVATION_FAILED = "derivation_failed";
const DERIVATION_REASON_PROFILE_OPERATOR_OWNED = "profile_operator_owned";
const DERIVATION_REASON_LINK_CONFLICT = "certificate_link_conflict";
// A trust-anchor job (distribute-trust/revoke-trust) has no certificate and
// no renewal (ADR-0012 decisions 4-6): this is the type-level guard that
// keeps one from ever reaching profile derivation, independent of the
// subject_type check its only current caller already applies, so the
// exclusion holds even if a future caller skips that check.
const DERIVATION_REASON_TRUST_ANCHOR_OPERATION = "trust_anchor_operation";

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
 * Build the store/site/binding deployment target for a Windows (os-store-
 * managed) issuance (ADR-0012 decisions 1 and 10). A windows-iis target has
 * no certPath/keyPath/chainPath: the renewal destination is a machine
 * certificate store plus an IIS site binding, keyed on thumbprint rather
 * than a filesystem path, so this returns a wholly distinct shape rather
 * than the certPath-based one with paths left null (matching
 * renewalProfile.js's validateTarget windows-iis branch, which the returned
 * shape must validate against).
 */
function buildWindowsDeploymentTarget(sourceTarget, targetReference) {
  const store = text(sourceTarget.store);
  if (!store) {
    throw derivationError(
      "Issue job payload has no store, so the Windows renewal has no " +
        "certificate-store destination",
    );
  }
  const binding = isPlainObject(sourceTarget.binding)
    ? sourceTarget.binding
    : null;
  const site = binding ? text(binding.site) : null;
  if (!binding || !site) {
    throw derivationError(
      "Issue job payload has no binding.site, so the IIS binding to " +
        "update on renewal is unknown",
    );
  }
  if (
    !Number.isSafeInteger(binding.port) ||
    binding.port < 1 ||
    binding.port > 65535
  ) {
    throw derivationError(
      "Issue job payload has no valid binding.port, so the IIS binding to " +
        "update on renewal is unknown",
    );
  }
  const sniHost = text(binding.sniHost);
  return {
    type: "windows-iis",
    reference: targetReference,
    store,
    binding: {
      site,
      port: binding.port,
      ...(sniHost ? { sniHost } : {}),
    },
  };
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

  const targetReference =
    text(payload.target?.reference) || commonName;
  const sourceTarget = isPlainObject(payload.deploymentTargets?.[0])
    ? payload.deploymentTargets[0]
    : payload;
  // Defense in depth behind validateIssueDeploymentTargets, which refuses a
  // multi-target issue payload at request time. Declining derivation is the
  // right failure here rather than deriving from [0]: a profile that maintains
  // one destination out of several looks healthy in the UI and silently stops
  // renewing the others, whereas a missing profile is visible as
  // "Renewal not configured" on the certificate the moment it is issued.
  if (
    Array.isArray(payload.deploymentTargets) &&
    payload.deploymentTargets.length > 1
  ) {
    throw derivationError(
      "Issue job payload carries more than one deploymentTargets entry; a " +
        "derived renewal profile describes a single destination, so deriving " +
        "from the first would silently drop the rest",
    );
  }
  const targetType =
    text(payload.target?.type) || text(sourceTarget.type) || "domain";

  const sharedProfileFields = {
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
  };

  // A Windows (os-store-managed) issuance deploys to a machine certificate
  // store plus an IIS site binding, keyed on thumbprint, not to a filesystem
  // path (ADR-0012 decisions 1 and 10). Branching here, on the same
  // target.type discriminator validateTarget already uses, keeps a
  // store/binding profile from ever being built with a Linux certPath shape
  // bolted on, and vice versa.
  if (targetType === "windows-iis") {
    const windowsTarget = buildWindowsDeploymentTarget(
      sourceTarget,
      targetReference,
    );
    const windowsCandidate = {
      ...sharedProfileFields,
      deploymentTargets: [windowsTarget],
      target: { ...windowsTarget },
      verification: {
        host: text(payload.verifyHost),
        port: Number.isSafeInteger(payload.verifyPort)
          ? payload.verifyPort
          : null,
        requireMatch: Boolean(text(payload.verifyHost)),
      },
    };
    return validateRenewalProfile(windowsCandidate);
  }

  const certPath = text(payload.certPath);
  if (!certPath) {
    throw derivationError(
      "Issue job payload has no certPath, so the renewal has no deployment destination",
    );
  }

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
  for (const field of optionalTargetFields) {
    const value = sourceTarget[field] ?? payload[field];
    if (value !== undefined && value !== null && value !== "") {
      deploymentTarget[field] = value;
    }
  }

  const candidate = {
    ...sharedProfileFields,
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
  operation = null,
  renewBeforeDays = null,
  logger = null,
  auditWriter = writeAudit,
} = {}) {
  // Type-level guard, not a convention: a trust-anchor job passed here (it
  // never legitimately would be, since its subject_type is 'trust_anchor'
  // rather than 'managed_certificate') is refused before any query runs,
  // rather than relying on every future caller to have checked subject_type
  // first.
  if (isTrustAnchorOperation(operation)) {
    if (logger?.warn) {
      logger.warn("certops-renewal-profile-derivation-skipped-trust-anchor", {
        workspaceId,
        certificateId,
        operation,
      });
    }
    return {
      profileId: null,
      created: false,
      reason: DERIVATION_REASON_TRUST_ANCHOR_OPERATION,
    };
  }

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
      reason: DERIVATION_REASON_ALREADY_LINKED,
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
      reason: DERIVATION_REASON_DERIVATION_FAILED,
      error: error?.message || null,
    };
  }

  const name = `${profile.profileName} (${certificateId})`;
  // ON CONFLICT on the per-workspace unique index over LOWER(name). The name
  // embeds certificateId, so this reuses a row only on a second derivation for
  // the *same* certificate (e.g. a promotion race, or a re-issuance that
  // revisits the same managed_certificates row); two certificates that merely
  // share a common name get distinct names and therefore distinct profiles.
  // status stays untouched and renew_before_days is COALESCE-preserved so
  // operator edits to those survive a same-certificate re-derivation, but
  // public_metadata is replaced. See ADR-0010 Amendment 2.
  //
  // The DO UPDATE refuses an operator-owned profile. Without that guard a
  // second derivation for the same certificate (e.g. a replayed
  // reconciliation) would replace public_metadata wholesale, so an operator
  // edit could revert silently and nothing would record that it had. Losing
  // the derivation is the better of the two failures: the stored profile
  // still describes a run that worked, and the refusal is reported rather
  // than swallowed.
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
       WHERE COALESCE(
               certificate_profiles.public_metadata->>$8::text,
               'false'
             ) <> 'true'
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
      OPERATOR_OWNED_METADATA_KEY,
    ],
  );
  // RETURNING yields nothing when the DO UPDATE's WHERE filters the row out, so
  // this is the operator-owned refusal, not an unexpected empty result. Reading
  // rows[0].id here would throw and break the never-throws contract this
  // function's callers depend on.
  if (upserted.rows.length === 0) {
    if (logger?.warn) {
      logger.warn("certops-renewal-profile-derivation-refused", {
        workspaceId,
        certificateId,
        profileName: name,
        reason: DERIVATION_REASON_PROFILE_OPERATOR_OWNED,
      });
    }
    return {
      profileId: null,
      created: false,
      reason: DERIVATION_REASON_PROFILE_OPERATOR_OWNED,
    };
  }
  const profileId = String(upserted.rows[0].id);

  const linkResult = await client.query(
    `UPDATE managed_certificates
        SET profile_id = $3::uuid,
            updated_at = NOW()
      WHERE workspace_id = $1
        AND id = $2::uuid
        AND profile_id IS NULL`,
    [workspaceId, certificateId, profileId],
  );
  // The guard can legitimately match nothing: a concurrent transaction may have
  // linked or detached the certificate since the read above. Reporting success
  // then would audit a grant of renewal authority the certificate does not
  // actually use, which is the one claim in this trail that must never be
  // false.
  if ((linkResult.rowCount ?? 0) === 0) {
    if (logger?.warn) {
      logger.warn("certops-renewal-profile-link-conflict", {
        workspaceId,
        certificateId,
        profileId,
      });
    }
    return {
      profileId: null,
      created: false,
      reason: DERIVATION_REASON_LINK_CONFLICT,
    };
  }

  // A derived profile is standing authority: it lets the scheduler re-run this
  // command, on this host, against this CA, indefinitely and with no operator in
  // the loop. Granting that has to be a recorded event, not an inferred one.
  // Without it the trail shows CERTOPS_RENEWAL_PROFILE_UPDATED events against a
  // profile that, as far as the audit log is concerned, never came into
  // existence.
  await auditWriter({
    client,
    actorUserId: null,
    subjectUserId: null,
    action: "CERTOPS_RENEWAL_PROFILE_DERIVED",
    targetType: "certificate_profile",
    targetId: null,
    workspaceId,
    metadata: {
      profileId,
      profileName: name,
      created: upserted.rows[0].inserted === true,
      managedCertificateId: String(certificateId),
      renewBeforeDays,
      acmeKind: profile.acme?.kind ?? null,
      // The three fields that decide what actually runs where: which ACME
      // command profile the agent invokes, which CA it orders from, and which
      // file on which host receives the result.
      commandRef: profile.acme?.commandRef ?? null,
      caEndpoint: profile.ca?.endpoint ?? null,
      certPath: profile.deploymentTargets?.[0]?.certPath ?? null,
      dnsProvider: profile.dns?.provider ?? null,
      dnsZone: profile.dns?.zone ?? null,
      keyAlgorithm: profile.keyAlgorithm ?? null,
      keySize: profile.keySize ?? null,
    },
  });

  return {
    profileId,
    created: upserted.rows[0].inserted === true,
    reason: null,
  };
}

module.exports = {
  DERIVATION_REASON_ALREADY_LINKED,
  DERIVATION_REASON_DERIVATION_FAILED,
  DERIVATION_REASON_LINK_CONFLICT,
  DERIVATION_REASON_PROFILE_OPERATOR_OWNED,
  DERIVATION_REASON_TRUST_ANCHOR_OPERATION,
  DERIVED_PROFILE_PREFIX,
  OPERATOR_OWNED_METADATA_KEY,
  buildWindowsDeploymentTarget,
  deriveRenewalProfileFromIssuedCertificate,
  ensureDerivedRenewalProfile,
};
