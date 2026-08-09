"use strict";

/**
 * Agent certificate discovery, generalized beyond filesystem paths to Windows
 * machine-store, IIS-binding, and http.sys locations.
 *
 * Jobless certificate.observed evidence from a credential-authenticated agent
 * must:
 *   1. advance the agent sequence, prove ownership, and insert evidence rows
 *      in one transaction (safe retry);
 *   2. upsert managed certificate / target / instance inventory rows in that
 *      same transaction so discovered certs become inventory-visible,
 *      regardless of whether the location is a file or an OS-store/IIS/
 *      http.sys binding;
 *   3. never let client metadata override server-owned fields (agentId,
 *      summary/fingerprint attribution, created_by_agent_id).
 */

const { pool } = require("../../db/database");
const { assertNoPrivateKeyMaterial } = require("../../utils/secretMaterial");
const {
  upsertManagedCertificateByMonitorSource,
  upsertAgentFilesystemTarget,
  upsertAgentFilesystemInstance,
  ensureManagedCertificateToken,
  findManagedCertificateBySourceRef,
} = require("./inventory");
const { createControllerObservationEvidence, createCertificateEvidence } = require("./evidence");
const {
  enforceAgentSequence,
  assertEvidenceClaimOwnership,
} = require("./agentDispatch");
const {
  WINDOWS_IIS_SITE_PATTERN,
  WINDOWS_SNI_HOST_PATTERN,
  WINDOWS_STORE_NAME_PATTERN,
} = require("./renewalProfile");

const CERTOPS_AGENT_OBSERVATION_INVALID = "CERTOPS_AGENT_OBSERVATION_INVALID";
const CERTOPS_AGENT_EVIDENCE_ID_REQUIRED = "CERTOPS_AGENT_EVIDENCE_ID_REQUIRED";
const AGENT_ID_PATTERN = /^[A-Za-z0-9_.:-]+$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const MAX_PATH = 512;
const MAX_TEXT = 1024;

// The observation contract's locality discriminator. 'filesystem' uses a
// filePath identity. The other three are non-filesystem locations reported by Windows
// discovery; identity for those is `locationSlot`, a stable per-binding string
// the agent computes (e.g. "Default Web Site:443", "LocalMachine/My/<thumbprint>")
// that survives a certificate rotation at the same location so a renewal
// refreshes the existing row instead of creating a duplicate.
const LOCATION_KINDS = new Set([
  "filesystem",
  "windows_store",
  "iis_binding",
  "http_sys",
]);

function observationError(
  message,
  code = CERTOPS_AGENT_OBSERVATION_INVALID,
) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function metadataMapFromItem(item) {
  if (!Array.isArray(item?.metadata)) return {};
  const out = {};
  for (const entry of item.metadata) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
    if (typeof entry.name !== "string" || !entry.name.trim()) continue;
    out[entry.name.trim()] = entry.value;
  }
  return out;
}

function requiredId(value, fieldName) {
  if (typeof value !== "string" || !value.trim() || value.length > 128) {
    throw observationError(`${fieldName} is invalid`);
  }
  const trimmed = value.trim();
  if (!AGENT_ID_PATTERN.test(trimmed)) {
    throw observationError(`${fieldName} is invalid`);
  }
  return trimmed;
}

/**
 * Strict boolean-or-absent parse for the Windows discovery `keyPresent`
 * fact, mirroring filesystem discovery's own coLocatedKeyDetected signal.
 * Named `keyPresent`
 * rather than `privateKeyPresent` deliberately: the latter's normalized form
 * contains the substring "privatekey", which both
 * packages/log-scrub/secret-material.js's field-name scan and this repo's
 * own zero-custody test convention treat as a private-key-material smell on
 * ANY field with that name, regardless of its value type. A boolean fact
 * about presence is exactly what the zero-custody rule wants surfaced, so
 * this avoids the name collision instead of trying to carve out an
 * exception in the secret scanner for one field.
 *
 * Absent means "the agent did not report this" (older agent build, or a
 * location kind this doesn't apply to) and is treated as unknown, never as
 * false -- this function returns `null` for that case so the caller can
 * distinguish "observed: no private key here" from "not observed either
 * way." A malformed value (anything other than a real boolean, or the two
 * literal strings kept here only because some client metadata paths
 * flatten values to strings) is rejected rather than silently coerced,
 * matching the port-validation rule: a field that gates a security-relevant
 * claim (keyMode) must fail loudly on nonsense input, not guess.
 */
function optionalBooleanFact(value, fieldName) {
  if (value === undefined || value === null) return null;
  if (typeof value === "boolean") return value;
  if (value === "true") return true;
  if (value === "false") return false;
  throw observationError(`${fieldName} must be a boolean when supplied`);
}

function optionalText(value, fieldName, max = MAX_TEXT) {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string") {
    throw observationError(`${fieldName} is invalid`);
  }
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > max) {
    throw observationError(`${fieldName} is invalid`);
  }
  return trimmed;
}

function optionalPatternText(value, fieldName, max, pattern) {
  const normalized = optionalText(value, fieldName, max);
  if (normalized !== null && !pattern.test(normalized)) {
    throw observationError(`${fieldName} is invalid`);
  }
  return normalized;
}

function optionalSha256(value, fieldName) {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    throw observationError(`${fieldName} is invalid`);
  }
  return value;
}

function optionalTimestamp(value, fieldName) {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
    throw observationError(`${fieldName} is invalid`);
  }
  return new Date(value).toISOString();
}

function optionalStringArray(value, fieldName) {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) {
    if (typeof value === "string") {
      const trimmed = value.trim();
      if (trimmed.startsWith("[")) {
        try {
          const parsed = JSON.parse(trimmed);
          if (!Array.isArray(parsed)) {
            throw observationError(`${fieldName} is invalid`);
          }
          return parsed
            .filter((entry) => typeof entry === "string")
            .map((entry) => entry.trim())
            .filter(Boolean)
            .slice(0, 64);
        } catch (error) {
          if (error?.code === CERTOPS_AGENT_OBSERVATION_INVALID) throw error;
          throw observationError(`${fieldName} is invalid`);
        }
      }
      return value
        .split(/[,\n]/)
        .map((part) => part.trim())
        .filter(Boolean)
        .slice(0, 64);
    }
    throw observationError(`${fieldName} is invalid`);
  }
  return value
    .filter((entry) => typeof entry === "string")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .slice(0, 64);
}

/**
 * Parses an explicitly-supplied Windows binding port. Mirrors the DB-level
 * contract on certificate_targets.windows_port exactly (migration 42:
 * `INTEGER NULL CHECK (windows_port IS NULL OR windows_port BETWEEN 1 AND
 * 65535)`) rather than inventing a second, looser rule here: a port is part
 * of IIS/http.sys binding identity (site/port/optional SNI host/store), so a
 * malformed explicit value must fail loudly, not silently collapse into
 * "no port" and quietly merge with a genuinely portless binding's identity.
 * Absence (undefined/null/empty string) is legitimately null -- an agent
 * that cannot determine a binding's port reports "unknown", not "invalid".
 */
function parseWindowsPort(raw, fieldName) {
  if (raw === undefined || raw === null || raw === "") return null;
  const asNumber =
    typeof raw === "number"
      ? raw
      : typeof raw === "string" && /^-?\d+$/.test(raw.trim())
        ? Number.parseInt(raw.trim(), 10)
        : NaN;
  if (!Number.isSafeInteger(asNumber) || asNumber < 1 || asNumber > 65535) {
    throw observationError(
      `${fieldName} must be an integer between 1 and 65535 when supplied (got ${JSON.stringify(raw)})`,
    );
  }
  return asNumber;
}

/**
 * Windows-specific metadata for the three non-filesystem location kinds.
 * None of these fields ever carry key material: store/site/port/hostname
 * are locality descriptors, exactly like `filePath` is for filesystem
 * discovery. `assertNoPrivateKeyMaterial` still runs over the whole evidence
 * item regardless of kind, so this does not loosen that boundary.
 */
function windowsLocationFieldsFor(locationKind, clientMeta) {
  const storeLocation =
    optionalPatternText(
      clientMeta.storeLocation,
      "storeLocation",
      64,
      /^LocalMachine$/,
    ) || "LocalMachine";
  const storeName =
    optionalPatternText(
      clientMeta.storeName,
      "storeName",
      64,
      WINDOWS_STORE_NAME_PATTERN,
    ) || "My";
  if (locationKind === "windows_store") {
    return {
      storeLocation,
      storeName,
      thumbprint: optionalText(clientMeta.thumbprint, "thumbprint", 64),
    };
  }
  if (locationKind === "iis_binding") {
    return {
      storeLocation,
      storeName,
      siteName: optionalPatternText(
        clientMeta.siteName,
        "siteName",
        256,
        WINDOWS_IIS_SITE_PATTERN,
      ),
      port: parseWindowsPort(clientMeta.port, "port"),
      sniHost: optionalPatternText(
        clientMeta.sniHost,
        "sniHost",
        255,
        WINDOWS_SNI_HOST_PATTERN,
      ),
    };
  }
  if (locationKind === "http_sys") {
    return {
      storeLocation,
      storeName,
      port: parseWindowsPort(clientMeta.port, "port"),
    };
  }
  return {};
}

/**
 * Server-derived default deployment reference per location kind, used when
 * the agent does not supply an explicit `locationRef`. Mirrors the URI
 * conventions sketched for this feature (winstore://, iis://, http-sys://).
 */
function defaultLocationRef(locationKind, { targetHost, windowsFields, locationSlot, thumbprint }) {
  if (locationKind === "windows_store") {
    const suffix = thumbprint || locationSlot;
    return `winstore://${windowsFields.storeLocation}/${windowsFields.storeName}${suffix ? `/${suffix}` : ""}`;
  }
  if (locationKind === "iis_binding") {
    const site = windowsFields.siteName || locationSlot;
    const port = windowsFields.port ? `:${windowsFields.port}` : "";
    return `iis://${site}${port}`;
  }
  if (locationKind === "http_sys") {
    const port = windowsFields.port ? `:${windowsFields.port}` : "";
    return `http-sys://${targetHost}${port}`;
  }
  return `file://${targetHost}`;
}

/**
 * Server-derived keyReference (zero-custody material-locality pointer; see
 * inventory.js's KEY_REFERENCE_ALLOWED_SCHEME_PREFIXES) for a non-filesystem
 * observation. Deliberately NOT the same string as defaultLocationRef/
 * deploymentReference: a binding descriptor like `iis://Default Web
 * Site:8443` or `http-sys://host:port` answers "how was this certificate
 * exposed", which is exactly the free-text shape the allow-list rejects,
 * because it is not one of the pointer schemes that actually names a key
 * custody location. For every Windows-sourced location kind the key -- when
 * present at all -- physically lives in the same machine certificate store
 * the binding merely references, never inside the binding itself, so the
 * custody pointer is always the winstore:// store coordinate regardless of
 * whether this observation came from the store enumeration or an IIS/
 * http.sys binding scan.
 */
function defaultKeyReference(locationKind, { windowsFields, locationSlot, thumbprint }) {
  if (locationKind === "filesystem") return null;
  const suffix = thumbprint || locationSlot;
  const storeLocation = windowsFields.storeLocation || "LocalMachine";
  const storeName = windowsFields.storeName || "My";
  return `winstore://${storeLocation}/${storeName}${suffix ? `/${suffix}` : ""}`;
}

/**
 * Structured agent-observation contract generalized beyond the original
 * filesystem-only shape. `locationKind` defaults to
 * 'filesystem' so every existing agent (which never sends this field) keeps
 * behaving exactly as before -- filePath stays required, identity stays
 * `agentId/targetHost/filePath`. A `locationKind` of windows_store/
 * iis_binding/http_sys instead requires `locationSlot`, the agent's own
 * stable identity string for that binding/store entry, and produces a
 * different identity + keyReference/keyMode/deploymentReference shape (see
 * certSourceRefFor/targetSourceRefFor and upsertInventoryForObservation).
 * Client-provided fields are validated first; server-owned fields are
 * applied AFTER spreading client input so they can never be spoofed (B18
 * invariant).
 */
function normalizeAgentFilesystemObservation({
  agent,
  evidenceItem,
  serverObservedAt = new Date().toISOString(),
}) {
  assertNoPrivateKeyMaterial(evidenceItem);
  if (!isPlainObject(evidenceItem)) {
    throw observationError("evidence item is invalid");
  }
  if (evidenceItem.eventType !== "certificate.observed") {
    throw observationError("evidence eventType is invalid");
  }

  const clientMeta = metadataMapFromItem(evidenceItem);
  const evidenceId = requiredId(
    evidenceItem.evidenceId || clientMeta.evidenceId,
    "evidenceId",
  );
  const fingerprintSha256 = optionalSha256(
    evidenceItem.fingerprintSha256 || clientMeta.fingerprintSha256,
    "fingerprintSha256",
  );
  if (!fingerprintSha256) {
    throw observationError("fingerprintSha256 is required for discovery evidence");
  }

  const rawLocationKind =
    typeof clientMeta.locationKind === "string" ? clientMeta.locationKind.trim() : "";
  const locationKind = rawLocationKind && LOCATION_KINDS.has(rawLocationKind)
    ? rawLocationKind
    : "filesystem";
  if (rawLocationKind && !LOCATION_KINDS.has(rawLocationKind)) {
    throw observationError("locationKind is invalid");
  }

  const targetHost = optionalText(
    clientMeta.targetHost ||
      clientMeta.hostname ||
      clientMeta.host ||
      agent.hostname,
    "targetHost",
    255,
  );
  if (!targetHost) {
    throw observationError("targetHost is required for discovery evidence");
  }

  let filePath = null;
  let locationSlot = null;
  let windowsFields = {};
  let keyPresent = null;
  if (locationKind === "filesystem") {
    filePath = optionalText(
      clientMeta.filePath || clientMeta.path || clientMeta.certificatePath,
      "filePath",
      MAX_PATH,
    );
    if (!filePath) {
      throw observationError("filePath is required for filesystem discovery evidence");
    }
  } else {
    locationSlot = optionalText(clientMeta.locationSlot, "locationSlot", MAX_PATH);
    if (!locationSlot) {
      throw observationError(
        `locationSlot is required for ${locationKind} discovery evidence`,
      );
    }
    windowsFields = windowsLocationFieldsFor(locationKind, clientMeta);
    // Fact only, never material: whether the location's certificate has an
    // associated private key, exactly as Windows itself reports it
    // (`X509Certificate2.HasPrivateKey`) -- never a key path, export, or
    // blob. Unknown (older agent, or a location the agent genuinely
    // couldn't determine this for) stays null rather than defaulting to
    // either true or false, so keyMode below only ever claims
    // os-store-managed when the agent actually observed a key.
    keyPresent = optionalBooleanFact(clientMeta.keyPresent, "keyPresent");
  }

  const locationRef =
    optionalText(clientMeta.locationRef, "locationRef", MAX_PATH) ||
    defaultLocationRef(locationKind, {
      targetHost,
      windowsFields,
      locationSlot,
      thumbprint: windowsFields.thumbprint,
    });

  const observedAt =
    optionalTimestamp(evidenceItem.observedAt, "observedAt") ||
    serverObservedAt;

  const publicCertificate = {
    fingerprintSha256,
    subject: optionalText(
      clientMeta.subject || clientMeta.observedSubject,
      "subject",
    ),
    issuer: optionalText(
      clientMeta.issuer || clientMeta.observedIssuer,
      "issuer",
    ),
    serialNumber: optionalText(clientMeta.serialNumber, "serialNumber"),
    subjectAltNames: optionalStringArray(
      clientMeta.subjectAltNames || clientMeta.sans,
      "subjectAltNames",
    ),
    notBefore: optionalTimestamp(
      clientMeta.notBefore || clientMeta.validFrom,
      "notBefore",
    ),
    notAfter: optionalTimestamp(
      clientMeta.notAfter || clientMeta.validTo,
      "notAfter",
    ),
    certificatePem: optionalText(
      clientMeta.certificatePem,
      "certificatePem",
      65536,
    ),
  };

  // Security-relevant invariant (B18): server-owned fields MUST be assigned
  // AFTER any client-submitted metadata is assembled so a compromised or
  // buggy agent cannot spoof agentId, summary, fingerprint attribution, or
  // created_by_agent_id.
  const clientSubmitted = {
    evidenceId,
    filePath,
    targetHost,
    locationKind,
    locationSlot,
    locationRef,
    windowsFields,
    keyPresent,
    publicCertificate,
    summary: optionalText(evidenceItem.summary || clientMeta.summary, "summary"),
    clientMetadata: clientMeta,
    observedAt,
  };

  return {
    ...clientSubmitted,
    schemaVersion: 1,
    source: locationKind === "filesystem" ? "agent_filesystem" : "agent_windows",
    agentId: agent.agentId,
    agentRowId: agent.id,
    workspaceId: agent.workspaceId,
    fingerprintSha256,
    summary: clientSubmitted.summary,
    observedAtServer: serverObservedAt,
  };
}

function certSourceRefFor(observation) {
  if (observation.locationKind === "filesystem") {
    return `${observation.agentId}/${observation.targetHost}/${observation.filePath}`;
  }
  return `${observation.agentId}/${observation.targetHost}/${observation.locationKind}/${observation.locationSlot}`;
}

function targetSourceRefFor(observation) {
  if (observation.locationKind === "filesystem") {
    return `${observation.agentId}/${observation.targetHost}`;
  }
  // Store entries and bindings carry distinct topology. Including the stable
  // location slot prevents one IIS site's store/site/port fields from
  // overwriting another site's target row on the same host.
  return `${observation.agentId}/${observation.targetHost}/${observation.locationKind}/${observation.locationSlot}`;
}

/**
 * Extracts the CN attribute from a raw X.509 subject string (e.g.
 * "CN=example.com, O=Example Inc"). Mirrors monitorBridge.js's
 * commonNameFromSubject so a discovered certificate's display name reflects
 * its own subject rather than the discovering host.
 */
function commonNameFromSubject(subject) {
  const text = typeof subject === "string" ? subject.trim() : "";
  if (!text) return null;
  const match = text.match(/(?:^|\n|,\s*)CN\s*=\s*([^,\n]+)/i);
  return match?.[1]?.trim() || null;
}

function certificateFor(observation) {
  const publicCertificate = observation.publicCertificate || {};
  return {
    certificatePem: publicCertificate.certificatePem || null,
    // SAN first (X.509 convention), then the certificate's own subject CN;
    // the discovery host/file path are last-resort fallbacks only for a
    // certificate that reports neither, not the certificate's identity.
    commonName:
      publicCertificate.subjectAltNames?.[0] ||
      commonNameFromSubject(publicCertificate.subject) ||
      observation.targetHost ||
      observation.filePath ||
      observation.locationSlot,
    fingerprintSha256: observation.fingerprintSha256,
    issuer: publicCertificate.issuer || null,
    notAfter: publicCertificate.notAfter || null,
    notBefore: publicCertificate.notBefore || null,
    serialNumber: publicCertificate.serialNumber || null,
    subject: publicCertificate.subject || null,
    subjectAltNames: publicCertificate.subjectAltNames || [],
  };
}

async function findExistingEvidenceByClientId(client, observation) {
  const result = await client.query(
    `SELECT id, workspace_id, job_id, evidence_type, subject_type, subject_id,
            metadata, redacted_output, output_truncated, output_sha256,
            output_size_bytes, observed_at, created_by_user_id,
            created_by_api_token_id, created_by_agent_id, client_evidence_id,
            created_at
       FROM certificate_evidence
      WHERE workspace_id = $1
        AND created_by_agent_id = $2
        AND client_evidence_id = $3
      LIMIT 1`,
    [observation.workspaceId, observation.agentRowId, observation.evidenceId],
  );
  return result.rows[0] || null;
}

async function upsertInventoryForObservation(client, observation) {
  const certificate = certificateFor(observation);
  const certSourceRef = certSourceRefFor(observation);
  const targetSourceRef = targetSourceRefFor(observation);
  const isFilesystem = observation.locationKind === "filesystem";
  const displayName =
    certificate.commonName || observation.filePath || observation.locationSlot;

  // Filesystem-discovered certificates have no pre-existing "linked token"
  // the way endpoint/domain monitors do (monitorBridge.js's "Token first"
  // rule: it skips the write entirely when no token is already linked).
  // There is no equivalent setup step for an agent host, so this instead
  // mirrors the manual PEM-import path (importPublicCertificates) and
  // auto-creates/reuses an ssl_cert token, keeping the CONTEXT.md invariant
  // that a managed_certificate row is never left without a linked token
  // (otherwise it is invisible in the token-centric dashboard views).
  // Looked up by the stable (source, source_ref) identity first, not
  // fingerprint, since a rotation at the same file path/binding keeps the
  // same source_ref but changes the fingerprint.
  const existingManagedCertificate = await findManagedCertificateBySourceRef(
    client,
    {
      workspaceId: observation.workspaceId,
      source: observation.source,
      sourceRef: certSourceRef,
    },
  );
  const tokenId = await ensureManagedCertificateToken(
    client,
    certificate,
    {
      workspaceId: observation.workspaceId,
      name: displayName,
      tokenNotesSourceLabel: isFilesystem
        ? "agent filesystem discovery"
        : "agent Windows discovery",
    },
    existingManagedCertificate,
  );

  const managedCertificate = await upsertManagedCertificateByMonitorSource(
    client,
    certificate,
    {
      workspaceId: observation.workspaceId,
      status: "discovered",
      source: observation.source,
      sourceRef: certSourceRef,
      name: displayName,
      // os-store-managed only when the agent actually
      // observed a private key at this location (observation.keyPresent ===
      // true, from the Windows store's own HasPrivateKey fact -- never
      // assumed). TokenTimer's executor creates a certificate directly inside
      // the CNG store, which always has a key by
      // construction; this code instead observes certificates that already
      // existed on the host, where that is not guaranteed (a public-only
      // import, an intermediate cert, or a binding pointing at a store entry
      // this agent cannot read the key state for). Claiming os-store-managed
      // for a location with no confirmed key would misrepresent custody, so
      // an unconfirmed/false observation leaves keyMode null rather than
      // guessing. A confirmed key plus complete IIS topology is deployable by
      // the Windows renew/rebind executor; public-only entries remain
      // observation-only.
      keyMode: isFilesystem
        ? "agent-local"
        : observation.keyPresent === true
          ? "os-store-managed"
          : null,
      keyReference: isFilesystem
        ? `file://${observation.filePath}`
        : defaultKeyReference(observation.locationKind, {
            windowsFields: observation.windowsFields,
            locationSlot: observation.locationSlot,
            thumbprint: observation.windowsFields?.thumbprint,
          }),
      // Filesystem adoption uses this path directly. Windows adoption uses
      // the store/site/binding descriptor instead, so its certificate path
      // remains null and no file-based key custody is invented.
      deployedCertPath: isFilesystem ? observation.filePath : null,
      deployedAgentId: observation.agentRowId,
      tokenId,
      controllerObservationMetadata: {
        agentId: observation.agentId,
        filePath: observation.filePath,
        locationKind: observation.locationKind,
        locationSlot: observation.locationSlot,
        targetHost: observation.targetHost,
        observedAt: observation.observedAt,
        observedAtServer: observation.observedAtServer,
        source: observation.source,
      },
    },
    0,
  );

  const target = await upsertAgentFilesystemTarget(client, {
    workspaceId: observation.workspaceId,
    source: observation.source,
    sourceRef: targetSourceRef,
    targetType: observation.locationKind === "iis_binding" ? "windows-iis" : "agent-host",
    hostname: observation.targetHost,
    name: observation.targetHost,
    locationKind: observation.locationKind,
    deploymentReference: observation.locationRef,
    windowsStore: observation.windowsFields?.storeName || null,
    windowsSite: observation.windowsFields?.siteName || null,
    windowsPort: observation.windowsFields?.port || null,
    windowsSniHost: observation.windowsFields?.sniHost || null,
    publicMetadata: {
      agentId: observation.agentId,
      targetHost: observation.targetHost,
      locationKind: observation.locationKind,
      observationOnly:
        observation.locationKind !== "iis_binding" ||
        observation.keyPresent !== true,
    },
  });

  const instance = await upsertAgentFilesystemInstance(client, {
    workspaceId: observation.workspaceId,
    managedCertificateId: managedCertificate.id,
    targetId: target.id,
    status: "discovered",
    source: observation.source,
    sourceRef: certSourceRef,
    locationKind: observation.locationKind,
    fingerprintSha256: observation.fingerprintSha256,
    serialNumber: certificate.serialNumber,
    subject: certificate.subject,
    issuer: certificate.issuer,
    notBefore: certificate.notBefore,
    notAfter: certificate.notAfter,
    deploymentReference: isFilesystem ? `file://${observation.filePath}` : observation.locationRef,
    observedAt: observation.observedAt,
    publicMetadata: {
      agentId: observation.agentId,
      filePath: observation.filePath,
      locationKind: observation.locationKind,
      locationSlot: observation.locationSlot,
      evidenceId: observation.evidenceId,
      observedAtServer: observation.observedAtServer,
    },
  });

  return { managedCertificate, target, instance };
}

async function persistOneObservation(client, observation) {
  const existing = await findExistingEvidenceByClientId(client, observation);
  if (existing) {
    return {
      duplicate: true,
      evidence: existing,
      managedCertificateId:
        existing.metadata?.managedCertificateId ||
        existing.subject_id ||
        null,
    };
  }

  const inventory = await upsertInventoryForObservation(client, observation);

  // Server-owned metadata fields set AFTER client metadata (B18).
  const clientMetadata = {
    ...(observation.clientMetadata && typeof observation.clientMetadata === "object"
      ? observation.clientMetadata
      : {}),
  };
  delete clientMetadata.agentId;
  delete clientMetadata.summary;
  delete clientMetadata.fingerprintSha256;
  delete clientMetadata.created_by_agent_id;
  delete clientMetadata.createdByAgentId;

  const metadata = {
    ...clientMetadata,
    // Security-relevant invariant: server-owned fields win.
    agentId: observation.agentId,
    summary: observation.summary,
    fingerprintSha256: observation.fingerprintSha256,
    filePath: observation.filePath,
    targetHost: observation.targetHost,
    locationKind: observation.locationKind,
    locationSlot: observation.locationSlot,
    evidenceId: observation.evidenceId,
    source: observation.source,
    eventType: "certificate.observed",
    managedCertificateId: inventory.managedCertificate.id,
    targetId: inventory.target.id,
    certificateInstanceId: inventory.instance?.id || null,
    observedAtServer: observation.observedAtServer,
  };

  const evidence = await createControllerObservationEvidence({
    client,
    workspaceId: observation.workspaceId,
    evidenceType: "certificate.observed",
    subjectType: "managed_certificate",
    subjectId: inventory.managedCertificate.id,
    observedAt: observation.observedAt,
    createdByAgentId: observation.agentRowId,
    clientEvidenceId: observation.evidenceId,
    metadata,
  });

  return {
    duplicate: false,
    evidence,
    managedCertificateId: inventory.managedCertificate.id,
    targetId: inventory.target.id,
    certificateInstanceId: inventory.instance?.id || null,
  };
}

/**
 * Persist a batch of jobless discovery observations atomically with the
 * agent sequence CAS (B17 + B18).
 */
async function persistAgentDiscoveryEvidenceBatch({
  dbPool = pool,
  agent,
  envelope,
  evidenceItems,
  deps = {},
} = {}) {
  if (!agent?.id || !agent?.workspaceId || !agent?.agentId) {
    throw observationError("Authenticated agent identity is required");
  }
  if (!Array.isArray(evidenceItems) || evidenceItems.length < 1) {
    throw observationError("evidenceItems is invalid");
  }

  const enforceSequence = deps.enforceAgentSequence || enforceAgentSequence;
  const serverObservedAt = new Date().toISOString();
  const observations = evidenceItems.map((item) =>
    normalizeAgentFilesystemObservation({
      agent,
      evidenceItem: item,
      serverObservedAt,
    }),
  );

  const client = await dbPool.connect();
  try {
    await client.query("BEGIN");
    await enforceSequence({
      client,
      agentRowId: agent.id,
      envelope,
    });

    const results = [];
    for (const observation of observations) {
      results.push(await persistOneObservation(client, observation));
    }

    await client.query("COMMIT");
    return {
      ok: true,
      evidenceCount: results.length,
      duplicateCount: results.filter((row) => row.duplicate).length,
      items: results,
    };
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (_rollbackError) {
      // Preserve the original failure.
    }
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Persist job-bound agent evidence atomically with sequence CAS and claim
 * ownership proof (B18).
 */
async function persistAgentJobEvidenceBatch({
  dbPool = pool,
  agent,
  envelope,
  jobId,
  claimId = null,
  evidenceItems,
  deps = {},
} = {}) {
  if (!agent?.id || !agent?.workspaceId || !agent?.agentId) {
    throw observationError("Authenticated agent identity is required");
  }
  if (typeof jobId !== "string" || !jobId.trim()) {
    throw observationError("jobId is required");
  }
  if (!Array.isArray(evidenceItems) || evidenceItems.length < 1) {
    throw observationError("evidenceItems is invalid");
  }

  const enforceSequence = deps.enforceAgentSequence || enforceAgentSequence;
  const assertOwnership =
    deps.assertEvidenceClaimOwnership || assertEvidenceClaimOwnership;
  const persist = deps.createCertificateEvidence || createCertificateEvidence;

  const client = await dbPool.connect();
  try {
    await client.query("BEGIN");
    await enforceSequence({
      client,
      agentRowId: agent.id,
      envelope,
    });
    const binding = await assertOwnership({
      dbPool: client,
      agent,
      jobId,
      claimId,
    });

    const created = [];
    for (const item of evidenceItems) {
      if (!item || typeof item !== "object" || Array.isArray(item)) {
        throw observationError("evidence item is invalid");
      }
      const evidenceId =
        typeof item.evidenceId === "string" ? item.evidenceId.trim() : "";
      if (!evidenceId) {
        throw observationError(
          "evidenceId is required",
          CERTOPS_AGENT_EVIDENCE_ID_REQUIRED,
        );
      }

      const clientMeta = metadataMapFromItem(item);
      // Security-relevant invariant (B18): server-owned fields win.
      const metadata = {
        ...clientMeta,
        summary: item.summary ?? null,
        fingerprintSha256: item.fingerprintSha256 ?? null,
        agentId: agent.agentId,
        evidenceId,
      };

      const evidence = await persist({
        client,
        workspaceId: agent.workspaceId,
        jobId,
        evidenceType: item.eventType,
        metadata,
        serverOwnedMetadata: {
          agentId: agent.agentId,
          summary: item.summary ?? null,
          fingerprintSha256: item.fingerprintSha256 ?? null,
          evidenceId,
        },
        observedAt: item.observedAt,
        createdByAgentId: agent.id,
        clientEvidenceId: evidenceId,
        // Server-validated, never agent-supplied: the claim the job is
        // currently on, plus the server's own attempt counter.
        claimId: binding?.claimId || null,
        attemptCount: binding?.attemptCount ?? null,
      });
      if (evidence) created.push(evidence);
    }

    await client.query("COMMIT");
    return { ok: true, evidenceCount: created.length, items: created };
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (_rollbackError) {
      // Preserve the original failure.
    }
    throw error;
  } finally {
    client.release();
  }
}

module.exports = {
  CERTOPS_AGENT_EVIDENCE_ID_REQUIRED,
  CERTOPS_AGENT_OBSERVATION_INVALID,
  LOCATION_KINDS,
  normalizeAgentFilesystemObservation,
  persistAgentDiscoveryEvidenceBatch,
  persistAgentJobEvidenceBatch,
  _test: {
    certificateFor,
    certSourceRefFor,
    metadataMapFromItem,
    normalizeAgentFilesystemObservation,
    targetSourceRefFor,
    defaultLocationRef,
    defaultKeyReference,
    windowsLocationFieldsFor,
  },
};
