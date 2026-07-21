"use strict";

const { scrubLogString } = require("@tokentimer/log-scrub");

const OBSERVATION_SCHEMA_VERSION = 1;
const OBSERVATION_SOURCE = "cert_manager";
const MAX_CONDITIONS = 16;
const MAX_DNS_NAMES = 64;
const MAX_IDENTIFIER_LENGTH = 253;
const MAX_MESSAGE_LENGTH = 1_024;
const MAX_REASON_LENGTH = 256;
const MAX_RESOURCE_VERSION_LENGTH = 256;
const MAX_TIMESTAMP_LENGTH = 64;
const CERTIFICATE_NAME_ANNOTATION = "cert-manager.io/certificate-name";
const CERTIFICATE_REVISION_ANNOTATION = "cert-manager.io/certificate-revision";

const WATCHED_RESOURCES = Object.freeze([
  "Certificate",
  "CertificateRequest",
]);

function boundedText(value, maximumLength) {
  if (typeof value !== "string" && typeof value !== "number") return undefined;
  const scrubbed = scrubLogString(String(value).trim());
  if (typeof scrubbed !== "string" || scrubbed === "") return undefined;
  return scrubbed.slice(0, maximumLength);
}

function normalizedTimestamp(value) {
  const text = boundedText(value, MAX_TIMESTAMP_LENGTH);
  if (!text) return undefined;
  const timestamp = Date.parse(text);
  return Number.isNaN(timestamp) ? undefined : new Date(timestamp).toISOString();
}

function normalizedInteger(value) {
  const number = typeof value === "number" ? value : Number(value);
  return Number.isSafeInteger(number) && number >= 0 ? number : undefined;
}

function objectValue(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function normalizedConditions(value) {
  if (!Array.isArray(value)) return [];

  return value
    .slice(0, MAX_CONDITIONS)
    .map((condition) => {
      const source = objectValue(condition);
      const type = boundedText(source.type, MAX_IDENTIFIER_LENGTH);
      const status = boundedText(source.status, 32);
      if (!type || !status) return null;

      const normalized = { status, type };
      const reason = boundedText(source.reason, MAX_REASON_LENGTH);
      const message = boundedText(source.message, MAX_MESSAGE_LENGTH);
      const lastTransitionTime = normalizedTimestamp(source.lastTransitionTime);
      if (reason) normalized.reason = reason;
      if (message) normalized.message = message;
      if (lastTransitionTime) normalized.lastTransitionTime = lastTransitionTime;
      return normalized;
    })
    .filter(Boolean)
    .sort((left, right) =>
      compareText(
        `${left.type}\u0000${left.status}\u0000${left.reason || ""}\u0000${left.message || ""}`,
        `${right.type}\u0000${right.status}\u0000${right.reason || ""}\u0000${right.message || ""}`,
      ),
    );
}

function readyCondition(conditions) {
  return conditions.find((condition) => condition.type === "Ready");
}

function normalizedDnsNames(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(
    value
      .slice(0, MAX_DNS_NAMES)
      .map((name) => boundedText(name, MAX_IDENTIFIER_LENGTH))
      .filter(Boolean),
  )].sort(compareText);
}

function resourceIdentity(resource) {
  const metadata = objectValue(resource?.metadata);
  const namespace = boundedText(metadata.namespace, MAX_IDENTIFIER_LENGTH);
  const name = boundedText(metadata.name, MAX_IDENTIFIER_LENGTH);
  const uid = boundedText(metadata.uid, MAX_IDENTIFIER_LENGTH);
  return namespace && name && uid ? `${namespace}/${name}/${uid}` : undefined;
}

function resourceNameIdentity(resource) {
  const metadata = objectValue(resource?.metadata);
  const namespace = boundedText(metadata.namespace, MAX_IDENTIFIER_LENGTH);
  const name = boundedText(metadata.name, MAX_IDENTIFIER_LENGTH);
  return namespace && name ? `${namespace}/${name}` : undefined;
}

function resourceVersion(resource) {
  return boundedText(
    objectValue(resource?.metadata).resourceVersion,
    MAX_RESOURCE_VERSION_LENGTH,
  );
}

function certificateRequestMatches(certificateRequest, certificate) {
  const requestMetadata = objectValue(certificateRequest?.metadata);
  const certificateMetadata = objectValue(certificate?.metadata);
  if (requestMetadata.namespace !== certificateMetadata.namespace) return false;

  const ownerReferences = Array.isArray(requestMetadata.ownerReferences)
    ? requestMetadata.ownerReferences
    : [];
  const certificateOwners = ownerReferences.filter(
    (owner) => objectValue(owner).kind === "Certificate",
  );
  if (certificateOwners.length > 0) {
    return certificateOwners.some((owner) => {
      const normalizedOwner = objectValue(owner);
      return normalizedOwner.uid
        ? normalizedOwner.uid === certificateMetadata.uid
        : normalizedOwner.name === certificateMetadata.name;
    });
  }

  return certificateRequestRevisionMatches(certificateRequest, certificate);
}

function certificateRequestRevisionMatches(certificateRequest, certificate) {
  const requestMetadata = objectValue(certificateRequest?.metadata);
  const certificateMetadata = objectValue(certificate?.metadata);
  const annotations = objectValue(requestMetadata.annotations);
  const revision = normalizedInteger(objectValue(certificate?.status).revision);
  return (
    typeof revision === "number" &&
    annotations[CERTIFICATE_NAME_ANNOTATION] === certificateMetadata.name &&
    annotations[CERTIFICATE_REVISION_ANNOTATION] === String(revision)
  );
}

function compareNewestResourceVersion(left, right) {
  const leftVersion = resourceVersion(left) || "";
  const rightVersion = resourceVersion(right) || "";
  if (/^\d+$/.test(leftVersion) && /^\d+$/.test(rightVersion)) {
    const normalizedLeft = leftVersion.replace(/^0+(?=\d)/, "");
    const normalizedRight = rightVersion.replace(/^0+(?=\d)/, "");
    if (normalizedLeft.length !== normalizedRight.length) {
      return normalizedRight.length - normalizedLeft.length;
    }
    return compareText(normalizedRight, normalizedLeft);
  }
  return compareText(rightVersion, leftVersion);
}

function compareCertificateRequests(left, right, certificate) {
  const leftRevisionMatch = certificateRequestRevisionMatches(left, certificate);
  const rightRevisionMatch = certificateRequestRevisionMatches(right, certificate);
  if (leftRevisionMatch !== rightRevisionMatch) return leftRevisionMatch ? -1 : 1;

  const leftMetadata = objectValue(left?.metadata);
  const rightMetadata = objectValue(right?.metadata);
  const leftCreatedAt = normalizedTimestamp(leftMetadata.creationTimestamp) || "";
  const rightCreatedAt = normalizedTimestamp(rightMetadata.creationTimestamp) || "";
  const createdAtComparison = compareText(rightCreatedAt, leftCreatedAt);
  if (createdAtComparison !== 0) return createdAtComparison;

  const resourceVersionComparison = compareNewestResourceVersion(left, right);
  if (resourceVersionComparison !== 0) return resourceVersionComparison;

  const nameComparison = compareText(
    boundedText(leftMetadata.name, MAX_IDENTIFIER_LENGTH) || "",
    boundedText(rightMetadata.name, MAX_IDENTIFIER_LENGTH) || "",
  );
  if (nameComparison !== 0) return nameComparison;
  return compareText(
    boundedText(leftMetadata.uid, MAX_IDENTIFIER_LENGTH) || "",
    boundedText(rightMetadata.uid, MAX_IDENTIFIER_LENGTH) || "",
  );
}

function selectCertificateRequest(certificate, certificateRequests) {
  if (!Array.isArray(certificateRequests)) return null;
  return certificateRequests
    .filter((request) => certificateRequestMatches(request, certificate))
    .sort((left, right) => compareCertificateRequests(left, right, certificate))[0] || null;
}

function safeCertificateRequestReference(certificateRequest) {
  if (!certificateRequest) return null;
  const metadata = objectValue(certificateRequest.metadata);
  const name = boundedText(metadata.name, MAX_IDENTIFIER_LENGTH);
  if (!name) return null;
  const reference = { name };
  const uid = boundedText(metadata.uid, MAX_IDENTIFIER_LENGTH);
  if (uid) reference.uid = uid;
  return reference;
}

function failureDetails(conditions) {
  const failed = readyCondition(conditions);
  if (!failed || failed.status !== "False") return {};
  const result = {};
  if (failed.reason) result.failureReason = failed.reason;
  if (failed.message) result.failureMessage = failed.message;
  return result;
}

function mapCertificateObservation({
  certificate,
  certificateRequest,
  clusterId,
  now = () => new Date().toISOString(),
  workspaceId,
} = {}) {
  const metadata = objectValue(certificate?.metadata);
  const spec = objectValue(certificate?.spec);
  const status = objectValue(certificate?.status);
  const namespace = boundedText(metadata.namespace, MAX_IDENTIFIER_LENGTH);
  const certificateName = boundedText(metadata.name, MAX_IDENTIFIER_LENGTH);
  const certificateUid = boundedText(metadata.uid, MAX_IDENTIFIER_LENGTH);
  const normalizedWorkspaceId = boundedText(workspaceId, MAX_IDENTIFIER_LENGTH);
  const normalizedClusterId = boundedText(clusterId, MAX_IDENTIFIER_LENGTH);
  if (
    !namespace ||
    !certificateName ||
    !certificateUid ||
    !normalizedWorkspaceId ||
    !normalizedClusterId
  ) {
    return null;
  }

  const issuerSource = objectValue(spec.issuerRef);
  const issuerRef = {
    group: boundedText(issuerSource.group, MAX_IDENTIFIER_LENGTH) || "cert-manager.io",
    kind: boundedText(issuerSource.kind, MAX_IDENTIFIER_LENGTH) || "Issuer",
    name: boundedText(issuerSource.name, MAX_IDENTIFIER_LENGTH) || "",
  };
  const conditions = normalizedConditions(status.conditions);
  const requestConditions = normalizedConditions(
    objectValue(certificateRequest?.status).conditions,
  );
  const certificateFailure = failureDetails(conditions);
  const requestFailure = failureDetails(requestConditions);
  const ready = readyCondition(conditions)?.status === "True";
  const observation = {
    schemaVersion: OBSERVATION_SCHEMA_VERSION,
    workspaceId: normalizedWorkspaceId,
    clusterId: normalizedClusterId,
    namespace,
    certificateName,
    certificateUid,
    issuerRef,
    secretName: boundedText(spec.secretName, MAX_IDENTIFIER_LENGTH) || null,
    certificateRequestRef: safeCertificateRequestReference(certificateRequest),
    dnsNames: normalizedDnsNames(spec.dnsNames),
    conditions,
    ready,
    observationSource: OBSERVATION_SOURCE,
    observedAt: normalizedTimestamp(now()) || new Date(0).toISOString(),
  };
  const generation = normalizedInteger(metadata.generation);
  const version = resourceVersion(certificate);
  const revision = normalizedInteger(status.revision);
  const notBefore = normalizedTimestamp(status.notBefore);
  const notAfter = normalizedTimestamp(status.notAfter);
  const renewalTime = normalizedTimestamp(status.renewalTime);
  if (generation !== undefined) observation.certificateGeneration = generation;
  if (version) observation.resourceVersion = version;
  if (revision !== undefined) observation.revision = revision;
  if (notBefore) observation.notBefore = notBefore;
  if (notAfter) observation.notAfter = notAfter;
  if (renewalTime) observation.renewalTime = renewalTime;
  Object.assign(observation, requestFailure, certificateFailure);
  return observation;
}

function errorCode(error) {
  const code = boundedText(error?.code, MAX_IDENTIFIER_LENGTH);
  return code || "CERT_MANAGER_WATCH_FAILED";
}

function errorStatus(error) {
  const status = error?.statusCode ?? error?.status ?? error?.code;
  return Number(status);
}

function restartDelay({ attempt, baseDelayMs, maxDelayMs, random }) {
  const exponential = Math.min(
    maxDelayMs,
    baseDelayMs * 2 ** Math.min(Math.max(attempt, 0), 16),
  );
  const jitter = Math.floor(
    Math.max(0, Math.min(1, Number(random()))) * Math.min(exponential, baseDelayMs),
  );
  return Math.min(maxDelayMs, exponential + jitter);
}

function closeWatch(handle) {
  if (typeof handle === "function") return handle();
  if (handle && typeof handle.close === "function") return handle.close();
  return undefined;
}

function createCertManagerObserver({
  client,
  clusterId,
  logger = { debug() {}, error() {}, info() {}, warn() {} },
  now = () => new Date().toISOString(),
  observationHandler,
  random = Math.random,
  restartBaseDelayMs = 250,
  restartMaxDelayMs = 30_000,
  scheduler = { clearTimeout, setTimeout },
  watchNamespaces = [],
  workspaceId,
} = {}) {
  if (!client || typeof client.list !== "function" || typeof client.watch !== "function") {
    throw new TypeError("client.list and client.watch are required");
  }
  if (!scheduler || typeof scheduler.setTimeout !== "function" || typeof scheduler.clearTimeout !== "function") {
    throw new TypeError("scheduler.setTimeout and scheduler.clearTimeout are required");
  }
  if (!Array.isArray(watchNamespaces)) {
    throw new TypeError("watchNamespaces must be an array");
  }

  const certificateByIdentity = new Map();
  const certificateIdentityByName = new Map();
  const certificateRequestByIdentity = new Map();
  const processedResourceVersions = new Map();
  const workByCertificateIdentity = new Map();
  const states = [];
  let acceptingWork = false;
  let closed = false;
  let started = false;
  let trackWork = (work) => Promise.resolve(work);

  const namespaces = watchNamespaces.length === 0 ? [undefined] : [...watchNamespaces];
  for (const namespace of namespaces) {
    for (const resource of WATCHED_RESOURCES) {
      states.push({
        namespace,
        resource,
        resourceVersion: undefined,
        restartAttempt: 0,
        restartTimer: null,
        synced: false,
        watch: null,
        watchGeneration: 0,
      });
    }
  }

  function safeLog(level, message, metadata) {
    const method = typeof logger[level] === "function" ? logger[level] : logger.warn;
    method.call(logger, message, metadata);
  }

  function relevantCertificateRequest(certificate) {
    return selectCertificateRequest(
      certificate,
      [...certificateRequestByIdentity.values()],
    );
  }

  function queueObservation(certificate) {
    if (!acceptingWork || closed) return;
    const identity = resourceIdentity(certificate);
    if (!identity) {
      safeLog("warn", "cert-manager-observation-skipped", {
        code: "CERT_MANAGER_OBSERVATION_IDENTITY_INVALID",
      });
      return;
    }

    let state = workByCertificateIdentity.get(identity);
    if (!state) {
      state = { pending: null, running: false };
      workByCertificateIdentity.set(identity, state);
    }
    state.pending = certificate;
    if (state.running) return;
    state.running = true;

    const flush = async () => {
      while (state.pending) {
        const next = state.pending;
        state.pending = null;
        const observation = mapCertificateObservation({
          certificate: next,
          certificateRequest: relevantCertificateRequest(next),
          clusterId,
          now,
          workspaceId,
        });
        if (!observation) continue;
        if (typeof observationHandler !== "function") {
          safeLog("warn", "cert-manager-observation-not-delivered", {
            certificateName: observation.certificateName,
            code: "CERT_MANAGER_OBSERVATION_DELIVERY_UNAVAILABLE",
            namespace: observation.namespace,
          });
          continue;
        }
        try {
          await observationHandler(observation);
        } catch (error) {
          safeLog("warn", "cert-manager-observation-delivery-failed", {
            certificateName: observation.certificateName,
            code: errorCode(error),
            namespace: observation.namespace,
          });
        }
      }
    };

    let tracked;
    try {
      tracked = trackWork(Promise.resolve().then(flush));
    } catch (error) {
      state.running = false;
      safeLog("warn", "cert-manager-observation-not-tracked", {
        code: errorCode(error),
      });
      return;
    }
    Promise.resolve(tracked).finally(() => {
      state.running = false;
      if (state.pending && acceptingWork && !closed) queueObservation(state.pending);
      else if (!state.pending) workByCertificateIdentity.delete(identity);
    });
  }

  function removeCertificate(certificate) {
    const identity = resourceIdentity(certificate);
    const nameIdentity = resourceNameIdentity(certificate);
    if (identity) {
      certificateByIdentity.delete(identity);
      const work = workByCertificateIdentity.get(identity);
      if (work) work.pending = null;
    }
    if (nameIdentity && certificateIdentityByName.get(nameIdentity) === identity) {
      certificateIdentityByName.delete(nameIdentity);
    }
  }

  function removeProcessedResourceVersion(resource, identity) {
    if (identity) processedResourceVersions.delete(`${resource}:${identity}`);
  }

  function resourceIsInNamespace(resource, namespace) {
    return (
      namespace === undefined ||
      objectValue(resource?.metadata).namespace === namespace
    );
  }

  function updateCertificate(certificate) {
    const identity = resourceIdentity(certificate);
    const nameIdentity = resourceNameIdentity(certificate);
    if (!identity || !nameIdentity) return;
    const previousIdentity = certificateIdentityByName.get(nameIdentity);
    if (previousIdentity && previousIdentity !== identity) {
      certificateByIdentity.delete(previousIdentity);
      workByCertificateIdentity.delete(previousIdentity);
    }
    certificateIdentityByName.set(nameIdentity, identity);
    certificateByIdentity.set(identity, certificate);
    queueObservation(certificate);
  }

  function updateCertificateRequest(certificateRequest) {
    const identity = resourceIdentity(certificateRequest);
    if (!identity) return;
    certificateRequestByIdentity.set(identity, certificateRequest);
    for (const certificate of certificateByIdentity.values()) {
      if (certificateRequestMatches(certificateRequest, certificate)) {
        queueObservation(certificate);
      }
    }
  }

  function removeCertificateRequest(certificateRequest) {
    const identity = resourceIdentity(certificateRequest);
    const cachedRequest = identity && certificateRequestByIdentity.get(identity);
    if (!cachedRequest) return;

    const affectedCertificates = [...certificateByIdentity.values()].filter(
      (certificate) => relevantCertificateRequest(certificate) === cachedRequest,
    );
    certificateRequestByIdentity.delete(identity);
    for (const certificate of affectedCertificates) queueObservation(certificate);
  }

  function reconcileRelistedResources(resource, namespace, items) {
    const listedIdentities = new Set(
      (Array.isArray(items) ? items : [])
        .map((item) => resourceIdentity(item))
        .filter(Boolean),
    );

    if (resource === "Certificate") {
      for (const [identity, certificate] of certificateByIdentity.entries()) {
        if (
          resourceIsInNamespace(certificate, namespace) &&
          !listedIdentities.has(identity)
        ) {
          removeProcessedResourceVersion(resource, identity);
          removeCertificate(certificate);
        }
      }
      return;
    }

    for (const [identity, certificateRequest] of certificateRequestByIdentity.entries()) {
      if (
        resourceIsInNamespace(certificateRequest, namespace) &&
        !listedIdentities.has(identity)
      ) {
        removeProcessedResourceVersion(resource, identity);
        removeCertificateRequest(certificateRequest);
      }
    }
  }

  function processResourceEvent(resource, phase, object, state) {
    if (!object || typeof object !== "object") return;
    const version = resourceVersion(object);
    if (phase === "BOOKMARK") {
      if (version) state.resourceVersion = version;
      return;
    }
    if (phase === "ERROR") {
      scheduleRestart(state, object);
      return;
    }

    const identity = resourceIdentity(object);
    if (!identity) return;
    const processedKey = `${resource}:${identity}`;
    if (version && processedResourceVersions.get(processedKey) === version) return;
    if (version) {
      processedResourceVersions.set(processedKey, version);
      state.resourceVersion = version;
    }

    if (phase === "DELETED") {
      processedResourceVersions.delete(processedKey);
      if (resource === "Certificate") removeCertificate(object);
      else removeCertificateRequest(object);
      return;
    }
    if (resource === "Certificate") updateCertificate(object);
    else updateCertificateRequest(object);
  }

  function cancelStateWatch(state) {
    state.watchGeneration += 1;
    const handle = state.watch;
    state.watch = null;
    if (handle) {
      try {
        closeWatch(handle);
      } catch (_error) {
        // Shutdown and retry paths must keep closing the remaining watches.
      }
    }
  }

  function scheduleRestart(state, error) {
    if (closed || !acceptingWork || state.restartTimer) return;
    state.synced = false;
    cancelStateWatch(state);
    const expiredResourceVersion = errorStatus(error) === 410;
    const delay = restartDelay({
      attempt: expiredResourceVersion ? 0 : state.restartAttempt,
      baseDelayMs: restartBaseDelayMs,
      maxDelayMs: restartMaxDelayMs,
      random,
    });
    state.restartAttempt += 1;
    safeLog("warn", "cert-manager-watch-restarting", {
      code: expiredResourceVersion ? "CERT_MANAGER_RESOURCE_VERSION_EXPIRED" : errorCode(error),
      namespace: state.namespace || "all",
      resource: state.resource,
    });
    state.restartTimer = scheduler.setTimeout(() => {
      state.restartTimer = null;
      void synchronizeAndWatch(state);
    }, delay);
  }

  async function synchronizeAndWatch(state) {
    if (closed || !acceptingWork) return;
    const generation = ++state.watchGeneration;
    try {
      const list = await client.list({
        namespace: state.namespace,
        resource: state.resource,
      });
      if (closed || !acceptingWork || generation !== state.watchGeneration) return;
      state.resourceVersion = list.resourceVersion;
      for (const item of list.items) {
        processResourceEvent(state.resource, "ADDED", item, state);
      }
      reconcileRelistedResources(state.resource, state.namespace, list.items);
      // The list response's resourceVersion is the consistent cursor for the
      // follow-on watch. Individual list items may have older revisions.
      state.resourceVersion = list.resourceVersion || state.resourceVersion;
      const watch = await client.watch({
        namespace: state.namespace,
        onError: (error) => {
          if (generation === state.watchGeneration) scheduleRestart(state, error);
        },
        onEvent: (phase, object) => {
          if (generation === state.watchGeneration) {
            // A real watch event (including a bookmark) confirms the new
            // cursor is live, so later transient failures start at the base
            // delay again. A watch that immediately closes keeps escalating.
            if (phase !== "ERROR") state.restartAttempt = 0;
            processResourceEvent(state.resource, phase, object, state);
          }
        },
        resource: state.resource,
        resourceVersion: state.resourceVersion,
      });
      if (closed || !acceptingWork || generation !== state.watchGeneration) {
        closeWatch(watch);
        return;
      }
      state.watch = watch;
      state.synced = true;
    } catch (error) {
      if (generation === state.watchGeneration) scheduleRestart(state, error);
    }
  }

  async function start({ trackWork: suppliedTrackWork } = {}) {
    if (started) return;
    started = true;
    acceptingWork = true;
    if (typeof suppliedTrackWork === "function") trackWork = suppliedTrackWork;
    if (typeof client.start === "function") await client.start();
    await Promise.all(states.map((state) => synchronizeAndWatch(state)));
  }

  async function stopAcceptingWork() {
    acceptingWork = false;
    for (const state of states) {
      if (state.restartTimer) {
        scheduler.clearTimeout(state.restartTimer);
        state.restartTimer = null;
      }
      state.synced = false;
      cancelStateWatch(state);
    }
  }

  async function close() {
    if (closed) return;
    closed = true;
    await stopAcceptingWork();
    if (typeof client.close === "function") await client.close();
  }

  return {
    close,
    isAlive() {
      return started && !closed;
    },
    isReady() {
      return started && acceptingWork && states.every((state) => state.synced);
    },
    start,
    stopAcceptingWork,
  };
}

module.exports = {
  CERTIFICATE_NAME_ANNOTATION,
  CERTIFICATE_REVISION_ANNOTATION,
  MAX_CONDITIONS,
  MAX_DNS_NAMES,
  OBSERVATION_SCHEMA_VERSION,
  OBSERVATION_SOURCE,
  WATCHED_RESOURCES,
  certificateRequestMatches,
  createCertManagerObserver,
  mapCertificateObservation,
  normalizedConditions,
  restartDelay,
  selectCertificateRequest,
};
