"use strict";

const CERT_MANAGER_GROUP = "cert-manager.io";
const CERT_MANAGER_VERSION = "v1";

const RESOURCE_SPECS = Object.freeze({
  Certificate: Object.freeze({ plural: "certificates" }),
  CertificateRequest: Object.freeze({ plural: "certificaterequests" }),
});

function resourceSpec(resource) {
  const spec = RESOURCE_SPECS[resource];
  if (!spec) {
    throw new TypeError(`Unsupported cert-manager resource: ${resource}`);
  }
  return spec;
}

function resourcePath({ resource, namespace }) {
  const { plural } = resourceSpec(resource);
  const base = `/apis/${CERT_MANAGER_GROUP}/${CERT_MANAGER_VERSION}`;
  return namespace
    ? `${base}/namespaces/${encodeURIComponent(namespace)}/${plural}`
    : `${base}/${plural}`;
}

function normalizeListResponse(response) {
  const body = response && typeof response === "object" && response.body
    ? response.body
    : response;
  return {
    items: Array.isArray(body?.items) ? body.items : [],
    resourceVersion:
      typeof body?.metadata?.resourceVersion === "string"
        ? body.metadata.resourceVersion
        : undefined,
  };
}

function createInClusterCertManagerClient({
  loadClient = () => import("@kubernetes/client-node"),
  secretFallbackEnabled = false,
  provisionEnabled = false,
} = {}) {
  let apiClient;
  let coreApiClient;
  let watchClient;
  let mergePatchRequestOptions;
  let started = false;
  const activeControllers = new Set();

  async function start() {
    if (started) return;

    const kubernetes = await loadClient();
    if (
      !kubernetes?.KubeConfig ||
      !kubernetes?.CustomObjectsApi ||
      !kubernetes?.Watch ||
      (secretFallbackEnabled && !kubernetes?.CoreV1Api)
    ) {
      throw new TypeError("Kubernetes client does not expose cert-manager watch APIs");
    }

    const config = new kubernetes.KubeConfig();
    // Deliberately do not call loadFromDefault(): controller access is only
    // through the mounted ServiceAccount credentials in its own cluster.
    config.loadFromCluster();
    apiClient = config.makeApiClient(kubernetes.CustomObjectsApi);
    // CoreV1Api is deliberately constructed only for the explicitly enabled,
    // narrow public-certificate fallback. It is never exposed to callers.
    if (secretFallbackEnabled) {
      coreApiClient = config.makeApiClient(kubernetes.CoreV1Api);
    }
    watchClient = new kubernetes.Watch(config);
    // The generated 1.4.0 client otherwise prefers JSON Patch before Merge
    // Patch. This narrow per-call middleware runs after request construction
    // and deliberately selects Merge Patch for the complete object body.
    mergePatchRequestOptions = {
      middleware: [{
        pre(context) {
          context.setHeaderParam("Content-Type", "application/merge-patch+json");
          return new kubernetes.Observable(Promise.resolve(context));
        },
        post(context) {
          return new kubernetes.Observable(Promise.resolve(context));
        },
      }],
      middlewareMergeStrategy: "append",
    };
    started = true;
  }

  function requireStarted() {
    if (!started) {
      throw new Error("Cert-manager client has not started");
    }
  }

  async function list({ resource, namespace } = {}) {
    requireStarted();
    const { plural } = resourceSpec(resource);
    const response = namespace
      ? await apiClient.listNamespacedCustomObject({
        group: CERT_MANAGER_GROUP,
        namespace,
        plural,
        version: CERT_MANAGER_VERSION,
      })
      : await apiClient.listClusterCustomObject({
        group: CERT_MANAGER_GROUP,
        plural,
        version: CERT_MANAGER_VERSION,
      });
    return normalizeListResponse(response);
  }

  async function watch({
    resource,
    namespace,
    resourceVersion,
    onEvent,
    onError,
  } = {}) {
    requireStarted();
    const watchState = { controller: null };
    const controller = await watchClient.watch(
      resourcePath({ resource, namespace }),
      {
        allowWatchBookmarks: true,
        resourceVersion: resourceVersion || undefined,
      },
      (phase, object) => {
        if (typeof onEvent === "function") onEvent(phase, object);
      },
      (error) => {
        if (watchState.controller) {
          activeControllers.delete(watchState.controller);
        }
        if (typeof onError === "function") onError(error);
      },
    );
    watchState.controller = controller;
    activeControllers.add(controller);

    return {
      close() {
        activeControllers.delete(controller);
        controller.abort();
      },
    };
  }

  async function readTlsCertificate({ namespace, secretName } = {}) {
    requireStarted();
    if (!secretFallbackEnabled || !coreApiClient) {
      const error = new Error("Secret fallback is disabled");
      error.code = "CERTOPS_SECRET_FALLBACK_DISABLED";
      throw error;
    }
    if (
      typeof namespace !== "string" ||
      namespace.trim() === "" ||
      typeof secretName !== "string" ||
      secretName.trim() === ""
    ) {
      const error = new TypeError("A namespace and Secret name are required");
      error.code = "CERTOPS_TLS_CRT_MISSING";
      throw error;
    }

    const response = await coreApiClient.readNamespacedSecret({
      namespace,
      name: secretName,
    });
    const secret = response && typeof response === "object" && response.body
      ? response.body
      : response;
    // Kubernetes returns the whole Secret for a `get`; this boundary reads one
    // allowlisted member and returns only its encoded public-certificate value.
    const data = secret && typeof secret === "object" ? secret.data : undefined;
    const encodedCertificate =
      data && typeof data === "object" ? data["tls.crt"] : undefined;
    return typeof encodedCertificate === "string" ? encodedCertificate : undefined;
  }

  function provisioningDisabled() {
    const error = new Error("Certificate provisioning is disabled");
    error.code = "CERTOPS_PROVISIONING_DISABLED";
    return error;
  }

  function certificateRequest({ namespace, name, body } = {}) {
    if (!provisionEnabled) throw provisioningDisabled();
    if (typeof namespace !== "string" || !namespace || typeof name !== "string" || !name) {
      throw new TypeError("A Certificate namespace and name are required");
    }
    return {
      group: CERT_MANAGER_GROUP,
      version: CERT_MANAGER_VERSION,
      namespace,
      plural: RESOURCE_SPECS.Certificate.plural,
      name,
      ...(body ? { body } : {}),
    };
  }

  async function getCertificate({ namespace, name } = {}) {
    requireStarted();
    return apiClient.getNamespacedCustomObject(certificateRequest({ namespace, name }));
  }

  async function createCertificate({ namespace, name, certificate } = {}) {
    requireStarted();
    return apiClient.createNamespacedCustomObject(
      certificateRequest({ namespace, name, body: certificate }),
    );
  }

  async function patchCertificate({ namespace, name, certificate } = {}) {
    requireStarted();
    return apiClient.patchNamespacedCustomObject({
      ...certificateRequest({ namespace, name, body: certificate }),
      fieldManager: "tokentimer-certops-controller",
    }, mergePatchRequestOptions);
  }

  async function close() {
    const controllers = [...activeControllers];
    activeControllers.clear();
    for (const controller of controllers) {
      controller.abort();
    }
  }

  return Object.freeze({
    close,
    createCertificate,
    getCertificate,
    list,
    patchCertificate,
    readTlsCertificate,
    start,
    watch,
  });
}

module.exports = {
  CERT_MANAGER_GROUP,
  CERT_MANAGER_VERSION,
  RESOURCE_SPECS,
  createInClusterCertManagerClient,
  normalizeListResponse,
  resourcePath,
};
