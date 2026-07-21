"use strict";

const { containsPrivateKeyMaterial } = require("@tokentimer/log-scrub");

const OWNERSHIP_LABELS = Object.freeze({
  managedBy: "app.kubernetes.io/managed-by",
  intentId: "certops.tokentimer.io/intent-id",
  workspaceId: "certops.tokentimer.io/workspace-id",
  clusterId: "certops.tokentimer.io/cluster-id",
  managedCertificateId: "certops.tokentimer.io/managed-certificate-id",
});

function provisionerError(code) {
  const error = new Error(`Certificate provisioning failed: ${code}`);
  error.code = code;
  return error;
}

function responseBody(response) {
  return response && typeof response === "object" && response.body ? response.body : response;
}

function isNotFound(error) {
  return Number(error?.statusCode || error?.status || error?.code) === 404;
}

function ownershipFor(command) {
  return {
    [OWNERSHIP_LABELS.managedBy]: "tokentimer",
    [OWNERSHIP_LABELS.intentId]: command.jobId,
    [OWNERSHIP_LABELS.workspaceId]: command.workspaceId,
    [OWNERSHIP_LABELS.clusterId]: command.clusterId,
    [OWNERSHIP_LABELS.managedCertificateId]: command.managedCertificateId,
  };
}

function certificateFor(command) {
  return {
    apiVersion: "cert-manager.io/v1",
    kind: "Certificate",
    metadata: {
      name: command.certificateName,
      namespace: command.namespace,
      labels: ownershipFor(command),
    },
    spec: {
      secretName: command.secretName,
      dnsNames: [...command.dnsNames],
      issuerRef: {
        group: command.issuerRef.group,
        kind: command.issuerRef.kind,
        name: command.issuerRef.name,
      },
    },
  };
}

function isOwnedByCommand(existing, command) {
  const labels = existing?.metadata?.labels || {};
  const expected = ownershipFor(command);
  return Object.entries(expected).every(([key, value]) => labels[key] === value);
}

function hasDesiredState(existing, command) {
  const desired = certificateFor(command);
  const spec = existing?.spec || {};
  return isOwnedByCommand(existing, command) &&
    spec.secretName === desired.spec.secretName &&
    JSON.stringify([...(spec.dnsNames || [])].sort()) === JSON.stringify([...desired.spec.dnsNames].sort()) &&
    spec.issuerRef?.group === desired.spec.issuerRef.group &&
    spec.issuerRef?.kind === desired.spec.issuerRef.kind &&
    spec.issuerRef?.name === desired.spec.issuerRef.name;
}

function createCertificateProvisioner({ client, clusterId, clusterWide = false, watchNamespaces = [] } = {}) {
  if (!client) throw new TypeError("A cert-manager client is required");

  function assertLocalPolicy(command) {
    if (command.clusterId !== clusterId) throw provisionerError("CERTOPS_PROVISIONING_CLUSTER_MISMATCH");
    if (!clusterWide && !watchNamespaces.includes(command.namespace)) {
      throw provisionerError("CERTOPS_PROVISIONING_NAMESPACE_FORBIDDEN");
    }
  }

  async function reconcile(command) {
    if (containsPrivateKeyMaterial(command)) {
      throw provisionerError("PRIVATE_KEY_MATERIAL_REJECTED");
    }
    assertLocalPolicy(command);
    const desired = certificateFor(command);
    let existing;
    try {
      existing = responseBody(await client.getCertificate({
        namespace: command.namespace,
        name: command.certificateName,
      }));
    } catch (error) {
      if (!isNotFound(error)) throw error;
      const created = responseBody(await client.createCertificate({
        namespace: command.namespace,
        name: command.certificateName,
        certificate: desired,
      }));
      return { operation: "created", resource: created || null };
    }
    if (!isOwnedByCommand(existing, command)) {
      throw provisionerError("CERTOPS_K8S_UNMANAGED_RESOURCE_CONFLICT");
    }
    if (hasDesiredState(existing, command)) return { operation: "unchanged", resource: existing };
    const patched = responseBody(await client.patchCertificate({
      namespace: command.namespace,
      name: command.certificateName,
      certificate: desired,
    }));
    return { operation: "reconciled", resource: patched || null };
  }

  return Object.freeze({
    reconcile,
    isReady: () => true,
    stopAcceptingWork: async () => {},
    close: async () => {},
  });
}

module.exports = {
  OWNERSHIP_LABELS,
  certificateFor,
  createCertificateProvisioner,
  hasDesiredState,
  isOwnedByCommand,
  ownershipFor,
};
