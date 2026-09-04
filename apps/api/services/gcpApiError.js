"use strict";

/**
 * Turn a GCP axios/API failure into an operator-facing sentence.
 * Axios's default "Request failed with status code 403" hides whether
 * the API is disabled, the token is the wrong identity, or a role is
 * actually missing.
 */

function gcpErrorPayload(error) {
  if (error?.body && typeof error.body === "object") return error.body;
  if (error?.response?.data && typeof error.response.data === "object") {
    return error.response.data;
  }
  return null;
}

function gcpErrorReason(data) {
  const details = data?.error?.details;
  if (Array.isArray(details)) {
    for (const detail of details) {
      if (detail && typeof detail.reason === "string" && detail.reason.trim()) {
        return detail.reason.trim();
      }
    }
  }
  const first = Array.isArray(data?.error?.errors) ? data.error.errors[0] : null;
  if (first && typeof first.reason === "string" && first.reason.trim()) {
    return first.reason.trim();
  }
  if (typeof data?.error?.status === "string" && data.error.status.trim()) {
    return data.error.status.trim();
  }
  return null;
}

function gcpErrorMessage(data) {
  if (typeof data?.error?.message === "string" && data.error.message.trim()) {
    return data.error.message.trim();
  }
  if (typeof data?.error === "string" && data.error.trim()) {
    return data.error.trim();
  }
  if (typeof data?.message === "string" && data.message.trim()) {
    return data.message.trim();
  }
  return null;
}

function roleHint(kindLabel) {
  if (kindLabel === "Compute Engine SSL certificates") {
    return (
      "Grant Compute Viewer (roles/compute.viewer) on the project to the " +
      "identity that minted this access token. gcloud auth print-access-token " +
      "is your user, not a service account, unless you impersonate that account."
    );
  }
  if (kindLabel === "Certificate Manager") {
    return (
      "Grant Certificate Manager Viewer (roles/certificatemanager.viewer) " +
      "to the identity that minted this access token."
    );
  }
  return (
    "Grant Secret Manager Viewer (roles/secretmanager.viewer) to the " +
    "identity that minted this access token. Secret Accessor cannot list secrets."
  );
}

function disabledApiHint(kindLabel) {
  if (kindLabel === "Compute Engine SSL certificates") {
    return "Compute Engine API (compute.googleapis.com)";
  }
  if (kindLabel === "Certificate Manager") {
    return "Certificate Manager API (certificatemanager.googleapis.com)";
  }
  return "Secret Manager API (secretmanager.googleapis.com)";
}

function formatGcpApiError(error, kindLabel) {
  const prefix = kindLabel ? `${kindLabel}: ` : "";
  const status = error?.status || error?.response?.status || null;
  const data = gcpErrorPayload(error);
  const reason = gcpErrorReason(data);
  const googleMessage = gcpErrorMessage(data);
  const raw = [googleMessage, reason, error?.message]
    .filter(Boolean)
    .join(" ");

  if (
    reason === "SERVICE_DISABLED" ||
    reason === "accessNotConfigured" ||
    /API has not been used|is disabled|API_NOT_ACTIVATED/i.test(raw)
  ) {
    return (
      `${prefix}this project's ${disabledApiHint(kindLabel)} is not enabled. ` +
      "Enable it in APIs & Services, then retry."
    );
  }

  if (reason === "ACCESS_TOKEN_SCOPE_INSUFFICIENT") {
    return (
      `${prefix}this access token is missing the required OAuth scope. ` +
      "Mint a new one with gcloud auth print-access-token after a " +
      "cloud-platform login."
    );
  }

  if (status === 403 || reason === "PERMISSION_DENIED") {
    const permissionMatch =
      typeof googleMessage === "string"
        ? googleMessage.match(/(?:Permission|Required)\s+['"]([^'"]+)['"]/i)
        : null;
    const permission = permissionMatch ? permissionMatch[1] : null;
    if (permission) {
      return `${prefix}missing ${permission}. ${roleHint(kindLabel)}`;
    }
    return `${prefix}permission denied. ${roleHint(kindLabel)}`;
  }

  if (status === 401 || reason === "UNAUTHENTICATED") {
    return (
      `${prefix}the access token is expired or invalid. Generate a fresh ` +
      "one with gcloud auth print-access-token."
    );
  }

  if (googleMessage) return `${prefix}${googleMessage}`;
  if (
    error?.message &&
    !/^Request failed with status code \d+$/.test(error.message)
  ) {
    return `${prefix}${error.message}`;
  }
  if (status) return `${prefix}request failed with HTTP ${status}.`;
  return `${prefix}request failed.`;
}

module.exports = {
  formatGcpApiError,
};
