"use strict";

/**
 * Maps CMC helper disposition + certreq HRESULT onto issuer outcomes
 * (ADR-0014 decision 9 table). Console text is never consulted.
 */

/** @typedef {"submit"|"retrieve"} AdcsPhase */

const HRESULT = Object.freeze({
  S_OK: 0,
  CERTSRV_E_ADMIN_DENIED_REQUEST: 0x80094014,
  CERTSRV_E_TEMPLATE_DENIED: 0x80094012,
  CERTSRV_E_UNSUPPORTED_CERT_TYPE: 0x80094800,
  CERTSRV_E_KEY_LENGTH: 0x80094811,
  CERTSRV_E_BAD_REQUESTSTATUS: 0x80094003,
  E_ACCESSDENIED: 0x80070005,
  CERTSRV_E_PROPERTY_EMPTY: 0x80094004,
  RPC_S_SERVER_UNAVAILABLE: 0x800706ba,
  RPC_S_CALL_FAILED_DNE: 0x800706bf,
  RPC_S_CALL_FAILED: 0x800706be,
});

function toUint32(code) {
  if (typeof code !== "number" || !Number.isFinite(code)) return null;
  return code >>> 0;
}

function hexHresult(code) {
  const u = toUint32(code);
  if (u === null) return "unknown";
  return `0x${u.toString(16)}`;
}

/**
 * @param {object} params
 * @param {AdcsPhase} params.phase
 * @param {boolean} params.responsePresent
 * @param {boolean} params.certificatePresent
 * @param {boolean} params.chainPresent
 * @param {number|null|undefined} params.exitCode certreq process exit / HRESULT
 * @param {{ disposition?: string, requestId?: number, certificateDerB64?: string, error?: string }|null} params.cmc
 */
function mapAdcsDisposition({
  phase,
  responsePresent,
  certificatePresent,
  chainPresent = false,
  exitCode,
  cmc,
}) {
  const hr = toUint32(exitCode);
  const hrText = hexHresult(exitCode);

  // Narrow not_submitted: RPC pair + no response/certificate/chain on submit.
  if (
    phase === "submit" &&
    !responsePresent &&
    !certificatePresent &&
    !chainPresent &&
    (hr === HRESULT.RPC_S_SERVER_UNAVAILABLE || hr === HRESULT.RPC_S_CALL_FAILED_DNE)
  ) {
    return {
      outcome: "not_submitted",
      detail: `CA unreachable (${hrText}); no CMC response, certificate, or chain was written`,
      hresult: hr,
    };
  }

  // RPC pair with any artefact written is uncertain (may have executed).
  if (
    phase === "submit" &&
    (hr === HRESULT.RPC_S_SERVER_UNAVAILABLE || hr === HRESULT.RPC_S_CALL_FAILED_DNE) &&
    (responsePresent || certificatePresent || chainPresent)
  ) {
    return {
      outcome: "uncertain",
      detail: `CA RPC failure (${hrText}) but a response/certificate/chain artefact was written`,
      hresult: hr,
    };
  }

  if (!cmc || typeof cmc.disposition !== "string") {
    return {
      outcome: "uncertain",
      detail: `ADCS_DISPOSITION_UNKNOWN: no usable CMC decode (certreq ${hrText})`,
      hresult: hr,
    };
  }

  switch (cmc.disposition) {
    case "issued": {
      if (typeof cmc.certificateDerB64 !== "string" || cmc.certificateDerB64.length === 0) {
        return {
          outcome: "uncertain",
          detail: "CMC success without certificateDerB64",
          hresult: hr,
        };
      }
      return {
        outcome: "issued",
        certificateDerB64: cmc.certificateDerB64,
        hresult: hr,
      };
    }
    case "pending": {
      if (hr !== HRESULT.S_OK) {
        return {
          outcome: "uncertain",
          detail: `CMC pending with unexpected certreq exit ${hrText}`,
          hresult: hr,
        };
      }
      if (!Number.isInteger(cmc.requestId) || cmc.requestId < 1) {
        return {
          outcome: "uncertain",
          detail: "CMC pending without requestId",
          hresult: hr,
        };
      }
      return {
        outcome: "pending",
        requestId: cmc.requestId,
        hresult: hr,
      };
    }
    case "denied": {
      if (phase === "submit") {
        return {
          outcome: "denied",
          detail: `CA denied the request (${hrText})`,
          hresult: hr,
        };
      }
      // retrieve: only admin deny is denied; other failed statuses stay uncertain
      if (hr === HRESULT.CERTSRV_E_ADMIN_DENIED_REQUEST) {
        return {
          outcome: "denied",
          detail: `CA manager denied the request (${hrText})`,
          hresult: hr,
        };
      }
      if (hr === HRESULT.E_ACCESSDENIED || hr === HRESULT.CERTSRV_E_PROPERTY_EMPTY) {
        return {
          outcome: "uncertain",
          detail: `retrieve failed for RequestId (${hrText})`,
          hresult: hr,
        };
      }
      return {
        outcome: "uncertain",
        detail: `CMC failed on retrieve with unmapped HRESULT ${hrText}`,
        hresult: hr,
      };
    }
    case "unknown":
    default:
      return {
        outcome: "uncertain",
        detail: `ADCS_DISPOSITION_UNKNOWN: ${cmc.error || cmc.disposition || "unknown"} (${hrText})`,
        hresult: hr,
      };
  }
}

module.exports = {
  HRESULT,
  mapAdcsDisposition,
  toUint32,
  hexHresult,
};
