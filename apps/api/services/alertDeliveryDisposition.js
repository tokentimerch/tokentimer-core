"use strict";

function discardedAlertReason(status, errorMessage) {
  if (status !== "sent" || !/^Discarded:/i.test(String(errorMessage || ""))) {
    return null;
  }
  if (/certificate revoked or decommissioned/i.test(errorMessage)) {
    return "retired_certificate";
  }
  if (/endpoint recovered/i.test(errorMessage)) {
    return "endpoint_recovered";
  }
  return "alert_discarded";
}

module.exports = { discardedAlertReason };
