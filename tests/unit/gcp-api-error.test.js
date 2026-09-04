"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { formatGcpApiError } = require(
  path.resolve(__dirname, "../../apps/api/services/gcpApiError.js"),
);

describe("formatGcpApiError", () => {
  it("names a disabled Compute Engine API instead of axios's 403 string", () => {
    const error = new Error("Request failed with status code 403");
    error.status = 403;
    error.response = {
      status: 403,
      data: {
        error: {
          code: 403,
          message:
            "Compute Engine API has not been used in project tokentimer-467819 before or it is disabled.",
          status: "PERMISSION_DENIED",
          details: [
            {
              reason: "SERVICE_DISABLED",
              metadata: { service: "compute.googleapis.com" },
            },
          ],
        },
      },
    };

    const text = formatGcpApiError(error, "Compute Engine SSL certificates");
    assert.match(text, /Compute Engine API/);
    assert.match(text, /not enabled/);
    assert.equal(text.includes("Request failed with status code 403"), false);
  });

  it("tells the operator the token identity must hold Compute Viewer", () => {
    const error = new Error("Request failed with status code 403");
    error.response = {
      status: 403,
      data: {
        error: {
          code: 403,
          message: "Permission 'compute.sslCertificates.list' denied on resource.",
          status: "PERMISSION_DENIED",
        },
      },
    };

    const text = formatGcpApiError(error, "Compute Engine SSL certificates");
    assert.match(text, /compute\.sslCertificates\.list/);
    assert.match(text, /print-access-token is your user/);
  });

  it("names a Required permission the same way as a Permission denied line", () => {
    const error = new Error("Request failed with status code 403");
    error.response = {
      status: 403,
      data: {
        error: {
          message:
            "Required 'compute.sslCertificates.list' permission for 'projects/proj'",
          status: "PERMISSION_DENIED",
        },
      },
    };
    const text = formatGcpApiError(error, "Compute Engine SSL certificates");
    assert.match(text, /compute\.sslCertificates\.list/);
  });

  it("keeps a non-HTTP Google message when no special reason is present", () => {
    const error = new Error("boom");
    error.response = {
      status: 500,
      data: { error: { message: "backend timeout" } },
    };
    assert.equal(
      formatGcpApiError(error, "Certificate Manager"),
      "Certificate Manager: backend timeout",
    );
  });
});
