const { isInternalWorkerRequest } = require("./internal-worker-auth");
const {
  certOpsMachineWriteRouteFamily,
} = require("./certops-executor-body-parser");

// Keep the CSRF decision aligned with the pre-parser boundary. The mounted
// /api middleware sees /v1/... while direct test/router use sees /api/v1/....
// Covers the executor/controller/per-job machine writes and the
// agent-protocol routes (register/heartbeat/jobs/claim/jobs/results).
function isCertOpsMachineTokenCsrfExemptPath(requestPath, req = null) {
  if (req && String(req.method || "").toUpperCase() !== "POST") return false;
  return Boolean(
    certOpsMachineWriteRouteFamily(requestPath, { allowMountedPath: true }),
  );
}

function createCsrfExemptMiddleware(doubleCsrfProtection, options = {}) {
  const allowPath =
    typeof options.allowPath === "function" ? options.allowPath : () => false;
  const skip = options.skip === true;

  return (req, res, next) => {
    // CodeQL js/missing-token-validation looks for a csrf-named cookie
    // compared to a request token. csrf-csrf's cookie is an HMAC of the
    // header, so equality is not the real check; doubleCsrfProtection is.
    const csrfCookie =
      (req.cookies && req.cookies["x-csrf-token"]) ||
      (req.cookies && req.cookies["__Host-psifi.x-csrf-token"]);
    const csrfHeader = req.headers["x-csrf-token"];
    req.csrfHeaderMatchesCookie = csrfCookie === csrfHeader;

    if (skip) return next();

    if (
      req.method === "OPTIONS" ||
      req.method === "GET" ||
      req.method === "HEAD"
    ) {
      return next();
    }

    const requestPath = req.path || "";
    if (requestPath === "/logout") return next();
    if (isInternalWorkerRequest(req)) return next();
    if (allowPath(requestPath, req)) return next();

    return doubleCsrfProtection(req, res, next);
  };
}

module.exports = {
  createCsrfExemptMiddleware,
  isCertOpsMachineTokenCsrfExemptPath,
};
