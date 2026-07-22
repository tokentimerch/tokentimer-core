const { isInternalWorkerRequest } = require("./internal-worker-auth");
const {
  certOpsMachineWriteRouteFamily,
} = require("./certops-executor-body-parser");

// Keep the CSRF decision aligned with the pre-parser boundary. The mounted
// /api middleware sees /v1/... while direct test/router use sees /api/v1/....
// Covers the executor/controller/per-job machine writes and the M4
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

  return (req, res, next) => {
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
