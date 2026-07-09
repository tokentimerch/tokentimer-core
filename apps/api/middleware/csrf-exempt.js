const { isInternalWorkerRequest } = require("./internal-worker-auth");

function isCertOpsMachineTokenCsrfExemptPath(requestPath) {
  return (
    requestPath === "/v1/certops/executor/events" ||
    requestPath.startsWith("/v1/certops/executor/") ||
    /^\/v1\/certops\/jobs\/[^/]+\/(?:events|evidence)$/.test(requestPath) ||
    requestPath === "/api/v1/certops/executor/events" ||
    requestPath.startsWith("/api/v1/certops/executor/") ||
    /^\/api\/v1\/certops\/jobs\/[^/]+\/(?:events|evidence)$/.test(requestPath)
  );
}

function createCsrfExemptMiddleware(doubleCsrfProtection, options = {}) {
  const allowPath = options.allowPath || isCertOpsMachineTokenCsrfExemptPath;

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
