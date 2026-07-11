const { isInternalWorkerRequest } = require("./internal-worker-auth");

// Add a route here only when its machine-token middleware is explicitly mounted.
const CERTOPS_MACHINE_TOKEN_CSRF_EXEMPT_PATHS = new Set([
  "/v1/certops/executor/events",
  "/api/v1/certops/executor/events",
]);

function isCertOpsMachineTokenCsrfExemptPath(requestPath) {
  return CERTOPS_MACHINE_TOKEN_CSRF_EXEMPT_PATHS.has(requestPath);
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
  CERTOPS_MACHINE_TOKEN_CSRF_EXEMPT_PATHS,
  createCsrfExemptMiddleware,
  isCertOpsMachineTokenCsrfExemptPath,
};
