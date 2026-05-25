const { isInternalWorkerRequest } = require("./internal-worker-auth");

function createCsrfExemptMiddleware(doubleCsrfProtection, options = {}) {
  const allowPath = options.allowPath || (() => false);

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
    if (allowPath(requestPath)) return next();

    return doubleCsrfProtection(req, res, next);
  };
}

module.exports = {
  createCsrfExemptMiddleware,
};
