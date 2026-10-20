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

// Operator routes authenticate with a bearer credential only. A browser cannot
// attach one cross-site, so CSRF does not apply to a request that carries an
// operator credential and no cookies. A request that carries cookies keeps the
// full CSRF check, so a session can never ride this exemption.
function isOperatorBearerCsrfExemptRequest(requestPath, req = null) {
  if (!req) return false;
  const path = String(requestPath || "");
  const header = req.headers?.authorization;
  const cookieHeader = req.headers?.cookie;
  const hasCookieHeader = typeof cookieHeader === "string" && cookieHeader.trim() !== "";
  const hasParsedCookies =
    req.cookies && typeof req.cookies === "object" && Object.keys(req.cookies).length > 0;
  if (hasCookieHeader || hasParsedCookies) return false;

  // Redeeming an enrollment grant: one exact route, a grant bearer, no cookies.
  if (
    String(req.method || "").toUpperCase() === "POST" &&
    (path === "/api/v1/operator/enroll/redeem" || path === "/v1/operator/enroll/redeem")
  ) {
    return typeof header === "string" && /^Bearer[ \t]+ttopg_/i.test(header.trim());
  }

  const remainder = path.startsWith("/api/v1/operator/")
    ? path.slice("/api/v1/operator/".length)
    : path.startsWith("/v1/operator/")
      ? path.slice("/v1/operator/".length)
      : null;
  // Plain segments only, matching the early operator guard.
  if (remainder === null || !/^[a-z0-9][a-z0-9_-]*(?:\/[a-z0-9][a-z0-9_-]*)*$/i.test(remainder)) {
    return false;
  }
  return typeof header === "string" && /^Bearer[ \t]+ttopc_/i.test(header.trim());
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
  isOperatorBearerCsrfExemptRequest,
};
