const { AsyncLocalStorage } = require("node:async_hooks");
const { randomUUID } = require("node:crypto");

const requestContext = new AsyncLocalStorage();

function isRequestCorrelationId(value) {
  return typeof value === "string" && value.length === 36 &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function getRequestContext() {
  const state = requestContext.getStore();
  return state?.active ? state.context : undefined;
}

function attachRequestContext(record) {
  const context = getRequestContext();
  // Context wins over caller metadata so an unrelated ID cannot mislabel logs.
  if (context) record.correlationId = context.correlationId;
  return record;
}

function captureRequestContext(logger) {
  const write = logger.write;
  // Winston can defer formatters under backpressure. Capture the request at
  // stream admission, before buffering can run formatting in another context.
  logger.write = function (record, ...args) {
    return write.call(this, attachRequestContext(record), ...args);
  };
}

function requestCorrelation(req, res, next) {
  // Generate locally: incoming headers may contain secrets or forged IDs.
  const correlationId = randomUUID();
  req.correlationId = correlationId;
  res.setHeader("X-Request-Id", correlationId);
  const state = { context: Object.freeze({ correlationId }), active: true };
  if (typeof res.once === "function") {
    // Sockets and other async resources can outlive the request that created them.
    const endRequest = () => { state.active = false; };
    res.once("finish", endRequest);
    res.once("close", endRequest);
  }
  requestContext.run(state, next);
}

function runWithRequestCorrelation(correlationId, work) {
  if (!isRequestCorrelationId(correlationId)) return work();
  const state = { context: Object.freeze({ correlationId }), active: true };
  return requestContext.run(state, async () => {
    try {
      return await work();
    } finally {
      state.active = false;
    }
  });
}

function requestCompletionLogger(logger) {
  return (req, res, next) => {
    res.once("finish", () => {
      // Only suppress successful exact probe routes. Never log raw URLs, which
      // can contain credentials; use the path solely for this comparison.
      const path =
        typeof req.originalUrl === "string"
          ? req.originalUrl.split("?", 1)[0]
          : "";
      const route =
        typeof req.route?.path === "string" ? req.route.path : "unmatched";
      const probe =
        (path === "/health" || path === "/metrics") && route === path;
      if (
        probe &&
        (req.method === "GET" || req.method === "HEAD") &&
        res.statusCode >= 200 &&
        res.statusCode < 400
      )
        return;
      logger.info("HTTP request completed", {
        correlationId: req.correlationId,
        method: req.method,
        statusCode: res.statusCode,
        route,
      });
    });
    next();
  };
}

module.exports = {
  getRequestContext,
  isRequestCorrelationId,
  attachRequestContext,
  captureRequestContext,
  requestCorrelation,
  runWithRequestCorrelation,
  requestCompletionLogger,
};
