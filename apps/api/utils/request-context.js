const { AsyncLocalStorage } = require("node:async_hooks");
const { randomUUID } = require("node:crypto");

const requestContext = new AsyncLocalStorage();

function getRequestContext() {
  return requestContext.getStore();
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
  requestContext.run(Object.freeze({ correlationId }), next);
}

module.exports = {
  getRequestContext,
  attachRequestContext,
  captureRequestContext,
  requestCorrelation,
};
