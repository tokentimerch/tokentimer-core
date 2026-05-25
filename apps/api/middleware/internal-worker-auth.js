const crypto = require("crypto");

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ""));
  const right = Buffer.from(String(b || ""));

  if (left.length !== right.length) return false;

  return crypto.timingSafeEqual(left, right);
}

function getInternalWorkerKey() {
  return process.env.WORKER_API_KEY || process.env.SESSION_SECRET;
}

function isInternalWorkerRequest(req) {
  const authHeader = req.get("Authorization") || "";
  const workerKey = getInternalWorkerKey();

  if (!workerKey || !authHeader.startsWith("Bearer ")) return false;

  return safeEqual(authHeader.slice("Bearer ".length), workerKey);
}

function authenticateInternalWorkerRequest(req) {
  if (!isInternalWorkerRequest(req)) return false;

  req.isWorkerCall = true;
  req.user = req.user || {
    id: null,
    role: "admin",
    email: "worker@internal",
  };

  return true;
}

module.exports = {
  authenticateInternalWorkerRequest,
  isInternalWorkerRequest,
};
