"use strict";

// Experimental transport only. It is not invoked by agent startup and does
// not establish a durable credential, authorize ACK, or isolate another
// privileged local process. The host must deliver the bootstrap on the
// child's dedicated stdin, and the child must close that stream before it can
// launch descendants.
const crypto = require("node:crypto");
const net = require("node:net");

const PROOF_DOMAIN = Buffer.from("TokenTimer-Credential-Pipe-Server-v1\0", "utf8");
const NAME = /^\\\\\.\\pipe\\TokenTimerCredential-[a-f0-9]{64}$/;
const MAX_FRAME = 1024;
const OPERATION = /^[a-f0-9]{32}$/;
const CREDENTIAL = /^ttagent_[a-f0-9]{16}_[a-f0-9]{64}$/;
const HASH = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/;
const AGENT = /^[A-Za-z0-9_.:-]{1,128}$/;
const sessionKeys = new WeakMap();

function genericError() { return new Error("credential pipe unavailable"); }

async function receiveCredentialPipeBootstrap(input, { timeoutMs = 5000 } = {}) {
  if (!input || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000) throw genericError();
  const chunks = [];
  let length = 0;
  const timer = setTimeout(() => input.destroy(genericError()), timeoutMs);
  try {
    for await (const chunk of input) {
      const part = Buffer.from(chunk);
      length += part.length;
      if (length > 546) throw genericError();
      chunks.push(part);
    }
    const packet = Buffer.concat(chunks, length);
    try {
      if (packet.length < 34) throw genericError();
      const nameLength = packet.readUInt16BE(0);
      if (nameLength < 1 || nameLength > 512 || packet.length !== 2 + nameLength + 32) throw genericError();
      const name = packet.subarray(2, 2 + nameLength).toString("utf8");
      if (!NAME.test(name)) throw genericError();
      const key = Buffer.from(packet.subarray(2 + nameLength));
      const session = { name };
      sessionKeys.set(session, { key, closed: false, sockets: new Set() });
      Object.defineProperty(session, "dispose", { value: () => {
        const state = sessionKeys.get(session);
        if (!state) return;
        state.closed = true;
        state.key.fill(0);
        for (const socket of state.sockets) socket.destroy();
        state.sockets.clear();
        sessionKeys.delete(session);
      }, enumerable: false });
      return session;
    } finally { packet.fill(0); }
  } catch (_error) { throw genericError(); }
  finally { clearTimeout(timer); for (const part of chunks) part.fill(0); input.destroy(); }
}

function readExactly(socket, size) {
  return new Promise((resolve, reject) => {
    const parts = []; let total = 0;
    function cleanup() { socket.off("readable", read); socket.off("error", failed); socket.off("end", failed); socket.off("close", failed); }
    function failed() { cleanup(); reject(genericError()); }
    function read() {
      let part;
      while (total < size && (part = socket.read(size - total)) !== null) { parts.push(part); total += part.length; }
      if (total === size) { cleanup(); resolve(Buffer.concat(parts, size)); }
    }
    socket.on("readable", read); socket.once("error", failed); socket.once("end", failed); socket.once("close", failed);
    read();
  });
}

function validRecord(record) {
  return record && typeof record === "object" && !Array.isArray(record) &&
    Object.keys(record).sort().join(",") === "credential,operation,version" && record.version === 1 &&
    typeof record.operation === "string" && OPERATION.test(record.operation) &&
    typeof record.credential === "string" && CREDENTIAL.test(record.credential);
}

function validBinding(binding) {
  return binding && typeof binding === "object" && !Array.isArray(binding) &&
    Object.keys(binding).sort().join(",") === "agentId,caHash,id,origin,workspaceId" &&
    typeof binding.id === "string" && UUID.test(binding.id) && typeof binding.workspaceId === "string" && UUID.test(binding.workspaceId) &&
    typeof binding.agentId === "string" && AGENT.test(binding.agentId) && typeof binding.caHash === "string" && HASH.test(binding.caHash) &&
    typeof binding.origin === "string" && binding.origin.length > 0 && binding.origin.length <= 512;
}

async function sendCredentialPipeRequest(session, request, { timeoutMs = 5000, expectedOperationId, expectedCandidateHash } = {}) {
  const state = session && sessionKeys.get(session);
  if (!session || !NAME.test(session.name || "") || !state || state.closed || !Buffer.isBuffer(state.key) || state.key.length !== 32 ||
      !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000) throw genericError();
  if (!request || typeof request !== "object" || Array.isArray(request)) throw genericError();
  if (request.command === "prepare") {
    if (Object.keys(request).sort().join(",") !== "command,record" || !validRecord(request.record)) throw genericError();
  } else if (request.command === "read") {
    if (Object.keys(request).join(",") !== "command" || typeof expectedOperationId !== "string" || !OPERATION.test(expectedOperationId) ||
        typeof expectedCandidateHash !== "string" || !HASH.test(expectedCandidateHash)) throw genericError();
  } else if (request.command === "bound-read") {
    if (Object.keys(request).sort().join(",") !== "binding,command" || !validBinding(request.binding)) throw genericError();
  } else throw genericError();
  let payload;
  try { payload = Buffer.from(JSON.stringify(request), "utf8"); } catch (_error) { throw genericError(); }
  if (payload.length === 0 || payload.length > MAX_FRAME) { payload.fill(0); throw genericError(); }
  const key = Buffer.from(state.key);
  let socket;
  try { socket = net.createConnection(session.name); } catch (_error) { key.fill(0); payload.fill(0); throw genericError(); }
  state.sockets.add(socket);
  // An error can arrive between two framed reads, when no phase-specific
  // listener is installed. Always consume it; active waits still reject and
  // the overall timer bounds a connection that fails between phases.
  socket.on("error", () => {});
  const timer = setTimeout(() => socket.destroy(genericError()), timeoutMs);
  try {
    await new Promise((resolve, reject) => {
      socket.once("connect", resolve);
      socket.once("error", () => reject(genericError()));
      socket.once("close", () => reject(genericError()));
    });
    if (state.closed) throw genericError();
    const challenge = crypto.randomBytes(32);
    socket.write(challenge);
    const proof = await readExactly(socket, 32);
    const expected = crypto.createHmac("sha256", key).update(PROOF_DOMAIN).update(challenge).digest();
    const valid = crypto.timingSafeEqual(proof, expected);
    proof.fill(0); expected.fill(0); challenge.fill(0);
    if (!valid || state.closed) throw genericError();
    const frame = Buffer.alloc(4 + payload.length);
    frame.writeUInt32BE(payload.length); payload.copy(frame, 4);
    try { await new Promise((resolve, reject) => socket.write(frame, error => error ? reject(genericError()) : resolve())); }
    finally { frame.fill(0); }
    const responseHeader = await readExactly(socket, 4);
    const responseLength = responseHeader.readUInt32BE(0);
    if (responseLength === 0 || responseLength > MAX_FRAME) throw genericError();
    const response = await readExactly(socket, responseLength);
    try {
      const parsed = JSON.parse(response.toString("utf8"));
      if (request.command === "prepare") {
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || Object.keys(parsed).join(",") !== "state" || parsed.state !== "prepared") throw genericError();
        return { state: "prepared" };
      }
      if (request.command === "bound-read") {
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || Object.keys(parsed).join(",") !== "credential" ||
            typeof parsed.credential !== "string" || !CREDENTIAL.test(parsed.credential)) throw genericError();
        return parsed.credential;
      }
      if (!validRecord(parsed) || parsed.operation !== expectedOperationId) throw genericError();
      const actualHash = crypto.createHash("sha256").update(parsed.credential).digest();
      const expectedHash = Buffer.from(expectedCandidateHash, "hex");
      const hashMatches = crypto.timingSafeEqual(actualHash, expectedHash);
      actualHash.fill(0); expectedHash.fill(0);
      if (!hashMatches) throw genericError();
      return parsed;
    } finally { response.fill(0); }
  } catch (_error) { throw genericError(); }
  finally { clearTimeout(timer); payload.fill(0); key.fill(0); state.sockets.delete(socket); socket.destroy(); }
}

module.exports = { receiveCredentialPipeBootstrap, sendCredentialPipeRequest };
