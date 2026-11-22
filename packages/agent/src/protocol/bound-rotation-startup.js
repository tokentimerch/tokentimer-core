"use strict";

// Experimental and not connected to the runtime. The caller must obtain both
// state and enrolled identity from independently protected storage. A response
// can become stale immediately after it is sent; it does not authorize ACK.
const crypto = require("node:crypto");
const { createCaAwareFetch } = require("./index");
const { sendCredentialPipeRequest } = require("./credential-pipe");
const UUID = /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/;
const AGENT = /^[A-Za-z0-9_.:-]{1,128}$/;
const TOKEN = /^ttagent_[a-f0-9]{16}_[a-f0-9]{64}$/;

function unavailable() { return new Error("bound rotation identity unavailable"); }
function validIdentity(i) {
  return i && typeof i === "object" && !Array.isArray(i) && Object.keys(i).sort().join(",") === "agentId,id,workspaceId" &&
    UUID.test(i.id || "") && AGENT.test(i.agentId || "") && UUID.test(i.workspaceId || "");
}

async function recoverBoundRotationCredential({ session, enrolledIdentity, origin, caBundlePem, signal } = {}) {
  if (signal?.aborted || !validIdentity(enrolledIdentity) || typeof origin !== "string" || typeof caBundlePem !== "string" || caBundlePem.length === 0 || caBundlePem.length > 1048576) throw unavailable();
  let parsed;
  try { parsed = new URL(origin); } catch (_error) { throw unavailable(); }
  if (parsed.protocol !== "https:" || parsed.origin !== origin || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash ||
      parsed.hostname.startsWith("[") || parsed.hostname.split(".").some(label => label.startsWith("xn--"))) throw unavailable();
  const binding = { ...enrolledIdentity, origin, caHash: crypto.createHash("sha256").update(caBundlePem,"utf8").digest("hex") };
  let response, identity, credential;
  try {
    credential = await sendCredentialPipeRequest(session, {command:"bound-read",binding});
    if (signal?.aborted || typeof credential !== "string" || !TOKEN.test(credential)) throw unavailable();
    const fetch = createCaAwareFetch({caBundlePem});
    response = await fetch(`${origin}/api/v1/certops/agent/credential-rotation/identity`, {
      method:"POST", headers:{"content-type":"application/json",authorization:`Bearer ${credential}`},
      body:"{}", signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(5000)]) : AbortSignal.timeout(5000), redirect:"error",
    });
    if (!response.ok || response.status !== 200 || typeof response.__readBoundedJson !== "function") throw unavailable();
    identity = response.__readBoundedJson();
  } catch (_error) { throw unavailable(); }
  if (!validIdentity(identity) || identity.id !== enrolledIdentity.id || identity.agentId !== enrolledIdentity.agentId || identity.workspaceId !== enrolledIdentity.workspaceId) throw unavailable();
  return credential;
}

module.exports = { recoverBoundRotationCredential };
