"use strict";
// Local API surface used by the existing customer(action, name) journey calls.
// The caller supplies a separately reviewed, authenticated role transport.
const http = require("node:http"), crypto = require("node:crypto"), { dispatch } = require("./role-dispatch.cjs");
function createBridge({ send, token }) {
  if (typeof send !== "function") throw new Error("authenticated role transport required");
  if (typeof token !== "string" || !/^[a-f0-9]{64}$/.test(token)) throw new Error("private control token required");
  return http.createServer((req,res) => {
    if (!["POST","GET"].includes(req.method) || req.url !== "/") { res.writeHead(404).end(); return; }
    const authorization=req.headers.authorization || "";
    const expected=Buffer.from(`Bearer ${token}`), supplied=Buffer.from(authorization);
    if (supplied.length!==expected.length || !crypto.timingSafeEqual(supplied,expected)) { res.writeHead(403).end(); return; }
    if (req.method === "GET") { res.writeHead(200,{"Content-Type":"application/json"}).end('{"lab":"wildcard-ux","databaseAccess":false}'); return; }
    let raw="", oversized=false;
    req.setEncoding("utf8");
    req.on("data", chunk => { raw += chunk; if (Buffer.byteLength(raw) > 65536) { oversized=true; req.destroy(); } });
    req.on("end", async () => {
      if (oversized) return;
      try {
        const result=await dispatch(JSON.parse(raw),send);
        res.writeHead(200,{"Content-Type":"application/json"}).end(JSON.stringify(result));
      } catch { res.writeHead(400,{"Content-Type":"application/json"}).end('{"error":"role control refused"}'); }
    });
  });
}
module.exports = { createBridge };
