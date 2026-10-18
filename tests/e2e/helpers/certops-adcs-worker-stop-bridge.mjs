/** Test-only IPC bridge for the unmodified worker CLI. It forwards one exact
 * owned stop message to the production SIGTERM event handler. It does not
 * replace worker definitions, timers, clocks, services or the runner entrypoint.
 * This qualifies graceful IPC-requested shutdown, not native OS signal delivery. */
const nonce = process.env.CERTOPS_WORKER_OWNERSHIP_NONCE;
if (!/^[a-f0-9]{32}$/.test(nonce || "") || !process.send)
  throw Error("Owned worker IPC prerequisite missing");
process.send({
  type: "certops-worker-bridge-ready",
  nonce,
  pid: process.pid,
  argv: process.argv,
  execArgv: process.execArgv,
});
let forwarded = false;
process.on("message", (message) => {
  if (
    !message ||
    typeof message !== "object" ||
    Array.isArray(message) ||
    Object.keys(message).sort().join(",") !== "nonce,type" ||
    message.type !== "certops-worker-stop" ||
    message.nonce !== nonce ||
    forwarded
  )
    return;
  const count = process.listenerCount("SIGTERM");
  if (count !== 1) {
    process.send?.({
      type: "certops-worker-stop-refused",
      nonce,
      pid: process.pid,
    });
    return;
  }
  forwarded = true;
  // Flush the bounded acknowledgement before the real handler can exit. Failed
  // IPC never triggers an unacknowledged graceful stop; the retained owner drains.
  process.send?.({
    type: "certops-worker-stop-forwarded",
    nonce,
    pid: process.pid,
  }, (error) => {
    if (error) return;
    process.emit("SIGTERM");
  });
});
