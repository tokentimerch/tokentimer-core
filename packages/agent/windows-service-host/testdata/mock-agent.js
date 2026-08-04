console.log("mock-agent: started, pid=" + process.pid);
let stopping = false;
process.on("SIGBREAK", () => {
  console.log("mock-agent: received SIGBREAK, shutting down gracefully");
  stopping = true;
  setTimeout(() => {
    console.log("mock-agent: graceful shutdown complete");
    process.exit(0);
  }, 500);
});
setInterval(() => {
  if (!stopping) console.log("mock-agent: heartbeat " + Date.now());
}, 1000);
