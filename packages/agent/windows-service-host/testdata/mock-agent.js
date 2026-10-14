console.log("mock-agent: started, pid=" + process.pid);
const fs = require("node:fs");
const path = require("node:path");
const stateDir = process.env.TOKENTIMER_AGENT_CONFIG_DIR;
if (stateDir) fs.appendFileSync(path.join(stateDir, "fixture-starts.log"), `${process.pid}\n`);
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
  if (stateDir) {
    const trigger = path.join(stateDir, "fixture-exit-code.txt");
    if (fs.existsSync(trigger)) {
      const code = Number(fs.readFileSync(trigger, "utf8"));
      fs.unlinkSync(trigger);
      if ([17, 86].includes(code)) process.exit(code);
    }
  }
  if (!stopping) console.log("mock-agent: heartbeat " + Date.now());
}, 1000);
