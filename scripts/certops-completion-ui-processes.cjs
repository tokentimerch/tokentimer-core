"use strict";

function stopOwnedChildren(children) {
  for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill();
}

async function waitForStartup(children, ready, { timeoutMs = 60000, pollMs = 500 } = {}) {
  try {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      try { if (await ready()) return; } catch { /* startup */ }
      if (children.some(child => child.exitCode !== null || child.signalCode !== null))
        throw new Error("Fixture application exited; inspect protected local startup logs");
      await new Promise(resolve => setTimeout(resolve, pollMs));
    }
    throw new Error("Fixture UI startup timed out; inspect protected local startup logs");
  } catch (error) {
    stopOwnedChildren(children);
    throw error;
  }
}

module.exports = { stopOwnedChildren, waitForStartup };
