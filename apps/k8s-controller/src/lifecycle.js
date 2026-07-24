"use strict";

function createControllerLifecycle({
  runtime,
  healthServer,
  logger,
  shutdownTimeoutMs,
  exitProcess = (code) => process.exit(code),
} = {}) {
  if (!runtime || !healthServer || !logger) {
    throw new TypeError("runtime, healthServer, and logger are required");
  }

  let phase = "starting";
  let startupPromise = null;
  let shutdownRequested = false;
  let shutdownPromise = null;
  let exitCode = null;
  let removeSignalHandlers = () => {};

  function exitOnce(code) {
    if (exitCode !== null) return;
    exitCode = code;
    exitProcess(code);
  }

  function runtimeState(method) {
    try {
      return runtime[method]() === true;
    } catch (_error) {
      return false;
    }
  }

  function status() {
    const healthy = phase === "running" && runtimeState("isAlive");
    return {
      healthy,
      phase,
      ready: healthy && runtimeState("isReady"),
    };
  }

  function start() {
    if (startupPromise) return startupPromise;

    startupPromise = (async () => {
      try {
        await healthServer.listen();
        if (shutdownRequested) return;

        await runtime.start();
        if (shutdownRequested) return;

        phase = "running";
        logger.info("controller-started");
      } catch (error) {
        if (shutdownRequested) throw error;

        phase = "failed";
        await Promise.allSettled([
          runtime.stopAcceptingWork(),
          healthServer.close(),
          runtime.close(),
        ]);
        logger.error("controller-startup-failed", {
          code: error.code || "CONTROLLER_STARTUP_FAILED",
        });
        exitOnce(1);
        throw error;
      }
    })();
    return startupPromise;
  }

  async function shutdown(signal = "manual") {
    if (shutdownPromise) return shutdownPromise;

    shutdownRequested = true;
    phase = "stopping";
    shutdownPromise = (async () => {
      removeSignalHandlers();
      logger.info("controller-stopping", { signal });
      let failure = null;

      if (startupPromise) {
        try {
          await startupPromise;
        } catch (error) {
          failure = error;
        }
      }

      for (const step of [
        () => runtime.stopAcceptingWork(),
        async () => {
          const idle = await runtime.waitForIdle(shutdownTimeoutMs);
          if (!idle) {
            logger.warn("controller-shutdown-timeout", { shutdownTimeoutMs });
          }
        },
        () => healthServer.close(),
        () => runtime.close(),
      ]) {
        try {
          await step();
        } catch (error) {
          failure ||= error;
        }
      }

      const exitCode = failure ? 1 : 0;
      phase = failure ? "failed" : "stopped";
      if (failure) {
        logger.error("controller-shutdown-failed", {
          code: failure.code || "CONTROLLER_SHUTDOWN_FAILED",
        });
      } else {
        logger.info("controller-stopped", { signal });
      }
      exitOnce(exitCode);
      return exitCode;
    })();
    return shutdownPromise;
  }

  function installSignalHandlers(processRef = process) {
    const sigintHandler = () => void shutdown("SIGINT");
    const sigtermHandler = () => void shutdown("SIGTERM");
    processRef.once("SIGINT", sigintHandler);
    processRef.once("SIGTERM", sigtermHandler);
    removeSignalHandlers = () => {
      const remove = processRef.off || processRef.removeListener;
      if (typeof remove !== "function") return;
      remove.call(processRef, "SIGINT", sigintHandler);
      remove.call(processRef, "SIGTERM", sigtermHandler);
    };
    return removeSignalHandlers;
  }

  return {
    hasExited() {
      return exitCode !== null;
    },
    installSignalHandlers,
    isShutdownRequested() {
      return shutdownRequested;
    },
    shutdown,
    start,
    status,
  };
}

module.exports = {
  createControllerLifecycle,
};
