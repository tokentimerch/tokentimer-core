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
  let shutdownPromise = null;
  let removeSignalHandlers = () => {};

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

  async function start() {
    await healthServer.listen();
    try {
      await runtime.start();
      phase = "running";
      logger.info("controller-started");
    } catch (error) {
      phase = "failed";
      await Promise.allSettled([healthServer.close(), runtime.close()]);
      throw error;
    }
  }

  async function shutdown(signal = "manual") {
    if (shutdownPromise) return shutdownPromise;

    shutdownPromise = (async () => {
      phase = "stopping";
      removeSignalHandlers();
      logger.info("controller-stopping", { signal });
      let failure = null;

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
      exitProcess(exitCode);
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
    installSignalHandlers,
    shutdown,
    start,
    status,
  };
}

module.exports = {
  createControllerLifecycle,
};
