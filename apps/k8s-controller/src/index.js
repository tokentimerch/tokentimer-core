"use strict";

const { loadControllerConfig } = require("./config");
const { createHealthServer } = require("./health-server");
const { createControllerLifecycle } = require("./lifecycle");
const { createControllerLogger } = require("./logger");
const { createControllerRuntime } = require("./runtime");

function createControllerApplication({
  env = process.env,
  fsOptions,
  createLogger = createControllerLogger,
  createRuntime = createControllerRuntime,
  createHealth = createHealthServer,
  createLifecycle = createControllerLifecycle,
  exitProcess,
} = {}) {
  const config = loadControllerConfig(env, fsOptions);
  const logger = createLogger();
  const runtime = createRuntime();
  const lifecycleRef = { current: null };
  const healthServer = createHealth({
    getStatus: () =>
      lifecycleRef.current
        ? lifecycleRef.current.status()
        : { healthy: false, phase: "starting", ready: false },
    port: config.healthPort,
  });
  const lifecycle = createLifecycle({
    exitProcess,
    healthServer,
    logger,
    runtime,
    shutdownTimeoutMs: config.shutdownTimeoutMs,
  });
  lifecycleRef.current = lifecycle;

  return {
    config,
    healthServer,
    lifecycle,
    logger,
    runtime,
  };
}

async function runController({
  exitProcess = (code) => process.exit(code),
  processRef = process,
  ...options
} = {}) {
  const logger = options.logger || createControllerLogger();
  let application;
  try {
    application = createControllerApplication({
      ...options,
      createLogger: () => logger,
      exitProcess,
    });
    application.lifecycle.installSignalHandlers(processRef);
    await application.lifecycle.start();
    return application;
  } catch (error) {
    if (
      !application ||
      (!application.lifecycle.isShutdownRequested() &&
        !application.lifecycle.hasExited())
    ) {
      logger.error("controller-startup-failed", {
        code: error.code || "CONTROLLER_STARTUP_FAILED",
      });
      exitProcess(1);
    }
    return null;
  }
}

if (require.main === module) {
  void runController();
}

module.exports = {
  createControllerApplication,
  runController,
};
