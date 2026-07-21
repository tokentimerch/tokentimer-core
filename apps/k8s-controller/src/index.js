"use strict";

const { loadControllerConfig } = require("./config");
const { createInClusterCertManagerClient } = require("./cert-manager-client");
const { createCertManagerObserver } = require("./cert-manager-observer");
const { createTlsCertificateFallback } = require("./tls-certificate-fallback");
const { createHealthServer } = require("./health-server");
const { createControllerLifecycle } = require("./lifecycle");
const { createControllerLogger } = require("./logger");
const { createControllerRuntime } = require("./runtime");
const { createControllerObservationReporter } = require("./observation-reporter");

function createControllerApplication({
  createKubernetesClient = createInClusterCertManagerClient,
  createObserver = createCertManagerObserver,
  createTlsFallback = createTlsCertificateFallback,
  env = process.env,
  fsOptions,
  createLogger = createControllerLogger,
  createRuntime = createControllerRuntime,
  createReporter = createControllerObservationReporter,
  createHealth = createHealthServer,
  createLifecycle = createControllerLifecycle,
  exitProcess,
  observationHandler,
} = {}) {
  const config = loadControllerConfig(env, fsOptions);
  const logger = createLogger();
  const reporter = createReporter({
    apiTokenFile: config.apiTokenFile,
    apiUrl: config.apiUrl,
    fsOptions,
  });
  const kubernetesClient = createKubernetesClient({
    secretFallbackEnabled: config.secretFallbackEnabled,
  });
  const tlsFallback = createTlsFallback({
    enabled: config.secretFallbackEnabled,
    kubernetesClient,
  });
  const observer = createObserver({
    client: kubernetesClient,
    clusterId: config.clusterId,
    enrichObservation: tlsFallback.enrichObservation,
    logger,
    observationHandler:
      observationHandler ||
      ((observation) => reporter.report(observation)),
    watchNamespaces: config.watchNamespaces,
    workspaceId: config.workspaceId,
  });
  const runtime = createRuntime({ kubernetesClient: observer, reporter });
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
    reporter,
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
