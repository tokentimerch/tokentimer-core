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
const { createCertificateProvisioner } = require("./certificate-provisioner");
const { createControllerProvisioningCommandClient } = require("./provisioning-command-client");
const { createProvisioningRunner } = require("./provisioning-runner");

function createControllerWorkPort(observer, provisioningRunner = null) {
  return Object.freeze({
    async close() {
      const results = await Promise.allSettled([
        observer.close(),
        provisioningRunner?.close(),
      ]);
      const failure = results.find((result) => result.status === "rejected");
      if (failure) throw failure.reason;
    },
    isAlive() {
      return observer.isAlive() && (!provisioningRunner || provisioningRunner.isAlive());
    },
    isReady() {
      return observer.isReady() && (!provisioningRunner || provisioningRunner.isReady());
    },
    async start(options) {
      await observer.start(options);
      if (provisioningRunner) await provisioningRunner.start(options);
    },
    async stopAcceptingWork() {
      const results = await Promise.allSettled([
        observer.stopAcceptingWork(),
        provisioningRunner?.stopAcceptingWork(),
      ]);
      const failure = results.find((result) => result.status === "rejected");
      if (failure) throw failure.reason;
    },
  });
}

function createControllerApplication({
  createKubernetesClient = createInClusterCertManagerClient,
  createObserver = createCertManagerObserver,
  createTlsFallback = createTlsCertificateFallback,
  env = process.env,
  fsOptions,
  createLogger = createControllerLogger,
  createRuntime = createControllerRuntime,
  createReporter = createControllerObservationReporter,
  createProvisioner = createCertificateProvisioner,
  createProvisioningClient = createControllerProvisioningCommandClient,
  createProvisioningRunnerPort = createProvisioningRunner,
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
    provisionEnabled: config.mode === "provision",
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
  const provisioningRunner = config.mode === "provision"
    ? createProvisioningRunnerPort({
      commandClient: createProvisioningClient({
        apiTokenFile: config.apiTokenFile,
        apiUrl: config.apiUrl,
        fsOptions,
      }),
      intervalMs: config.reconcileIntervalMs,
      logger,
      provisioner: createProvisioner({
        client: kubernetesClient,
        clusterId: config.clusterId,
        clusterWide: config.clusterWide,
        watchNamespaces: config.watchNamespaces,
      }),
    })
    : null;
  const runtime = createRuntime({
    kubernetesClient: createControllerWorkPort(observer, provisioningRunner),
    reporter,
  });
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
  createControllerWorkPort,
  runController,
};
