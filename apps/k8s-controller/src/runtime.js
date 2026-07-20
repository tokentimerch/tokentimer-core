"use strict";

const {
  createUnavailableKubernetesClientPort,
  createUnavailableReporterPort,
} = require("./ports");

function invokePort(port, method) {
  return typeof port[method] === "function" ? port[method]() : undefined;
}

function settlePortInvocation(port, method) {
  return Promise.resolve().then(() => invokePort(port, method));
}

function portState(port, method, fallback) {
  try {
    return typeof port[method] === "function" ? port[method]() === true : fallback;
  } catch (_error) {
    return false;
  }
}

function waitForTrackedWork(activeWork, timeoutMs, setTimeoutFn, clearTimeoutFn) {
  if (activeWork.size === 0) return Promise.resolve(true);

  return new Promise((resolve) => {
    const timeout = setTimeoutFn(() => resolve(false), timeoutMs);
    Promise.allSettled([...activeWork]).then(() => {
      clearTimeoutFn(timeout);
      resolve(true);
    });
  });
}

function createControllerRuntime({
  kubernetesClient = createUnavailableKubernetesClientPort(),
  reporter = createUnavailableReporterPort(),
  setTimeoutFn = setTimeout,
  clearTimeoutFn = clearTimeout,
} = {}) {
  const activeWork = new Set();
  let acceptingWork = false;
  let started = false;

  async function start() {
    await invokePort(kubernetesClient, "start");
    await invokePort(reporter, "start");
    started = true;
    acceptingWork = true;
  }

  async function stopAcceptingWork() {
    acceptingWork = false;
    const results = await Promise.allSettled([
      settlePortInvocation(kubernetesClient, "stopAcceptingWork"),
      settlePortInvocation(reporter, "stopAcceptingWork"),
    ]);
    const failure = results.find((result) => result.status === "rejected");
    if (failure) throw failure.reason;
  }

  function trackWork(work) {
    if (!acceptingWork) {
      const error = new Error("Controller is stopping");
      error.code = "CONTROLLER_STOPPING";
      throw error;
    }
    const promise = Promise.resolve().then(() => work);
    activeWork.add(promise);
    promise.then(
      () => activeWork.delete(promise),
      () => activeWork.delete(promise),
    );
    return promise;
  }

  async function waitForIdle(timeoutMs) {
    return waitForTrackedWork(
      activeWork,
      timeoutMs,
      setTimeoutFn,
      clearTimeoutFn,
    );
  }

  async function close() {
    acceptingWork = false;
    const results = await Promise.allSettled([
      invokePort(reporter, "close"),
      invokePort(kubernetesClient, "close"),
    ]);
    const failure = results.find((result) => result.status === "rejected");
    if (failure) throw failure.reason;
  }

  return {
    activeWork,
    close,
    isAlive() {
      return (
        started &&
        portState(kubernetesClient, "isAlive", true) &&
        portState(reporter, "isAlive", true)
      );
    },
    isReady() {
      return (
        started &&
        acceptingWork &&
        portState(kubernetesClient, "isReady", false) &&
        portState(reporter, "isReady", false)
      );
    },
    start,
    stopAcceptingWork,
    trackWork,
    waitForIdle,
  };
}

module.exports = {
  createControllerRuntime,
  waitForTrackedWork,
};
