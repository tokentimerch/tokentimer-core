"use strict";

function createUnavailableKubernetesClientPort() {
  return Object.freeze({
    async close() {},
    isAlive() {
      return true;
    },
    isReady() {
      return false;
    },
    async start() {},
    async stopAcceptingWork() {},
  });
}

function createUnavailableReporterPort() {
  return Object.freeze({
    async close() {},
    isAlive() {
      return true;
    },
    isReady() {
      return false;
    },
    async start() {},
    async stopAcceptingWork() {},
  });
}

module.exports = {
  createUnavailableKubernetesClientPort,
  createUnavailableReporterPort,
};
