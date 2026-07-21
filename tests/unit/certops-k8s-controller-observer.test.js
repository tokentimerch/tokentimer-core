"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  createInClusterCertManagerClient,
} = require(
  path.resolve(__dirname, "../../apps/k8s-controller/src/cert-manager-client.js"),
);
const {
  certificateRequestMatches,
  createCertManagerObserver,
  mapCertificateObservation,
  selectCertificateRequest,
} = require(
  path.resolve(__dirname, "../../apps/k8s-controller/src/cert-manager-observer.js"),
);
const {
  createControllerRuntime,
} = require(
  path.resolve(__dirname, "../../apps/k8s-controller/src/runtime.js"),
);

function certificate({
  namespace = "team-a",
  name = "web",
  uid = "certificate-uid",
  resourceVersion = "10",
  revision = 7,
  ready = "True",
} = {}) {
  return {
    apiVersion: "cert-manager.io/v1",
    kind: "Certificate",
    metadata: {
      generation: 3,
      name,
      namespace,
      resourceVersion,
      uid,
    },
    spec: {
      dnsNames: ["z.example.test", "a.example.test", "a.example.test"],
      issuerRef: {
        group: "cert-manager.io",
        kind: "ClusterIssuer",
        name: "issuer-a",
      },
      secretName: "web-tls",
    },
    status: {
      conditions: [
        {
          lastTransitionTime: "2026-07-21T10:00:00Z",
          message: "certificate ready",
          reason: "Issued",
          status: ready,
          type: "Ready",
        },
      ],
      notAfter: "2026-10-21T10:00:00Z",
      notBefore: "2026-07-21T10:00:00Z",
      renewalTime: "2026-09-21T10:00:00Z",
      revision,
    },
  };
}

function certificateRequest({
  namespace = "team-a",
  name = "web-7",
  uid = "request-uid",
  certificateName = "web",
  revision = "7",
  certificateUid = "certificate-uid",
  creationTimestamp = "2026-07-21T09:00:00Z",
  resourceVersion = "20",
} = {}) {
  return {
    apiVersion: "cert-manager.io/v1",
    kind: "CertificateRequest",
    metadata: {
      annotations: {
        "cert-manager.io/certificate-name": certificateName,
        "cert-manager.io/certificate-revision": revision,
      },
      creationTimestamp,
      name,
      namespace,
      ownerReferences: [{ kind: "Certificate", name: certificateName, uid: certificateUid }],
      resourceVersion,
      uid,
    },
    spec: {
      request: "-----BEGIN PRIVATE KEY-----\nnever-read\n-----END PRIVATE KEY-----",
    },
    status: {
      conditions: [
        {
          message: "token=must-be-redacted",
          reason: "Denied",
          status: "False",
          type: "Ready",
        },
      ],
    },
  };
}

function createFakeClient({ lists = {} } = {}) {
  const listCalls = [];
  const listResponseIndexes = new Map();
  const watchCalls = [];
  let closeCalls = 0;
  let startCalls = 0;

  return {
    async close() {
      closeCalls += 1;
    },
    get closeCalls() {
      return closeCalls;
    },
    listCalls,
    async list(options) {
      listCalls.push(options);
      const key = `${options.resource}:${options.namespace || "all"}`;
      const configured = lists[key];
      const responseIndex = listResponseIndexes.get(key) || 0;
      listResponseIndexes.set(key, responseIndex + 1);
      const result = Array.isArray(configured)
        ? configured[Math.min(responseIndex, configured.length - 1)]
        : configured || { items: [], resourceVersion: `${key}-rv` };
      return {
        items: result.items || [],
        resourceVersion: result.resourceVersion || `${key}-rv`,
      };
    },
    get startCalls() {
      return startCalls;
    },
    async start() {
      startCalls += 1;
    },
    watchCalls,
    async watch(options) {
      const call = { ...options, closeCalls: 0 };
      watchCalls.push(call);
      return {
        close() {
          call.closeCalls += 1;
        },
      };
    },
  };
}

function tick() {
  return new Promise((resolve) => setImmediate(resolve));
}

describe("CertOps cert-manager status observer", () => {
  it("maps only deterministic, bounded status-safe Certificate fields", () => {
    const sourceCertificate = certificate({ ready: "False" });
    sourceCertificate.status.conditions.push({
      message: "Authorization: Bearer raw-value",
      reason: "token=raw-value",
      status: "True",
      type: "Issuing",
    });
    sourceCertificate.status.failureTime = "ignored";
    sourceCertificate.spec.privateKey = { rotationPolicy: "Never" };
    const request = certificateRequest();

    const observation = mapCertificateObservation({
      certificate: sourceCertificate,
      certificateRequest: request,
      clusterId: "cluster-a",
      now: () => "2026-07-21T12:00:00Z",
      workspaceId: "workspace-a",
    });

    assert.deepEqual(observation, {
      certificateGeneration: 3,
      certificateName: "web",
      certificateRequestRef: { name: "web-7", uid: "request-uid" },
      certificateUid: "certificate-uid",
      clusterId: "cluster-a",
      conditions: [
        {
          message: "Authorization: [REDACTED]",
          reason: "token=[REDACTED]",
          status: "True",
          type: "Issuing",
        },
        {
          lastTransitionTime: "2026-07-21T10:00:00.000Z",
          message: "certificate ready",
          reason: "Issued",
          status: "False",
          type: "Ready",
        },
      ],
      dnsNames: ["a.example.test", "z.example.test"],
      failureMessage: "certificate ready",
      failureReason: "Issued",
      issuerRef: {
        group: "cert-manager.io",
        kind: "ClusterIssuer",
        name: "issuer-a",
      },
      namespace: "team-a",
      notAfter: "2026-10-21T10:00:00.000Z",
      notBefore: "2026-07-21T10:00:00.000Z",
      observationSource: "cert_manager",
      observedAt: "2026-07-21T12:00:00.000Z",
      ready: false,
      renewalTime: "2026-09-21T10:00:00.000Z",
      resourceVersion: "10",
      revision: 7,
      schemaVersion: 1,
      secretName: "web-tls",
      workspaceId: "workspace-a",
    });

    const serialized = JSON.stringify(observation);
    assert.doesNotMatch(serialized, /never-read|BEGIN PRIVATE KEY|must-be-redacted|raw-value/);
    assert.equal(Object.hasOwn(observation, "raw"), false);
    assert.equal(Object.hasOwn(observation, "certificateRequest"), false);
  });

  it("associates CertificateRequests through an exact owner UID or safe name and revision annotations", () => {
    const observedCertificate = certificate();
    assert.equal(certificateRequestMatches(certificateRequest(), observedCertificate), true);
    assert.equal(
      certificateRequestMatches(
        certificateRequest({ certificateUid: "another-certificate" }),
        observedCertificate,
      ),
      false,
    );
    const annotationOnly = certificateRequest();
    annotationOnly.metadata.ownerReferences = [];
    assert.equal(certificateRequestMatches(annotationOnly, observedCertificate), true);
    annotationOnly.metadata.annotations["cert-manager.io/certificate-revision"] = "8";
    assert.equal(certificateRequestMatches(annotationOnly, observedCertificate), false);
  });

  it("loads the official client from in-cluster credentials and exposes only cert-manager custom object list/watch operations", async () => {
    const calls = [];
    const abortController = { abort: () => calls.push("abort") };
    const apiClient = {
      async listClusterCustomObject(options) {
        calls.push(["list-cluster", options]);
        return { items: [], metadata: { resourceVersion: "rv-cluster" } };
      },
      async listNamespacedCustomObject(options) {
        calls.push(["list-namespace", options]);
        return { items: [], metadata: { resourceVersion: "rv-namespace" } };
      },
    };
    class KubeConfig {
      loadFromCluster() {
        calls.push("load-from-cluster");
      }

      makeApiClient(apiType) {
        calls.push(["make-api-client", apiType]);
        return apiClient;
      }
    }
    class CustomObjectsApi {}
    class Watch {
      constructor(config) {
        calls.push(["watch-constructor", config.constructor.name]);
      }

      async watch(pathname, parameters, onEvent, onError) {
        calls.push(["watch", pathname, parameters]);
        this.onEvent = onEvent;
        this.onError = onError;
        return abortController;
      }
    }
    const client = createInClusterCertManagerClient({
      loadClient: async () => ({ CustomObjectsApi, KubeConfig, Watch }),
    });

    await client.start();
    const clusterList = await client.list({ resource: "Certificate" });
    const namespaceList = await client.list({
      namespace: "team-a",
      resource: "CertificateRequest",
    });
    const watch = await client.watch({
      namespace: "team-a",
      onError() {},
      onEvent() {},
      resource: "Certificate",
      resourceVersion: "rv-namespace",
    });
    watch.close();
    await client.close();

    assert.deepEqual(clusterList, { items: [], resourceVersion: "rv-cluster" });
    assert.deepEqual(namespaceList, { items: [], resourceVersion: "rv-namespace" });
    assert.equal(calls.includes("load-from-cluster"), true);
    assert.equal(calls.some((call) => call === "load-from-default"), false);
    assert.deepEqual(calls.find((call) => call[0] === "list-cluster")[1], {
      group: "cert-manager.io",
      plural: "certificates",
      version: "v1",
    });
    assert.deepEqual(calls.find((call) => call[0] === "list-namespace")[1], {
      group: "cert-manager.io",
      namespace: "team-a",
      plural: "certificaterequests",
      version: "v1",
    });
    assert.deepEqual(calls.find((call) => call[0] === "watch").slice(1), [
      "/apis/cert-manager.io/v1/namespaces/team-a/certificates",
      { allowWatchBookmarks: true, resourceVersion: "rv-namespace" },
    ]);
    assert.deepEqual(calls.filter((call) => call === "abort"), ["abort"]);
  });

  it("lists then watches both resources cluster-wide, and becomes ready only after each watch starts", async () => {
    const client = createFakeClient({
      lists: {
        "Certificate:all": {
          items: [certificate()],
          resourceVersion: "certificate-list-rv",
        },
        "CertificateRequest:all": {
          items: [certificateRequest()],
          resourceVersion: "request-list-rv",
        },
      },
    });
    const observations = [];
    const observer = createCertManagerObserver({
      client,
      clusterId: "cluster-a",
      observationHandler: async (observation) => observations.push(observation),
      now: () => "2026-07-21T12:00:00Z",
      workspaceId: "workspace-a",
    });

    assert.equal(observer.isReady(), false);
    await observer.start({ trackWork: (work) => work });
    await tick();

    assert.equal(client.startCalls, 1);
    assert.deepEqual(
      client.listCalls.map((call) => [call.resource, call.namespace]),
      [["Certificate", undefined], ["CertificateRequest", undefined]],
    );
    assert.deepEqual(
      client.watchCalls.map((call) => [call.resource, call.namespace, call.resourceVersion]),
      [
        ["Certificate", undefined, "certificate-list-rv"],
        ["CertificateRequest", undefined, "request-list-rv"],
      ],
    );
    assert.equal(observer.isReady(), true);
    assert.equal(observations.length, 1);
    assert.equal(observations[0].certificateRequestRef.name, "web-7");
  });

  it("uses only explicit namespaces when configured", async () => {
    const client = createFakeClient();
    const observer = createCertManagerObserver({
      client,
      clusterId: "cluster-a",
      watchNamespaces: ["team-a", "team-b"],
      workspaceId: "workspace-a",
    });

    await observer.start({ trackWork: (work) => work });

    assert.deepEqual(
      client.listCalls.map((call) => `${call.namespace}:${call.resource}`).sort(),
      [
        "team-a:Certificate",
        "team-a:CertificateRequest",
        "team-b:Certificate",
        "team-b:CertificateRequest",
      ],
    );
    assert.equal(client.listCalls.some((call) => call.namespace === undefined), false);
  });

  it("skips duplicate resource versions and coalesces newer pending Certificate observations", async () => {
    const client = createFakeClient();
    const observations = [];
    let releaseFirst;
    let firstEntered;
    const firstStarted = new Promise((resolve) => {
      firstEntered = resolve;
    });
    const firstRelease = new Promise((resolve) => {
      releaseFirst = resolve;
    });
    const observer = createCertManagerObserver({
      client,
      clusterId: "cluster-a",
      observationHandler: async (observation) => {
        observations.push(observation);
        if (observations.length === 1) {
          firstEntered();
          await firstRelease;
        }
      },
      workspaceId: "workspace-a",
    });
    await observer.start({ trackWork: (work) => work });
    const certificateWatch = client.watchCalls.find(
      (call) => call.resource === "Certificate",
    );

    certificateWatch.onEvent("ADDED", certificate({ resourceVersion: "1" }));
    await firstStarted;
    certificateWatch.onEvent("MODIFIED", certificate({ resourceVersion: "1" }));
    certificateWatch.onEvent("MODIFIED", certificate({ resourceVersion: "2" }));
    certificateWatch.onEvent("MODIFIED", certificate({ resourceVersion: "3" }));
    releaseFirst();
    await tick();
    await tick();

    assert.deepEqual(observations.map((observation) => observation.resourceVersion), ["1", "3"]);
  });

  it("re-lists after a 410 ERROR watch event using base-delay restart scheduling", async () => {
    const client = createFakeClient();
    const timers = [];
    const scheduler = {
      clearTimeout(timer) {
        timer.cleared = true;
      },
      setTimeout(callback, delay) {
        const timer = { callback, cleared: false, delay };
        timers.push(timer);
        return timer;
      },
    };
    const observer = createCertManagerObserver({
      client,
      clusterId: "cluster-a",
      random: () => 0,
      restartBaseDelayMs: 250,
      scheduler,
      workspaceId: "workspace-a",
    });
    await observer.start({ trackWork: (work) => work });
    const certificateWatch = client.watchCalls.find(
      (call) => call.resource === "Certificate",
    );

    certificateWatch.onEvent("ERROR", { code: 410 });
    assert.equal(observer.isReady(), false);
    assert.equal(timers.length, 1);
    assert.equal(timers[0].delay, 250);
    timers[0].callback();
    await tick();
    await tick();

    assert.equal(
      client.listCalls.filter((call) => call.resource === "Certificate").length,
      2,
    );
    assert.equal(
      client.watchCalls.filter((call) => call.resource === "Certificate").length,
      2,
    );
    assert.equal(observer.isReady(), true);
  });

  it("exponentially backs off 500 ERROR watch events and resets after a live watch event", async () => {
    const client = createFakeClient();
    const timers = [];
    const scheduler = {
      clearTimeout(timer) {
        timer.cleared = true;
      },
      setTimeout(callback, delay) {
        const timer = { callback, cleared: false, delay };
        timers.push(timer);
        return timer;
      },
    };
    const observer = createCertManagerObserver({
      client,
      clusterId: "cluster-a",
      random: () => 0,
      restartBaseDelayMs: 250,
      scheduler,
      workspaceId: "workspace-a",
    });
    await observer.start({ trackWork: (work) => work });
    const certificateWatch = () =>
      client.watchCalls.filter((call) => call.resource === "Certificate").at(-1);

    certificateWatch().onEvent("ERROR", { code: 500 });
    assert.equal(timers[0].delay, 250);
    timers[0].callback();
    await tick();
    await tick();
    certificateWatch().onEvent("ERROR", { code: 500 });
    assert.equal(timers[1].delay, 500);
    timers[1].callback();
    await tick();
    await tick();
    certificateWatch().onEvent("BOOKMARK", {
      metadata: { resourceVersion: "live-rv" },
    });
    certificateWatch().onEvent("ERROR", { code: 500 });
    assert.equal(timers[2].delay, 250);
  });

  it("prunes a Certificate missing from a relist and permits a later same-version add", async () => {
    const observedCertificate = certificate({ resourceVersion: "10" });
    const client = createFakeClient({
      lists: {
        "Certificate:all": [
          { items: [observedCertificate], resourceVersion: "certificate-rv-1" },
          { items: [], resourceVersion: "certificate-rv-2" },
        ],
      },
    });
    const timers = [];
    const scheduler = {
      clearTimeout() {},
      setTimeout(callback, delay) {
        const timer = { callback, delay };
        timers.push(timer);
        return timer;
      },
    };
    const observations = [];
    const observer = createCertManagerObserver({
      client,
      clusterId: "cluster-a",
      observationHandler: async (observation) => observations.push(observation),
      random: () => 0,
      scheduler,
      workspaceId: "workspace-a",
    });
    await observer.start({ trackWork: (work) => work });
    await tick();
    const certificateWatch = () =>
      client.watchCalls.filter((call) => call.resource === "Certificate").at(-1);

    certificateWatch().onError({ code: "DISCONNECTED" });
    timers[0].callback();
    await tick();
    await tick();
    certificateWatch().onEvent("ADDED", observedCertificate);
    await tick();

    assert.deepEqual(
      observations.map((observation) => observation.resourceVersion),
      ["10", "10"],
    );
  });

  it("removes stale CertificateRequest enrichment after a relist and accepts it again", async () => {
    const observedCertificate = certificate();
    const currentRequest = certificateRequest();
    const client = createFakeClient({
      lists: {
        "Certificate:all": [
          { items: [observedCertificate], resourceVersion: "certificate-rv-1" },
          { items: [observedCertificate], resourceVersion: "certificate-rv-2" },
        ],
        "CertificateRequest:all": [
          { items: [currentRequest], resourceVersion: "request-rv-1" },
          { items: [], resourceVersion: "request-rv-2" },
        ],
      },
    });
    const timers = [];
    const scheduler = {
      clearTimeout() {},
      setTimeout(callback, delay) {
        const timer = { callback, delay };
        timers.push(timer);
        return timer;
      },
    };
    const observations = [];
    const observer = createCertManagerObserver({
      client,
      clusterId: "cluster-a",
      observationHandler: async (observation) => observations.push(observation),
      random: () => 0,
      scheduler,
      workspaceId: "workspace-a",
    });
    await observer.start({ trackWork: (work) => work });
    await tick();
    await tick();
    const requestWatch = () =>
      client.watchCalls.filter((call) => call.resource === "CertificateRequest").at(-1);
    assert.equal(observations.at(-1).certificateRequestRef.name, "web-7");

    requestWatch().onError({ code: "DISCONNECTED" });
    timers[0].callback();
    await tick();
    await tick();
    assert.equal(observations.at(-1).certificateRequestRef, null);

    requestWatch().onEvent("ADDED", currentRequest);
    await tick();
    await tick();
    assert.equal(observations.at(-1).certificateRequestRef.name, "web-7");
  });

  it("selects the current CertificateRequest deterministically when old requests arrive last", async () => {
    const observedCertificate = certificate({ revision: 7 });
    const currentRequest = certificateRequest({
      creationTimestamp: "2026-07-21T10:00:00Z",
      name: "web-current",
      resourceVersion: "10",
      revision: "7",
      uid: "request-current",
    });
    const oldRequest = certificateRequest({
      creationTimestamp: "2026-07-21T11:00:00Z",
      name: "web-old",
      resourceVersion: "999",
      revision: "6",
      uid: "request-old",
    });
    assert.equal(
      selectCertificateRequest(observedCertificate, [oldRequest, currentRequest]).metadata.name,
      "web-current",
    );
    assert.equal(
      selectCertificateRequest(observedCertificate, [currentRequest, oldRequest]).metadata.name,
      "web-current",
    );
    const newerRequest = certificateRequest({
      creationTimestamp: "2026-07-21T12:00:00Z",
      name: "web-newer",
      resourceVersion: "1",
      uid: "request-newer",
    });
    assert.equal(
      selectCertificateRequest(observedCertificate, [currentRequest, newerRequest]).metadata.name,
      "web-newer",
    );
    const higherVersionRequest = certificateRequest({
      creationTimestamp: "2026-07-21T12:00:00Z",
      name: "web-higher-version",
      resourceVersion: "11",
      uid: "request-higher-version",
    });
    assert.equal(
      selectCertificateRequest(observedCertificate, [newerRequest, higherVersionRequest]).metadata.name,
      "web-higher-version",
    );
    const alphabeticallyEarlierRequest = certificateRequest({
      creationTimestamp: "2026-07-21T12:00:00Z",
      name: "web-a",
      resourceVersion: "11",
      uid: "request-a",
    });
    assert.equal(
      selectCertificateRequest(
        observedCertificate,
        [higherVersionRequest, alphabeticallyEarlierRequest],
      ).metadata.name,
      "web-a",
    );

    const client = createFakeClient();
    const observations = [];
    const observer = createCertManagerObserver({
      client,
      clusterId: "cluster-a",
      observationHandler: async (observation) => observations.push(observation),
      workspaceId: "workspace-a",
    });
    await observer.start({ trackWork: (work) => work });
    const certificateWatch = client.watchCalls.find((call) => call.resource === "Certificate");
    const requestWatch = client.watchCalls.find((call) => call.resource === "CertificateRequest");

    certificateWatch.onEvent("ADDED", observedCertificate);
    requestWatch.onEvent("ADDED", currentRequest);
    requestWatch.onEvent("ADDED", oldRequest);
    await tick();
    await tick();

    assert.equal(observations.at(-1).certificateRequestRef.name, "web-current");
  });

  it("cleans deleted Certificate cache entries before later CertificateRequest events", async () => {
    const client = createFakeClient();
    const observations = [];
    const observer = createCertManagerObserver({
      client,
      clusterId: "cluster-a",
      observationHandler: async (observation) => observations.push(observation),
      workspaceId: "workspace-a",
    });
    await observer.start({ trackWork: (work) => work });
    const certificateWatch = client.watchCalls.find(
      (call) => call.resource === "Certificate",
    );
    const requestWatch = client.watchCalls.find(
      (call) => call.resource === "CertificateRequest",
    );

    certificateWatch.onEvent("ADDED", certificate({ resourceVersion: "1" }));
    await tick();
    certificateWatch.onEvent("DELETED", certificate({ resourceVersion: "2" }));
    requestWatch.onEvent("MODIFIED", certificateRequest());
    await tick();

    assert.equal(observations.length, 1);
  });

  it("tracks observation delivery as runtime work and logs only safe error codes", async () => {
    const client = createFakeClient({
      lists: {
        "Certificate:all": {
          items: [certificate({ resourceVersion: "1" })],
          resourceVersion: "list-rv",
        },
      },
    });
    const logs = [];
    let releaseWork;
    let workStarted;
    const workStartedPromise = new Promise((resolve) => {
      workStarted = resolve;
    });
    const workReleasePromise = new Promise((resolve) => {
      releaseWork = resolve;
    });
    const observer = createCertManagerObserver({
      client,
      clusterId: "cluster-a",
      logger: {
        debug() {},
        error() {},
        info() {},
        warn(message, metadata) {
          logs.push({ message, metadata });
        },
      },
      observationHandler: async () => {
        workStarted();
        await workReleasePromise;
        const error = new Error("Authorization: Bearer raw-value");
        error.code = "DELIVERY_ERROR";
        throw error;
      },
      workspaceId: "workspace-a",
    });
    const runtime = createControllerRuntime({
      kubernetesClient: observer,
      reporter: {
        async close() {},
        isAlive: () => true,
        isReady: () => false,
        async start() {},
        async stopAcceptingWork() {},
      },
    });
    await runtime.start();
    await workStartedPromise;
    assert.equal(runtime.activeWork.size, 1);
    releaseWork();
    await tick();
    await tick();

    assert.equal(runtime.activeWork.size, 0);
    const output = JSON.stringify(logs);
    assert.match(output, /DELIVERY_ERROR/);
    assert.doesNotMatch(output, /raw-value|Authorization/);
  });

  it("cancels every watch and prevents watch-error restarts during shutdown", async () => {
    const client = createFakeClient();
    const timers = [];
    const scheduler = {
      clearTimeout(timer) {
        timer.cleared = true;
      },
      setTimeout(callback, delay) {
        const timer = { callback, cleared: false, delay };
        timers.push(timer);
        return timer;
      },
    };
    const observer = createCertManagerObserver({
      client,
      clusterId: "cluster-a",
      scheduler,
      workspaceId: "workspace-a",
    });
    await observer.start({ trackWork: (work) => work });
    const calls = [...client.watchCalls];

    await observer.stopAcceptingWork();
    for (const call of calls) call.onError({ code: "ECONNRESET" });
    await observer.close();

    assert.equal(observer.isReady(), false);
    assert.deepEqual(calls.map((call) => call.closeCalls), [1, 1]);
    assert.deepEqual(timers, []);
    assert.equal(client.closeCalls, 1);
  });
});
