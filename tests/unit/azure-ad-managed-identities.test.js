"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const Module = require("module");
const path = require("path");

const TENANT_ID = "11111111-1111-1111-1111-111111111111";
const SP_ONLY = { applications: false, servicePrincipals: true };

function credential(keyId) {
  return {
    keyId,
    endDateTime: "2027-01-02T00:00:00Z",
    startDateTime: "2026-01-02T00:00:00Z",
  };
}

function principal(appId, servicePrincipalType = "Application") {
  return {
    appId,
    displayName: appId,
    servicePrincipalType,
    passwordCredentials: [credential(`${appId}-secret`)],
    keyCredentials: [credential(`${appId}-cert`)],
  };
}

function loadService(handler) {
  const modulePath = path.resolve(
    __dirname,
    "../../apps/api/services/azureADIntegration.js",
  );
  delete require.cache[require.resolve(modulePath)];
  const originalLoad = Module._load;
  const originalEnv = process.env.NODE_ENV;
  const calls = [];
  process.env.NODE_ENV = "test";
  Module._load = function (request, parent, isMain) {
    if (request === "axios") {
      return async (config) => {
        calls.push(config);
        return { data: await handler(new URL(config.url), calls.length) };
      };
    }
    if (request === "../utils/logger") {
      return { logger: { info() {}, warn() {}, error() {} } };
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  try {
    return { service: require(modulePath), calls };
  } finally {
    Module._load = originalLoad;
    if (originalEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = originalEnv;
  }
}

function scan(service, options = {}) {
  return service.scanAzureAD({
    token: "opaque-graph-token",
    tenantId: TENANT_ID,
    ...options,
  });
}

function assertCompleteness(summary, complete) {
  assert.ok(summary.length > 0);
  for (const row of summary) {
    assert.equal(row.complete, complete);
    assert.equal(row.truncated, !complete);
  }
}

describe("Entra managed identity scan modes", () => {
  for (const mode of [undefined, "all", "exclude", "only"]) {
    it(`scans a mixed tenant with mode ${mode ?? "default"}`, async () => {
      const ordinary = principal("ordinary");
      const managed = principal("managed", "ManagedIdentity");
      const unknown = principal("unknown");
      delete unknown.servicePrincipalType;
      const { service, calls } = loadService((url) => ({
        value: url.pathname.endsWith("/applications")
          ? [principal("app")]
          : [ordinary, managed, unknown],
      }));
      const result = await scan(service, { managedIdentityMode: mode });
      const expectedIds =
        mode === "only"
          ? ["managed", "managed"]
          : mode === "exclude"
            ? ["app", "app", "ordinary", "ordinary", "unknown", "unknown"]
            : [
                "app", "app", "ordinary", "ordinary",
                "managed", "managed", "unknown", "unknown",
              ];
      assert.deepEqual(result.items.map((item) => item.app_id), expectedIds);
      assert.equal(calls.length, mode === "only" ? 1 : 2);
      assert.equal(result.tenantId, TENANT_ID);
      assertCompleteness(result.summary, true);
    });
  }

  it("only overrides stale include flags and never requests applications", async () => {
    const { service, calls } = loadService(() => ({
      value: [principal("managed", "ManagedIdentity")],
    }));
    const result = await scan(service, {
      managedIdentityMode: "only",
      include: { applications: true, servicePrincipals: false },
    });
    assert.equal(result.items.length, 2);
    assert.equal(calls.length, 1);
    assert.equal(new URL(calls[0].url).pathname, "/v1.0/servicePrincipals");
    assert.ok(result.summary.every((row) => row.type === "service_principals"));
  });

  for (const mode of ["all", "exclude"]) {
    it(`${mode} honors disabled service principals`, async () => {
      const { service, calls } = loadService(() => ({ value: [principal("app")] }));
      const result = await scan(service, {
        managedIdentityMode: mode,
        include: { applications: true, servicePrincipals: false },
      });
      assert.equal(calls.length, 1);
      assert.ok(result.items.every((item) => item.app_id === "app"));
      assert.ok(calls[0].url.includes("/applications"));
    });
  }

  it("rejects invalid mode values before any Graph request", async () => {
    const { service, calls } = loadService(() => ({ value: [] }));
    assert.equal(service.validateManagedIdentityMode(), "all");
    for (const mode of ["all", "exclude", "only"]) {
      assert.equal(service.validateManagedIdentityMode(mode), mode);
    }
    for (const mode of [null, "", "ALL", "managed", false, 1, {}, ["only"]]) {
      assert.throws(
        () => service.validateManagedIdentityMode(mode),
        (error) => error.status === 400 && /managedIdentityMode/.test(error.message),
      );
      await assert.rejects(
        () => scan(service, { managedIdentityMode: mode }),
        (error) => error.status === 400,
      );
    }
    assert.equal(calls.length, 0);
  });

  it("uses only exact Graph type classification, never names or alternative hints", async () => {
    const objects = [
      principal("managed", "ManagedIdentity"),
      principal("lowercase", "managedidentity"),
      principal("unknown", "FutureType"),
      principal("missing"),
    ];
    delete objects[3].servicePrincipalType;
    objects[3].displayName = "ManagedIdentity";
    objects[3].alternativeNames = ["/subscriptions/example/managedIdentities/foo"];
    const { service } = loadService(() => ({ value: objects }));
    const result = await scan(service, { include: SP_ONLY });
    for (const item of result.items) {
      const managed = item.app_id === "managed";
      const kind = item.type === "ssl_cert" ? "certificates" : "secrets";
      const sourceKind = item.type === "ssl_cert"
        ? "azure-ad-sp-certificate"
        : "azure-ad-sp-secret";
      assert.equal(item.source, sourceKind);
      assert.equal(item.sourceKind, sourceKind);
      assert.equal(item.sourceObjectId, `${item.app_id}:${item.key_id}`);
      assert.equal(item.identityType, managed ? "managedIdentity" : "servicePrincipal");
      assert.equal(item.isManagedIdentity, managed);
      assert.equal(
        item.servicePrincipalType,
        objects.find((object) => object.appId === item.app_id).servicePrincipalType ?? null,
      );
      assert.equal(
        item.location,
        `azure-ad:${managed ? "managedIdentities" : "servicePrincipals"}/${item.app_id}/${kind}/${item.key_id}`,
      );
      if (managed) {
        assert.equal(
          item.legacyLocation,
          `azure-ad:servicePrincipals/${item.app_id}/${kind}/${item.key_id}`,
        );
      } else {
        assert.equal(Object.hasOwn(item, "legacyLocation"), false);
      }
      assert.equal(item.expiration, "2027-01-02");
    }
  });

  it("retains the default 500-item budget", async () => {
    const object = principal("managed", "ManagedIdentity");
    object.passwordCredentials = Array.from({ length: 501 }, (_, i) => credential(`s${i}`));
    object.keyCredentials = [];
    const { service } = loadService(() => ({ value: [object] }));
    const result = await scan(service, { managedIdentityMode: "only" });
    assert.equal(result.items.length, 500);
    assertCompleteness(result.summary, false);
  });
});

describe("Entra filtered pagination and completeness", () => {
  for (const mode of ["only", "exclude"]) {
    it(`${mode} counts eligible objects rather than skipped pages`, async () => {
      const wantedType = mode === "only" ? "ManagedIdentity" : "Application";
      const skippedType = mode === "only" ? "Application" : "ManagedIdentity";
      const { service, calls } = loadService((_url, page) => ({
        value: page === 1
          ? [principal("skip1", skippedType), principal("skip2", skippedType)]
          : [{ ...principal("wanted", wantedType), keyCredentials: [] }],
        ...(page === 1 ? {
          "@odata.nextLink": "https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=next",
        } : {}),
      }));
      const result = await scan(service, {
        include: SP_ONLY, managedIdentityMode: mode, maxItems: 1,
      });
      assert.equal(calls.length, 2);
      assert.equal(result.items[0].app_id, "wanted");
      assert.equal(calls[1].url, "https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=next");
      assertCompleteness(result.summary, true);
    });
  }

  it("caps filtered enumeration at 50 pages and marks the scope incomplete", async () => {
    const { service, calls } = loadService((_url, page) => ({
      value: [principal(`skip${page}`)],
      "@odata.nextLink": `https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=${page}`,
    }));
    const result = await scan(service, { managedIdentityMode: "only", maxItems: 1 });
    assert.equal(calls.length, 50);
    assert.deepEqual(result.items, []);
    assertCompleteness(result.summary, false);
  });

  it("does not mark the final allowed page incomplete without a nextLink", async () => {
    const { service, calls } = loadService((_url, page) => ({
      value: [],
      ...(page < 50 ? {
        "@odata.nextLink": `https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=${page}`,
      } : {}),
    }));
    const result = await scan(service, { managedIdentityMode: "only" });
    assert.equal(calls.length, 50);
    assertCompleteness(result.summary, true);
  });

  for (const nextPage of [false, true]) {
    it(`marks eligible object overflow incomplete (nextLink ${nextPage})`, async () => {
      const { service, calls } = loadService(() => ({
        value: [
          { ...principal("m1", "ManagedIdentity"), keyCredentials: [] },
          ...(nextPage ? [] : [principal("m2", "ManagedIdentity")]),
        ],
        ...(nextPage ? {
          "@odata.nextLink": "https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=next",
        } : {}),
      }));
      const result = await scan(service, { managedIdentityMode: "only", maxItems: 1 });
      assert.equal(calls.length, 1);
      assert.equal(result.items.length, 1);
      assertCompleteness(result.summary, false);
    });
  }

  for (const collection of ["applications", "servicePrincipals"]) {
    for (const credentials of ["passwordCredentials", "keyCredentials", "both"]) {
      it(`reports mid-object truncation in ${collection} ${credentials}`, async () => {
        const object = principal("object", "ManagedIdentity");
        object.passwordCredentials = credentials === "keyCredentials"
          ? [] : [credential("s1"), ...(credentials === "passwordCredentials" ? [credential("s2")] : [])];
        object.keyCredentials = credentials === "passwordCredentials"
          ? [] : [credential("c1"), ...(credentials === "keyCredentials" ? [credential("c2")] : [])];
        const { service } = loadService(() => ({ value: [object] }));
        const result = await scan(service, {
          include: {
            applications: collection === "applications",
            servicePrincipals: collection === "servicePrincipals",
          },
          maxItems: 1,
        });
        assert.equal(result.items.length, 1);
        assertCompleteness(result.summary, false);
      });
    }
  }

  it("marks SP credentials incomplete when applications consume the shared budget", async () => {
    const { service } = loadService(() => ({
      value: [{ ...principal("object"), keyCredentials: [] }],
    }));
    const result = await scan(service, { maxItems: 1 });
    assert.equal(result.items.length, 1);
    assertCompleteness(result.summary.filter((row) => row.type === "applications"), true);
    assertCompleteness(result.summary.filter((row) => row.type === "service_principals"), false);
  });

  it("keeps an empty SP scope complete after applications consume the budget", async () => {
    const { service } = loadService((url) => ({
      value: url.pathname.endsWith("/applications")
        ? [{ ...principal("app"), keyCredentials: [] }]
        : [],
    }));
    const result = await scan(service, { maxItems: 1 });
    assertCompleteness(result.summary, true);
  });

  for (const failure of ["http", "off-origin"]) {
    it(`does not report failed ${failure} pagination as complete`, async () => {
      const { service, calls } = loadService((url) => {
        if (url.pathname.endsWith("/applications")) return { value: [] };
        if (url.searchParams.has("$skiptoken")) {
          const error = new Error("Graph unavailable");
          error.response = { status: 503, data: { error: { message: "Unavailable" } } };
          throw error;
        }
        return {
          value: [principal("managed", "ManagedIdentity")],
          "@odata.nextLink": failure === "http"
            ? "https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=next"
            : "https://attacker.example/servicePrincipals",
        };
      });
      const result = await scan(service);
      const spSummary = result.summary.filter((row) => row.type === "service_principals");
      assert.equal(spSummary.length, 2);
      assert.ok(spSummary.every((row) => row.complete === false && row.error));
      assert.deepEqual(result.items, []);
      assert.equal(calls.length, failure === "http" ? 3 : 2);
    });
  }

  it("throws the upstream failure when filtered pagination is the only selected scope", async () => {
    const { service } = loadService((_url, page) => {
      if (page === 2) {
        const error = new Error("Graph unavailable");
        error.response = { status: 503, data: {} };
        throw error;
      }
      return {
        value: [principal("excluded")],
        "@odata.nextLink": "https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=next",
      };
    });
    await assert.rejects(
      () => scan(service, { managedIdentityMode: "only", maxItems: 1 }),
      (error) => error.status === 503,
    );
  });
});
