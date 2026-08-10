"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  CERTOPS_AGENT_OBSERVATION_INVALID,
  LOCATION_KINDS,
  normalizeAgentFilesystemObservation,
  persistAgentDiscoveryEvidenceBatch,
  _test,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/agentObservations.js",
  ),
);

const AGENT = {
  id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  agentId: "agent-host-1",
  workspaceId: "11111111-1111-4111-8111-111111111111",
  hostname: "edge-01.example",
};
const WINDOWS_THUMBPRINT = "A1".repeat(20);

describe("normalizeAgentFilesystemObservation", () => {
  it("builds a structured observation and overlays server-owned agentId", () => {
    const observation = normalizeAgentFilesystemObservation({
      agent: AGENT,
      evidenceItem: {
        evidenceId: "ev_discovery_1",
        eventType: "certificate.observed",
        observedAt: "2026-07-24T08:00:00.000Z",
        fingerprintSha256: "a".repeat(64),
        summary: "found cert",
        metadata: [
          { name: "filePath", value: "/etc/ssl/certs/app.pem" },
          { name: "agentId", value: "spoofed-agent" },
          { name: "subject", value: "CN=app.example" },
          { name: "issuer", value: "CN=Test CA" },
          { name: "targetHost", value: "edge-01.example" },
        ],
      },
      serverObservedAt: "2026-07-24T08:00:01.000Z",
    });

    assert.equal(observation.agentId, AGENT.agentId);
    assert.equal(observation.agentRowId, AGENT.id);
    assert.equal(observation.filePath, "/etc/ssl/certs/app.pem");
    assert.equal(observation.fingerprintSha256, "a".repeat(64));
    assert.equal(observation.source, "agent_filesystem");
    assert.equal(observation.observedAtServer, "2026-07-24T08:00:01.000Z");
  });

  it("rejects discovery evidence without fingerprint or filePath", () => {
    assert.throws(
      () =>
        normalizeAgentFilesystemObservation({
          agent: AGENT,
          evidenceItem: {
            evidenceId: "ev_1",
            eventType: "certificate.observed",
            observedAt: "2026-07-24T08:00:00.000Z",
            metadata: [{ name: "filePath", value: "/tmp/a.pem" }],
          },
        }),
      (error) => error.code === CERTOPS_AGENT_OBSERVATION_INVALID,
    );
  });
});

describe("certificateFor", () => {
  it("derives commonName from the certificate's own subject CN, not the discovering host", () => {
    const observation = normalizeAgentFilesystemObservation({
      agent: AGENT,
      evidenceItem: {
        evidenceId: "ev_cn_1",
        eventType: "certificate.observed",
        observedAt: "2026-07-24T08:00:00.000Z",
        fingerprintSha256: "c".repeat(64),
        metadata: [
          { name: "filePath", value: "/etc/ssl/certs/app.pem" },
          { name: "targetHost", value: "edge-01.example" },
          { name: "subject", value: "CN=app.example.com, O=Example Inc" },
        ],
      },
    });

    const certificate = _test.certificateFor(observation);
    assert.equal(certificate.commonName, "app.example.com");
  });

  it("falls back to the discovery host only when the certificate has no SAN or subject CN", () => {
    const observation = normalizeAgentFilesystemObservation({
      agent: AGENT,
      evidenceItem: {
        evidenceId: "ev_cn_2",
        eventType: "certificate.observed",
        observedAt: "2026-07-24T08:00:00.000Z",
        fingerprintSha256: "d".repeat(64),
        metadata: [
          { name: "filePath", value: "/etc/ssl/certs/app.pem" },
          { name: "targetHost", value: "edge-01.example" },
        ],
      },
    });

    const certificate = _test.certificateFor(observation);
    assert.equal(certificate.commonName, "edge-01.example");
  });
});

describe("persistAgentDiscoveryEvidenceBatch", () => {
  it("rolls back sequence when inventory upsert fails mid-batch", async () => {
    const queries = [];
    let begun = false;
    let rolledBack = false;
    const client = {
      async query(sql, params) {
        queries.push({ sql, params });
        if (sql === "BEGIN") {
          begun = true;
          return { rows: [] };
        }
        if (sql === "ROLLBACK") {
          rolledBack = true;
          return { rows: [] };
        }
        if (sql.includes("SET last_sequence")) {
          return { rows: [{ id: AGENT.id }] };
        }
        if (sql.includes("FROM certificate_evidence")) {
          return { rows: [] };
        }
        if (sql.includes("INSERT INTO tokens")) {
          return { rows: [{ id: 999 }] };
        }
        if (sql.includes("INSERT INTO managed_certificates")) {
          throw new Error("inventory boom");
        }
        return { rows: [] };
      },
      release() {},
    };
    const dbPool = {
      async connect() {
        return client;
      },
    };

    await assert.rejects(
      () =>
        persistAgentDiscoveryEvidenceBatch({
          dbPool,
          agent: AGENT,
          envelope: { sequence: 3 },
          evidenceItems: [
            {
              evidenceId: "ev_1",
              eventType: "certificate.observed",
              observedAt: "2026-07-24T08:00:00.000Z",
              fingerprintSha256: "b".repeat(64),
              metadata: [
                { name: "filePath", value: "/etc/ssl/certs/app.pem" },
                { name: "targetHost", value: "edge-01.example" },
                { name: "validFrom", value: "2026-01-01T00:00:00.000Z" },
                { name: "validTo", value: "2027-01-01T00:00:00.000Z" },
              ],
            },
          ],
          deps: {
            enforceAgentSequence: async ({ client: c, envelope }) => {
              await c.query("SET last_sequence = $1", [envelope.sequence]);
            },
          },
        }),
      /inventory boom/,
    );

    assert.equal(begun, true);
    assert.equal(rolledBack, true);
    assert.ok(queries.some((entry) => entry.sql.includes("SET last_sequence")));
  });

  it("mints and links an ssl_cert token for a filesystem discovery with no existing token", async () => {
    const queries = [];
    const client = {
      async query(sql, params) {
        queries.push({ sql, params });
        if (sql === "BEGIN" || sql === "COMMIT") return { rows: [] };
        if (sql.includes("SET last_sequence")) {
          return { rows: [{ id: AGENT.id }] };
        }
        if (sql.includes("FROM certificate_evidence")) {
          return { rows: [] };
        }
        // No pre-existing managed_certificate or token: both lookups miss.
        if (sql.includes("FROM managed_certificates") && sql.includes("SELECT")) {
          return { rows: [] };
        }
        if (sql.includes("FROM tokens") && sql.includes("SELECT")) {
          return { rows: [] };
        }
        if (sql.includes("INSERT INTO tokens")) {
          return { rows: [{ id: 4242 }] };
        }
        if (sql.includes("INSERT INTO managed_certificates")) {
          return {
            rows: [
              {
                id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                token_id: 4242,
                workspace_id: AGENT.workspaceId,
                status: "discovered",
              },
            ],
          };
        }
        if (sql.includes("INSERT INTO certificate_targets")) {
          return { rows: [{ id: "target-1" }] };
        }
        if (sql.includes("INSERT INTO certificate_instances")) {
          return { rows: [{ id: "instance-1" }] };
        }
        if (sql.includes("INSERT INTO certificate_evidence")) {
          return { rows: [{ id: "evidence-1" }] };
        }
        return { rows: [] };
      },
      release() {},
    };
    const dbPool = {
      async connect() {
        return client;
      },
    };

    const result = await persistAgentDiscoveryEvidenceBatch({
      dbPool,
      agent: AGENT,
      envelope: { sequence: 4 },
      evidenceItems: [
        {
          evidenceId: "ev_token_1",
          eventType: "certificate.observed",
          observedAt: "2026-07-24T08:00:00.000Z",
          fingerprintSha256: "e".repeat(64),
          metadata: [
            { name: "filePath", value: "/etc/ssl/certs/app.pem" },
            { name: "targetHost", value: "edge-01.example" },
            { name: "subject", value: "CN=app.example.com" },
            { name: "validFrom", value: "2026-01-01T00:00:00.000Z" },
            { name: "validTo", value: "2027-01-01T00:00:00.000Z" },
          ],
        },
      ],
      deps: {
        enforceAgentSequence: async ({ client: c, envelope }) => {
          await c.query("SET last_sequence = $1", [envelope.sequence]);
        },
      },
    });

    assert.equal(result.ok, true);
    const tokenInsert = queries.find((entry) =>
      entry.sql.includes("INSERT INTO tokens"),
    );
    assert.ok(tokenInsert, "expected a token to be minted for the discovery");
    assert.ok(
      String(tokenInsert.params.at(-1)).includes("agent filesystem discovery"),
      "token notes should attribute the agent filesystem source, not the generic PEM-import copy",
    );

    const certInsert = queries.find((entry) =>
      entry.sql.includes("INSERT INTO managed_certificates"),
    );
    assert.ok(certInsert, "expected a managed_certificate insert");
    assert.equal(
      certInsert.params[1],
      4242,
      "the minted token id should be passed as the managed_certificate's token_id",
    );
    // Renewal adoption (renewalAdoption.js) refuses a certificate with no
    // deployed_cert_path. Filesystem discovery is the one source that
    // observes this path directly, so it must populate both columns.
    assert.equal(
      certInsert.params[23],
      "/etc/ssl/certs/app.pem",
      "deployed_cert_path must be populated from the discovered file path",
    );
    assert.equal(
      certInsert.params[24],
      AGENT.id,
      "deployed_agent_id must be populated from the discovering agent",
    );
  });
});

// Windows / OS-store discovery generalizes the observation contract beyond
// filesystem paths.
// windows_store/iis_binding/http_sys observations have no filePath; their
// identity is locationSlot, a stable per-binding string the agent computes
// so a certificate rotation at the same binding refreshes the existing
// logical location instead of creating a misleading duplicate.
describe("normalizeAgentFilesystemObservation - Windows locations", () => {
  function windowsEvidenceItem(overrides = {}) {
    return {
      evidenceId: "ev_win_1",
      eventType: "certificate.observed",
      observedAt: "2026-07-24T08:00:00.000Z",
      fingerprintSha256: "1".repeat(64),
      metadata: [
        { name: "locationKind", value: "windows_store" },
        { name: "locationSlot", value: "LocalMachine/My/deadbeef" },
        { name: "targetHost", value: "iis-01.example" },
        { name: "storeLocation", value: "LocalMachine" },
        { name: "storeName", value: "My" },
        { name: "thumbprint", value: WINDOWS_THUMBPRINT },
        { name: "subject", value: "CN=app.example.com" },
        { name: "validFrom", value: "2026-01-01T00:00:00.000Z" },
        { name: "validTo", value: "2027-01-01T00:00:00.000Z" },
      ],
      ...overrides,
    };
  }

  it("builds a windows_store observation keyed by locationSlot, not filePath", () => {
    const observation = normalizeAgentFilesystemObservation({
      agent: AGENT,
      evidenceItem: windowsEvidenceItem(),
    });

    assert.equal(observation.locationKind, "windows_store");
    assert.equal(observation.locationSlot, "LocalMachine/My/deadbeef");
    assert.equal(observation.filePath, null);
    assert.equal(observation.source, "agent_windows");
    assert.equal(observation.windowsFields.storeLocation, "LocalMachine");
    assert.equal(observation.windowsFields.storeName, "My");
    assert.equal(observation.windowsFields.thumbprint, WINDOWS_THUMBPRINT);
    assert.equal(
      observation.locationRef,
      `winstore://LocalMachine/My/${WINDOWS_THUMBPRINT}`,
    );
    assert.equal(
      _test.defaultKeyReference(observation.locationKind, {
        windowsFields: observation.windowsFields,
        thumbprint: observation.windowsFields.thumbprint,
      }),
      `winstore://LocalMachine/My/${WINDOWS_THUMBPRINT}`,
    );
  });

  it("preserves JSON-encoded SAN arrays without splitting commas inside values", () => {
    const item = windowsEvidenceItem();
    item.metadata.push({
      name: "subjectAltNames",
      value: JSON.stringify([
        "app.example.com",
        "10.0.0.5",
        "https://example.com/a,b",
        "ops@example.com",
      ]),
    });
    const observation = normalizeAgentFilesystemObservation({
      agent: AGENT,
      evidenceItem: item,
    });

    assert.deepEqual(observation.publicCertificate.subjectAltNames, [
      "app.example.com",
      "10.0.0.5",
      "https://example.com/a,b",
      "ops@example.com",
    ]);
  });

  it("rejects unsafe Windows store names at the observation boundary", () => {
    const item = windowsEvidenceItem();
    item.metadata.push({
      name: "storeName",
      value: "WebHosting; Remove-Item C:\\",
    });
    assert.throws(
      () =>
        normalizeAgentFilesystemObservation({
          agent: AGENT,
          evidenceItem: item,
        }),
      /storeName is invalid/,
    );
  });

  it("builds an iis_binding observation carrying site/port/SNI fields", () => {
    const observation = normalizeAgentFilesystemObservation({
      agent: AGENT,
      evidenceItem: windowsEvidenceItem({
        metadata: [
          { name: "locationKind", value: "iis_binding" },
          { name: "locationSlot", value: "Default Web Site:443#app.example.com" },
          { name: "targetHost", value: "iis-01.example" },
          { name: "siteName", value: "Default Web Site" },
          { name: "port", value: "443" },
          { name: "sniHost", value: "app.example.com" },
          { name: "storeLocation", value: "LocalMachine" },
          { name: "storeName", value: "My" },
          { name: "thumbprint", value: WINDOWS_THUMBPRINT },
        ],
      }),
    });

    assert.equal(observation.locationKind, "iis_binding");
    assert.equal(observation.source, "agent_windows");
    assert.equal(observation.windowsFields.siteName, "Default Web Site");
    assert.equal(observation.windowsFields.port, 443);
    assert.equal(observation.windowsFields.sniHost, "app.example.com");
    assert.equal(observation.windowsFields.thumbprint, WINDOWS_THUMBPRINT);
    assert.equal(
      observation.locationRef,
      "iis://Default Web Site:443#app.example.com",
    );
    assert.equal(
      _test.defaultKeyReference(observation.locationKind, {
        windowsFields: observation.windowsFields,
        thumbprint: observation.windowsFields.thumbprint,
      }),
      `winstore://LocalMachine/My/${WINDOWS_THUMBPRINT}`,
    );
  });

  it("builds an http_sys observation with only a port, no site identity", () => {
    const observation = normalizeAgentFilesystemObservation({
      agent: AGENT,
      evidenceItem: windowsEvidenceItem({
        metadata: [
          { name: "locationKind", value: "http_sys" },
          { name: "locationSlot", value: "0.0.0.0:8443" },
          { name: "targetHost", value: "iis-01.example" },
          { name: "boundAddress", value: "0.0.0.0" },
          { name: "port", value: "8443" },
          { name: "storeLocation", value: "LocalMachine" },
          { name: "storeName", value: "My" },
          { name: "thumbprint", value: WINDOWS_THUMBPRINT },
        ],
      }),
    });

    assert.equal(observation.locationKind, "http_sys");
    assert.equal(observation.windowsFields.siteName, undefined);
    assert.equal(observation.windowsFields.port, 8443);
    assert.equal(observation.windowsFields.boundAddress, "0.0.0.0");
    assert.equal(observation.windowsFields.thumbprint, WINDOWS_THUMBPRINT);
    assert.equal(observation.locationRef, "http-sys://0.0.0.0:8443");
    assert.equal(
      _test.defaultKeyReference(observation.locationKind, {
        windowsFields: observation.windowsFields,
        thumbprint: observation.windowsFields.thumbprint,
      }),
      `winstore://LocalMachine/My/${WINDOWS_THUMBPRINT}`,
    );
  });

  it("reports a confirmed private key as a boolean fact, not a path or export", () => {
    const observation = normalizeAgentFilesystemObservation({
      agent: AGENT,
      evidenceItem: windowsEvidenceItem({
        metadata: [
          ...windowsEvidenceItem().metadata,
          { name: "keyPresent", value: true },
        ],
      }),
    });
    assert.equal(observation.keyPresent, true);
  });

  it("reports a confirmed absent private key distinctly from unknown", () => {
    const observation = normalizeAgentFilesystemObservation({
      agent: AGENT,
      evidenceItem: windowsEvidenceItem({
        metadata: [
          ...windowsEvidenceItem().metadata,
          { name: "keyPresent", value: false },
        ],
      }),
    });
    assert.equal(observation.keyPresent, false);
  });

  it("treats an omitted keyPresent as unknown (null), not false", () => {
    const observation = normalizeAgentFilesystemObservation({
      agent: AGENT,
      evidenceItem: windowsEvidenceItem(),
    });
    assert.equal(observation.keyPresent, null);
  });

  it("rejects a malformed keyPresent rather than coercing it", () => {
    assert.throws(
      () =>
        normalizeAgentFilesystemObservation({
          agent: AGENT,
          evidenceItem: windowsEvidenceItem({
            metadata: [
              ...windowsEvidenceItem().metadata,
              { name: "keyPresent", value: "yes" },
            ],
          }),
        }),
      /keyPresent must be a boolean/,
    );
  });

  it("rejects a non-filesystem observation missing locationSlot", () => {
    assert.throws(
      () =>
        normalizeAgentFilesystemObservation({
          agent: AGENT,
          evidenceItem: windowsEvidenceItem({
            metadata: [
              { name: "locationKind", value: "windows_store" },
              { name: "targetHost", value: "iis-01.example" },
            ],
          }),
        }),
      (error) => error.code === CERTOPS_AGENT_OBSERVATION_INVALID,
    );
  });

  it("rejects an unrecognized locationKind rather than silently defaulting", () => {
    assert.throws(
      () =>
        normalizeAgentFilesystemObservation({
          agent: AGENT,
          evidenceItem: windowsEvidenceItem({
            metadata: [
              { name: "locationKind", value: "kubernetes_secret" },
              { name: "locationSlot", value: "ns/default/secret/tls" },
              { name: "targetHost", value: "iis-01.example" },
            ],
          }),
        }),
      (error) => error.code === CERTOPS_AGENT_OBSERVATION_INVALID,
    );
  });

  it("defaults locationKind to filesystem when omitted, preserving old-agent compatibility", () => {
    const observation = normalizeAgentFilesystemObservation({
      agent: AGENT,
      evidenceItem: {
        evidenceId: "ev_legacy_1",
        eventType: "certificate.observed",
        observedAt: "2026-07-24T08:00:00.000Z",
        fingerprintSha256: "2".repeat(64),
        metadata: [
          { name: "filePath", value: "/etc/ssl/certs/app.pem" },
          { name: "targetHost", value: "edge-01.example" },
        ],
      },
    });

    assert.equal(observation.locationKind, "filesystem");
    assert.equal(observation.source, "agent_filesystem");
  });

  it("never carries key material fields on a Windows observation (zero-custody)", () => {
    const observation = normalizeAgentFilesystemObservation({
      agent: AGENT,
      evidenceItem: windowsEvidenceItem(),
    });

    const serialized = JSON.stringify(observation).toLowerCase();
    assert.equal(serialized.includes("privatekey"), false);
    assert.equal(serialized.includes("begin private key"), false);
    assert.equal(observation.windowsFields.privateKey, undefined);
  });

  it("rejects a Windows observation whose evidence smuggles private key material", () => {
    assert.throws(() =>
      normalizeAgentFilesystemObservation({
        agent: AGENT,
        evidenceItem: windowsEvidenceItem({
          metadata: [
            { name: "locationKind", value: "windows_store" },
            { name: "locationSlot", value: "LocalMachine/My/deadbeef" },
            { name: "targetHost", value: "iis-01.example" },
            {
              name: "privateKey",
              value: "-----BEGIN PRIVATE KEY-----\nMIIBogI\n-----END PRIVATE KEY-----",
            },
          ],
        }),
      }),
    );
  });
});

describe("_test.windowsLocationFieldsFor", () => {
  it("defaults storeLocation/storeName to LocalMachine/My when omitted", () => {
    const fields = _test.windowsLocationFieldsFor("windows_store", {});
    assert.equal(fields.storeLocation, "LocalMachine");
    assert.equal(fields.storeName, "My");
    assert.equal(fields.thumbprint, null);
  });

  for (const locationKind of ["windows_store", "iis_binding", "http_sys"]) {
    it(`validates and preserves a SHA-1 thumbprint for ${locationKind}`, () => {
      const fields = _test.windowsLocationFieldsFor(locationKind, {
        thumbprint: WINDOWS_THUMBPRINT.toLowerCase(),
      });
      assert.equal(fields.thumbprint, WINDOWS_THUMBPRINT);
    });
  }

  for (const malformed of ["deadbeef", "G".repeat(40), "A".repeat(41)]) {
    it(`rejects malformed Windows thumbprint ${JSON.stringify(malformed)}`, () => {
      assert.throws(
        () =>
          _test.windowsLocationFieldsFor("iis_binding", {
            thumbprint: malformed,
          }),
        /40-character hexadecimal SHA-1 thumbprint/,
      );
    });
  }

  it("rejects an out-of-range explicit iis_binding port rather than silently collapsing identity", () => {
    // Port is part of binding identity (site/port/optional SNI host/store),
    // matching the DB-level windows_port CHECK (1..65535) on
    // certificate_targets (migration 42). An explicitly-supplied malformed
    // port must fail loudly, not silently become null and merge with a
    // genuinely portless binding's identity.
    assert.throws(
      () => _test.windowsLocationFieldsFor("iis_binding", { port: "999999" }),
      /port must be an integer between 1 and 65535/,
    );
  });

  it("rejects a non-numeric explicit iis_binding port", () => {
    assert.throws(
      () => _test.windowsLocationFieldsFor("iis_binding", { port: "not-a-port" }),
      /port must be an integer between 1 and 65535/,
    );
  });

  it("treats an absent iis_binding port as legitimately null, not invalid", () => {
    const fields = _test.windowsLocationFieldsFor("iis_binding", {});
    assert.equal(fields.port, null);
  });

  it("accepts a valid explicit http_sys port", () => {
    const fields = _test.windowsLocationFieldsFor("http_sys", { port: "8443" });
    assert.equal(fields.port, 8443);
  });

  it("rejects an out-of-range explicit http_sys port", () => {
    assert.throws(
      () => _test.windowsLocationFieldsFor("http_sys", { port: "0" }),
      /port must be an integer between 1 and 65535/,
    );
  });

  it("returns an empty object for the filesystem locationKind", () => {
    assert.deepEqual(_test.windowsLocationFieldsFor("filesystem", {}), {});
  });
});

describe("_test.defaultLocationRef", () => {
  it("builds a winstore:// URI, preferring thumbprint over locationSlot", () => {
    const ref = _test.defaultLocationRef("windows_store", {
      targetHost: "iis-01.example",
      windowsFields: { storeLocation: "LocalMachine", storeName: "My" },
      locationSlot: "LocalMachine/My/fallback-slot",
      thumbprint: WINDOWS_THUMBPRINT,
    });
    assert.equal(ref, `winstore://LocalMachine/My/${WINDOWS_THUMBPRINT}`);
  });

  it("falls back to locationSlot for winstore:// when no thumbprint is known", () => {
    const ref = _test.defaultLocationRef("windows_store", {
      targetHost: "iis-01.example",
      windowsFields: { storeLocation: "LocalMachine", storeName: "My" },
      locationSlot: "LocalMachine/My/fallback-slot",
      thumbprint: null,
    });
    assert.equal(ref, "winstore://LocalMachine/My/fallback-slot");
  });

  it("builds an IIS URI with the full site, port, and SNI identity", () => {
    const ref = _test.defaultLocationRef("iis_binding", {
      targetHost: "iis-01.example",
      windowsFields: {
        siteName: "Default Web Site",
        port: 443,
        sniHost: "app.example.com",
      },
      locationSlot: "Default Web Site:443#app.example.com",
      thumbprint: WINDOWS_THUMBPRINT,
    });
    assert.equal(ref, "iis://Default Web Site:443#app.example.com");
  });

  it("keeps same-site/port IIS bindings distinct when their SNI hosts differ", () => {
    const referenceFor = (sniHost) =>
      _test.defaultLocationRef("iis_binding", {
        targetHost: "iis-01.example",
        windowsFields: { siteName: "Default Web Site", port: 443, sniHost },
        locationSlot: `Default Web Site:443#${sniHost}`,
        thumbprint: WINDOWS_THUMBPRINT,
      });
    assert.notEqual(
      referenceFor("app-a.example.com"),
      referenceFor("app-b.example.com"),
    );
  });

  it("builds an http-sys:// URI from the real bound address, not the machine hostname", () => {
    const ref = _test.defaultLocationRef("http_sys", {
      targetHost: "iis-01.example",
      windowsFields: { boundAddress: "0.0.0.0", port: 8443 },
      locationSlot: "0.0.0.0:8443",
      thumbprint: null,
    });
    assert.equal(ref, "http-sys://0.0.0.0:8443");
  });
});

// Regression coverage for a real-host defect (found on a live Windows
// Server 2022 QA VM running IIS with a genuine SNI HTTPS binding): the
// evidence route rejected every batch containing an iis_binding/http_sys
// observation with HTTP 500 CERTOPS_KEY_REFERENCE_INVALID, because the
// os-store-managed keyReference was set to the same iis://.../http-sys://...
// descriptor as locationRef/deploymentReference, and inventory.js's
// KEY_REFERENCE_ALLOWED_SCHEME_PREFIXES allow-list has no iis:// or
// http-sys:// scheme. Since normalizeAgentFilesystemObservation.map() runs
// for the whole batch before any DB write, this silently dropped every
// Windows discovery observation from that host, including its otherwise-
// valid windows_store entries. defaultKeyReference must always resolve to
// the winstore:// store coordinate for every non-filesystem location kind,
// because the key -- when present -- physically lives in the store the
// binding references, never in the binding descriptor itself.
describe("_test.defaultKeyReference", () => {
  it("returns null for filesystem (key reference is file:// built elsewhere)", () => {
    assert.equal(_test.defaultKeyReference("filesystem", {}), null);
  });

  it("resolves an iis_binding key reference to the underlying winstore:// store coordinate, not iis://", () => {
    const ref = _test.defaultKeyReference("iis_binding", {
      windowsFields: { storeLocation: "LocalMachine", storeName: "My" },
      locationSlot: "Default Web Site:8443",
      thumbprint: WINDOWS_THUMBPRINT,
    });
    assert.equal(ref, `winstore://LocalMachine/My/${WINDOWS_THUMBPRINT}`);
  });

  it("resolves an http_sys key reference to the underlying winstore:// store coordinate, not http-sys://", () => {
    const ref = _test.defaultKeyReference("http_sys", {
      windowsFields: { storeLocation: "LocalMachine", storeName: "My" },
      locationSlot: "0.0.0.0:8443",
      thumbprint: WINDOWS_THUMBPRINT,
    });
    assert.equal(ref, `winstore://LocalMachine/My/${WINDOWS_THUMBPRINT}`);
  });

  it("does not reinterpret an IIS binding identity as a custody pointer when no thumbprint is known", () => {
    const ref = _test.defaultKeyReference("iis_binding", {
      windowsFields: { storeLocation: "LocalMachine", storeName: "My" },
      locationSlot: "Default Web Site:8443",
      thumbprint: null,
    });
    assert.equal(ref, null);
  });

  it("uses default store location/name with a real thumbprint", () => {
    const ref = _test.defaultKeyReference("http_sys", {
      windowsFields: {},
      locationSlot: "0.0.0.0:443",
      thumbprint: WINDOWS_THUMBPRINT,
    });
    assert.equal(ref, `winstore://LocalMachine/My/${WINDOWS_THUMBPRINT}`);
  });
});

describe("real-host regression: iis_binding/http_sys observations with a private key must pass keyReference validation", () => {
  const { normalizeKeyReference } = require(
    path.resolve(__dirname, "../../apps/api/services/certops/inventory.js"),
  );

  function keyReferenceForObservation(evidenceItem) {
    const observation = normalizeAgentFilesystemObservation({
      agent: AGENT,
      evidenceItem,
    });
    const keyReference =
      observation.locationKind === "filesystem"
        ? `file://${observation.filePath}`
        : _test.defaultKeyReference(observation.locationKind, {
            windowsFields: observation.windowsFields,
            locationSlot: observation.locationSlot,
            thumbprint: observation.windowsFields?.thumbprint,
          });
    // Must not throw CERTOPS_KEY_REFERENCE_INVALID, exactly as
    // upsertManagedCertificateByMonitorSource would apply it server-side.
    return normalizeKeyReference(keyReference);
  }

  it("accepts an IIS SNI binding observation with a store-resident private key", () => {
    const ref = keyReferenceForObservation({
      evidenceId: "ev_iis_1",
      eventType: "certificate.observed",
      observedAt: "2026-08-08T11:45:00.000Z",
      fingerprintSha256: "5".repeat(64),
      metadata: [
        { name: "locationKind", value: "iis_binding" },
        { name: "locationSlot", value: "Default Web Site:8443" },
        { name: "targetHost", value: "iis-qa.example.com" },
        { name: "siteName", value: "Default Web Site" },
        { name: "port", value: "8443" },
        { name: "sniHost", value: "iis-qa.example.com" },
        { name: "storeLocation", value: "LocalMachine" },
        { name: "storeName", value: "My" },
        { name: "thumbprint", value: WINDOWS_THUMBPRINT },
        { name: "keyPresent", value: true },
      ],
    });
    assert.equal(ref, `winstore://LocalMachine/My/${WINDOWS_THUMBPRINT}`);
  });

  it("accepts a real http_sys binding observation with a store-resident private key", () => {
    const ref = keyReferenceForObservation({
      evidenceId: "ev_httpsys_1",
      eventType: "certificate.observed",
      observedAt: "2026-08-08T11:45:00.000Z",
      fingerprintSha256: "6".repeat(64),
      metadata: [
        { name: "locationKind", value: "http_sys" },
        { name: "locationSlot", value: "0.0.0.0:5986" },
        { name: "targetHost", value: "iis-qa.example.com" },
        { name: "boundAddress", value: "0.0.0.0" },
        { name: "port", value: "5986" },
        { name: "storeLocation", value: "LocalMachine" },
        { name: "storeName", value: "My" },
        { name: "thumbprint", value: WINDOWS_THUMBPRINT },
        { name: "keyPresent", value: true },
      ],
    });
    assert.equal(ref, `winstore://LocalMachine/My/${WINDOWS_THUMBPRINT}`);
  });

  it("prefers an explicit thumbprint over locationSlot when the agent does supply one", () => {
    const ref = keyReferenceForObservation({
      evidenceId: "ev_iis_2",
      eventType: "certificate.observed",
      observedAt: "2026-08-08T11:45:00.000Z",
      fingerprintSha256: "7".repeat(64),
      metadata: [
        { name: "locationKind", value: "windows_store" },
        { name: "locationSlot", value: "LocalMachine/My/some-cn" },
        { name: "targetHost", value: "iis-qa.example.com" },
        { name: "storeLocation", value: "LocalMachine" },
        { name: "storeName", value: "My" },
        { name: "thumbprint", value: "587c96d037a416002a3cbeeb7c6e8c31e1dc2c94" },
        { name: "keyPresent", value: true },
      ],
    });
    assert.equal(ref, "winstore://LocalMachine/My/587C96D037A416002A3CBEEB7C6E8C31E1DC2C94");
  });
});

describe("certSourceRefFor / targetSourceRefFor - Windows location identity", () => {
  function windowsObservation(overrides = {}) {
    return normalizeAgentFilesystemObservation({
      agent: AGENT,
      evidenceItem: {
        evidenceId: "ev_id_1",
        eventType: "certificate.observed",
        observedAt: "2026-07-24T08:00:00.000Z",
        fingerprintSha256: "3".repeat(64),
        metadata: [
          { name: "locationKind", value: "windows_store" },
          { name: "locationSlot", value: "LocalMachine/My/deadbeef" },
          { name: "targetHost", value: "iis-01.example" },
        ],
        ...overrides,
      },
    });
  }

  it("keeps the same certSourceRef across a fingerprint rotation at the same binding", () => {
    const before = windowsObservation({ fingerprintSha256: "3".repeat(64) });
    const after = windowsObservation({ fingerprintSha256: "4".repeat(64) });

    assert.equal(
      _test.certSourceRefFor(before),
      _test.certSourceRefFor(after),
      "a renewed certificate at the same location must keep the same logical identity, not create a duplicate",
    );
  });

  it("produces a distinct certSourceRef for two different bindings on the same host", () => {
    const bindingA = windowsObservation({
      metadata: [
        { name: "locationKind", value: "iis_binding" },
        { name: "locationSlot", value: "Site-A:443" },
        { name: "targetHost", value: "iis-01.example" },
      ],
    });
    const bindingB = windowsObservation({
      metadata: [
        { name: "locationKind", value: "iis_binding" },
        { name: "locationSlot", value: "Site-B:8443" },
        { name: "targetHost", value: "iis-01.example" },
      ],
    });

    assert.notEqual(
      _test.certSourceRefFor(bindingA),
      _test.certSourceRefFor(bindingB),
      "two distinct bindings on the same host must never be conflated into one location",
    );
  });

  it("keeps distinct targets for bindings with different executor topology", () => {
    const bindingA = windowsObservation({
      metadata: [
        { name: "locationKind", value: "iis_binding" },
        { name: "locationSlot", value: "Site-A:443" },
        { name: "targetHost", value: "iis-01.example" },
      ],
    });
    const bindingB = windowsObservation({
      metadata: [
        { name: "locationKind", value: "iis_binding" },
        { name: "locationSlot", value: "Site-B:8443" },
        { name: "targetHost", value: "iis-01.example" },
      ],
    });

    assert.notEqual(
      _test.targetSourceRefFor(bindingA),
      _test.targetSourceRefFor(bindingB),
      "site/port topology must not be overwritten by another binding on the same host",
    );
  });

  it("gives filesystem and Windows discovery on the same host distinct targets", () => {
    const filesystemObservation = normalizeAgentFilesystemObservation({
      agent: AGENT,
      evidenceItem: {
        evidenceId: "ev_fs_1",
        eventType: "certificate.observed",
        observedAt: "2026-07-24T08:00:00.000Z",
        fingerprintSha256: "5".repeat(64),
        metadata: [
          { name: "filePath", value: "/etc/ssl/certs/app.pem" },
          { name: "targetHost", value: "iis-01.example" },
        ],
      },
    });
    const windowsObs = windowsObservation();

    assert.notEqual(
      _test.targetSourceRefFor(filesystemObservation),
      _test.targetSourceRefFor(windowsObs),
    );
  });
});

describe("persistAgentDiscoveryEvidenceBatch - Windows discovery persistence (observed-location gap)", () => {
  function buildWindowsClient(queries) {
    return {
      async query(sql, params) {
        queries.push({ sql, params });
        if (sql === "BEGIN" || sql === "COMMIT") return { rows: [] };
        if (sql.includes("SET last_sequence")) {
          return { rows: [{ id: AGENT.id }] };
        }
        if (sql.includes("FROM certificate_evidence")) {
          return { rows: [] };
        }
        if (sql.includes("FROM managed_certificates") && sql.includes("SELECT")) {
          return { rows: [] };
        }
        if (sql.includes("FROM tokens") && sql.includes("SELECT")) {
          return { rows: [] };
        }
        if (sql.includes("INSERT INTO tokens")) {
          return { rows: [{ id: 9001 }] };
        }
        if (sql.includes("INSERT INTO managed_certificates")) {
          return {
            rows: [
              {
                id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                token_id: 9001,
                workspace_id: AGENT.workspaceId,
                status: "discovered",
                key_mode: "os-store-managed",
              },
            ],
          };
        }
        if (sql.includes("INSERT INTO certificate_targets")) {
          return { rows: [{ id: "target-win-1", location_kind: "windows_store" }] };
        }
        if (sql.includes("INSERT INTO certificate_instances")) {
          return { rows: [{ id: "instance-win-1", location_kind: "windows_store" }] };
        }
        if (sql.includes("INSERT INTO certificate_evidence")) {
          return { rows: [{ id: "evidence-win-1" }] };
        }
        return { rows: [] };
      },
      release() {},
    };
  }

  it("persists a Windows machine-store certificate as a durable observed location", async () => {
    const queries = [];
    const client = buildWindowsClient(queries);
    const dbPool = { async connect() { return client; } };

    const result = await persistAgentDiscoveryEvidenceBatch({
      dbPool,
      agent: AGENT,
      envelope: { sequence: 5 },
      evidenceItems: [
        {
          evidenceId: "ev_win_persist_1",
          eventType: "certificate.observed",
          observedAt: "2026-07-24T08:00:00.000Z",
          fingerprintSha256: "6".repeat(64),
          metadata: [
            { name: "locationKind", value: "windows_store" },
            { name: "locationSlot", value: "LocalMachine/My/deadbeef" },
            { name: "targetHost", value: "iis-01.example" },
            { name: "storeLocation", value: "LocalMachine" },
            { name: "storeName", value: "My" },
            { name: "thumbprint", value: WINDOWS_THUMBPRINT },
            { name: "subject", value: "CN=app.example.com" },
            { name: "validFrom", value: "2026-01-01T00:00:00.000Z" },
            { name: "validTo", value: "2027-01-01T00:00:00.000Z" },
            { name: "keyPresent", value: true },
          ],
        },
      ],
      deps: {
        enforceAgentSequence: async ({ client: c, envelope }) => {
          await c.query("SET last_sequence = $1", [envelope.sequence]);
        },
      },
    });

    assert.equal(result.ok, true);

    const certInsert = queries.find((entry) =>
      entry.sql.includes("INSERT INTO managed_certificates"),
    );
    assert.ok(certInsert, "expected a managed_certificate insert");
    // keyMode is the 20th bound param (index 19, 0-based; see
    // upsertManagedCertificateByMonitorSource's params array).
    assert.equal(
      certInsert.params[19],
      "os-store-managed",
      "a confirmed private-key presence marks the location os-store-managed",
    );
    assert.equal(
      certInsert.params[20],
      `winstore://LocalMachine/My/${WINDOWS_THUMBPRINT}`,
      "Windows key custody must point to the real store thumbprint, not the location identity",
    );
    // deployed_cert_path is the 24th bound param; Windows discovery has no
    // filesystem path to offer, unlike filesystem discovery.
    assert.equal(
      certInsert.params[23],
      null,
      "Windows discovery has no filesystem path; deployed_cert_path must stay null",
    );
    assert.equal(
      certInsert.params[24],
      AGENT.id,
      "deployed_agent_id must still be populated (used for Observed Locations' responsible-agent display and deploy-job cert resolution; renewal-path health separately excludes os-store-managed certificates as not_agent_deployable regardless of this value)",
    );

    const targetInsert = queries.find((entry) =>
      entry.sql.includes("INSERT INTO certificate_targets"),
    );
    assert.ok(targetInsert, "expected a certificate_targets insert");
    assert.ok(
      targetInsert.params.includes("windows_store"),
      "the target insert must carry the windows_store location_kind",
    );

    const instanceInsert = queries.find((entry) =>
      entry.sql.includes("INSERT INTO certificate_instances"),
    );
    assert.ok(instanceInsert, "expected a certificate_instances insert");
    assert.ok(
      instanceInsert.params.includes("windows_store"),
      "the instance insert must carry the windows_store location_kind",
    );

    const allParamsSerialized = JSON.stringify(
      queries.flatMap((entry) => entry.params || []),
    ).toLowerCase();
    assert.equal(
      allParamsSerialized.includes("private key"),
      false,
      "no private key material must ever reach a persisted row",
    );
  });

  it("targets the same certificate/target identity on a repeated scan of the same binding (no duplicate location)", async () => {
    const firstScanQueries = [];
    const secondScanQueries = [];
    const evidenceItemFor = (evidenceId, fingerprintSha256) => ({
      evidenceId,
      eventType: "certificate.observed",
      observedAt: "2026-07-24T08:00:00.000Z",
      fingerprintSha256,
      metadata: [
        { name: "locationKind", value: "windows_store" },
        { name: "locationSlot", value: "LocalMachine/My/deadbeef" },
        { name: "targetHost", value: "iis-01.example" },
        { name: "storeLocation", value: "LocalMachine" },
        { name: "storeName", value: "My" },
        { name: "thumbprint", value: WINDOWS_THUMBPRINT },
        { name: "validFrom", value: "2026-01-01T00:00:00.000Z" },
        { name: "validTo", value: "2027-01-01T00:00:00.000Z" },
      ],
    });
    const deps = {
      enforceAgentSequence: async ({ client: c, envelope }) => {
        await c.query("SET last_sequence = $1", [envelope.sequence]);
      },
    };

    await persistAgentDiscoveryEvidenceBatch({
      dbPool: { async connect() { return buildWindowsClient(firstScanQueries); } },
      agent: AGENT,
      envelope: { sequence: 6 },
      evidenceItems: [evidenceItemFor("ev_scan_1", "7".repeat(64))],
      deps,
    });

    // Second scan observes a rotated fingerprint at the exact same binding
    // (same locationSlot). The renewed certificate must resolve to the same
    // logical location, not a new one.
    await persistAgentDiscoveryEvidenceBatch({
      dbPool: { async connect() { return buildWindowsClient(secondScanQueries); } },
      agent: AGENT,
      envelope: { sequence: 7 },
      evidenceItems: [evidenceItemFor("ev_scan_2", "8".repeat(64))],
      deps,
    });

    const sourceRefFromLookup = (queries) =>
      queries.find((entry) => entry.sql.includes("FROM managed_certificates") && entry.sql.includes("source_ref"))
        ?.params?.find((value) => typeof value === "string" && value.includes("windows_store"));

    const firstRef = sourceRefFromLookup(firstScanQueries);
    const secondRef = sourceRefFromLookup(secondScanQueries);
    assert.ok(firstRef, "expected the first scan to look up the certificate by its stable source_ref");
    assert.equal(
      firstRef,
      secondRef,
      "a rotated fingerprint at the same binding must reuse the same source_ref identity across scans",
    );
  });
});
