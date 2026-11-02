"use strict";
// Dedicated trusted-main entry point. Unlike the optional developer baseline,
// this campaign has no skip path and cannot succeed without real Azure + PG.
const fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const policy = require("../../infra/certops-azure-keyvault/policy");
const lab = require("../../infra/certops-azure-keyvault/lab");
const io = require("./helpers/azure-keyvault-live-io.cjs");
const reports = require("../../scripts/certops-azure-keyvault-report");
const packager = require("../../scripts/certops-agent-package");
const { check, rejects, eventually } = io;
const resultFile = path.resolve(
  "qualification-results/azure-keyvault-evidence.json",
);
function inventoryHash(files) {
  return crypto
    .createHash("sha256")
    .update(
      JSON.stringify(
        Object.entries(files).sort(([a], [b]) => a.localeCompare(b)),
      ),
    )
    .digest("hex");
}
function context() {
  policy.requireTrusted(process.env);
  check(
    process.platform === "linux" &&
      process.env.TT_REAL_AZURE === "1" &&
      process.env.TT_AZURE_QUALIFICATION_REQUIRED === "1",
    "AZURE_KV_MANDATORY_LINUX_CAMPAIGN_REQUIRED",
  );
  const root = lab.privateRoot(),
    state = lab.load(path.join(root, "state.json"));
  lab.assertPlan(state);
  check(
    state.tags.runId === process.env.GITHUB_RUN_ID &&
      state.tags.attempt === process.env.GITHUB_RUN_ATTEMPT &&
      state.tags.sourceSha === process.env.GITHUB_SHA,
    "AZURE_KV_CAMPAIGN_OWNER_MISMATCH",
  );
  return { root, state };
}
async function prepare() {
  const { root, state } = context();
  await lab.verifyOwned(state);
  const outputRoot = path.join(root, "candidate");
  const receipt = packager.buildCandidate({
    sourcePackage: path.resolve("packages/agent"),
    outputRoot,
    candidateSha: process.env.GITHUB_SHA,
    capabilities: ["material-store-azure-key-vault-v1"],
  });
  const candidate = packager.extractVerified({
    tarball: path.join(outputRoot, "artifacts", receipt.archive),
    expectedSha256: receipt.sha256,
    destination: path.join(root, "extracted"),
  });
  lab.save(path.join(root, "candidate.json"), {
    root: candidate.root,
    sha256: receipt.sha256,
    archive: receipt.archive,
    inventorySha256: inventoryHash(candidate.files),
  });
  const auth = {
    type: "workload-identity",
    tenantId: state.tenantId,
    clientId: state.identities.issuer.clientId,
    assertionFile: path.join(root, "assertion.jwt"),
  };
  const config = {
    provider: "azure-key-vault",
    address: `https://${state.vault}.vault.azure.net`,
    timeoutMs: 15000,
    auth,
  };
  let issued = await io.assertion(root);
  const { credential } = require(
    path.join(candidate.root, "src/material-store/azure"),
  );
  const { requestJson } = require(
    path.join(candidate.root, "src/material-store/transport"),
  );
  const token = credential(config, config.timeoutMs);
  await eventually(async () => {
    // Only idempotent token acquisition and metadata GETs are retried for RBAC.
    try {
      if (issued.expiresAt < Date.now() + 120000)
        issued = await io.assertion(root);
      const response = await requestJson(
        new URL("/secrets?api-version=7.4&maxresults=1", config.address),
        { headers: { Authorization: `Bearer ${await token(true)}` } },
      );
      return response.status === 200;
    } catch {
      return false;
    }
  }, "AZURE_KV_ISSUER_RBAC_OR_FEDERATION_NOT_READY_AT_RUN_VAULT");
  const file = path.join(root, "baseline-config.json");
  lab.save(file, config);
  check(
    path.isAbsolute(process.env.GITHUB_ENV || ""),
    "AZURE_KV_GITHUB_ENV_REQUIRED",
  );
  fs.appendFileSync(process.env.GITHUB_ENV, `TT_REAL_AZURE_CONFIG=${file}\n`);
}
async function run() {
  const { root, state } = context();
  await lab.verifyOwned(state);
  const candidate = lab.load(path.join(root, "candidate.json"));
  check(
    candidate.root === path.join(root, "extracted", "package") &&
      /^[a-f0-9]{64}$/.test(candidate.sha256),
    "AZURE_KV_PACKAGE_STATE_INVALID",
  );
  const verifyPackage = () => {
    check(
      candidate.archive === path.basename(candidate.archive) &&
        candidate.archive.endsWith(".tgz") &&
        packager.digest(
          path.join(root, "candidate/artifacts", candidate.archive),
        ) === candidate.sha256 &&
        inventoryHash(packager.inventory(candidate.root)) ===
          candidate.inventorySha256,
      "AZURE_KV_PACKAGE_BYTES_CHANGED",
    );
  };
  verifyPackage();
  const original = JSON.parse(
    fs.readFileSync(
      "packages/agent/src/capabilities/qualified-capabilities.json",
      "utf8",
    ),
  );
  check(
    !original.qualified.includes("material-store-azure-key-vault-v1") &&
      !original.qualified.includes("windows-material-iis-v1"),
    "AZURE_KV_PRODUCTION_GATE_MUST_REMAIN_DISABLED",
  );
  const config = lab.load(path.join(root, "baseline-config.json"));
  check(
    config.address === `https://${state.vault}.vault.azure.net`,
    "AZURE_KV_CAMPAIGN_ENDPOINT_DENIED",
  );
  const { createMaterialStore, readProtectedFile } = require(
    path.join(candidate.root, "src/material-store"),
  );
  const { credential } = require(
    path.join(candidate.root, "src/material-store/azure"),
  );
  const { requestJson } = require(
    path.join(candidate.root, "src/material-store/transport"),
  );
  const boundary = new io.FaultBoundary(
    `${state.vault}.vault.azure.net`,
  ).install();
  const report = reports.emptyReport(process.env.GITHUB_SHA, candidate.sha256);
  fs.mkdirSync(path.dirname(resultFile), { recursive: true });
  let bridge,
    active = null,
    assertionRenewalFailure = false,
    assertionTask = Promise.resolve();
  // A customer normally renews its projected assertion externally. Keep that
  // real GitHub sink fresh during potentially slow RBAC propagation too.
  let issued = await io.assertion(root);
  const renewer = setInterval(() => {
    assertionTask = assertionTask
      .then(async () => {
        if (issued.expiresAt < Date.now() + 120000)
          issued = await io.assertion(root);
      })
      .catch(() => {
        assertionRenewalFailure = true;
      });
  }, 60000);
  renewer.unref();
  function write() {
    report.counts = reports.counts(report.scenarios);
    report.facts.azure401Responses = boundary.events.filter(
      (e) => e.kind === "vault" && e.status === 401,
    ).length;
    report.facts.azure403Responses = boundary.events.filter(
      (e) => e.kind === "vault" && e.status === 403,
    ).length;
    report.facts.entraTokenExchanges = boundary.events.filter(
      (e) => e.kind === "entra" && e.status === 200,
    ).length;
    lab.save(resultFile, report);
  }
  async function scenario(id, task) {
    active = report.scenarios.find((row) => row.id === id);
    check(active?.status === "pending", "AZURE_KV_SCENARIO_INVENTORY_INVALID");
    check(
      !assertionRenewalFailure,
      "AZURE_KV_EXTERNAL_ASSERTION_RENEWAL_FAILED",
    );
    await task();
    check(
      !assertionRenewalFailure,
      "AZURE_KV_EXTERNAL_ASSERTION_RENEWAL_FAILED",
    );
    active.status = "passed";
    active = null;
    write();
    console.log(`Azure qualification: ${id} passed`);
  }
  const authFor = (kind) => ({
    ...config.auth,
    clientId: state.identities[kind].clientId,
  });
  const tokens = Object.fromEntries(
    Object.keys(state.identities).map((kind) => [
      kind,
      credential({ ...config, auth: authFor(kind) }, config.timeoutMs),
    ]),
  );
  async function api(kind, method, route, body) {
    check(
      /^\/secrets(?:\?|\/tt-[a-f0-9]{64}(?:\/|\?|$))/.test(route),
      "AZURE_KV_DATA_SCOPE_DENIED",
    );
    const url = new URL(route, config.address);
    url.searchParams.set("api-version", "7.4");
    return requestJson(url, {
      method,
      body,
      timeoutMs: 15000,
      maxBytes: 100000,
      headers: {
        Authorization: `Bearer ${await tokens[kind]()}`,
        "Content-Type": "application/json",
      },
    });
  }
  async function versions(store) {
    const response = await api(
      "issuer",
      "GET",
      `/secrets/${store.objectRef}/versions?maxresults=25`,
    );
    check(
      response.status === 200 &&
        Array.isArray(response.json?.value) &&
        !response.json.nextLink &&
        response.json.value.every((row) => !Object.hasOwn(row, "value")),
      "AZURE_KV_VERSION_METADATA_INVALID",
    );
    return response.json.value;
  }
  async function approve(stores) {
    state.approvedSecrets = [
      ...new Set([
        ...(state.approvedSecrets || []),
        ...stores.map((store) => store.objectRef),
      ]),
    ];
    lab.save(path.join(root, "state.json"), state);
    await lab.consumerAccess(
      state,
      stores.map((store) => store.objectRef),
      true,
    );
  }
  try {
    write();
    let first, published, second, renewed, approved;
    await scenario("owned-isolated-rbac-resources", async () => {
      const inventory = lab.arm(
        "GET",
        lab.groupId(state) + "/resources?api-version=2021-04-01",
      );
      check(!inventory.nextLink, "AZURE_KV_PARTIAL_RESOURCE_INVENTORY_DENIED");
      policy.ownedResources(inventory.value, state);
      for (const kind of ["issuer", "consumer", "attributes"])
        policy.roleDefinition(
          lab.arm(
            "GET",
            `/subscriptions/${state.subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/${state.roles[kind]}?api-version=2022-04-01`,
          ),
          kind,
        );
    });
    await scenario("signed-packaged-publication-and-postgres-pin", async () => {
      bridge = await require("./helpers/azure-keyvault-core.cjs").open({
        root,
        packageRoot: candidate.root,
        config,
        materials: io.makeMaterial(root),
      });
      first = await bridge.publication(0);
      published = await first.session.publish(first.bundle, first.lease);
      await bridge.accept(first, published);
      report.facts.acceptedProviderPins++;
      check(
        /^[a-f0-9]{32}$/.test(published.publicationReceipt.providerVersion),
        "AZURE_KV_OPAQUE_VERSION_MISSING",
      );
      check(
        !JSON.stringify(published).includes(first.bundle.privateKeyPem),
        "AZURE_KV_PRIVATE_KEY_IN_PUBLICATION_RESULT",
      );
    });
    await scenario("exact-version-full-chain-and-key-association", async () => {
      const fetched = await first.session.store.fetch(
        published.publicationReceipt.providerVersion,
      );
      check(
        JSON.stringify(fetched) === JSON.stringify(first.bundle) &&
          io.verifyMaterial(fetched) === first.bundle.fingerprintSha256,
        "AZURE_KV_EXACT_MATERIAL_MISMATCH",
      );
      check(
        (await versions(first.session.store)).length === 1,
        "AZURE_KV_UNEXPECTED_PROVIDER_VERSION_COUNT",
      );
    });
    await scenario("consumer-approved-secret-only", async () => {
      await approve([first.session.store]);
      approved = createMaterialStore(bridge.stores(authFor("consumer")), {
        ...first.signed.publication,
        workspaceId: bridge.workspaceId,
      });
      await eventually(async () => {
        try {
          return (
            io.verifyMaterial(
              await approved.fetch(
                published.publicationReceipt.providerVersion,
              ),
            ) === first.bundle.fingerprintSha256
          );
        } catch {
          return false;
        }
      }, "AZURE_KV_CONSUMER_RBAC_NOT_READY_AT_APPROVED_SECRET");
    });
    await scenario("consumer-cannot-write-or-modify", async () => {
      const route = `/secrets/${first.session.store.objectRef}`;
      check(
        (await api("consumer", "PUT", route, { value: "must-not-be-written" }))
          .status === 403,
        "AZURE_KV_CONSUMER_WRITE_NOT_DENIED",
      );
      check(
        (
          await api(
            "consumer",
            "PATCH",
            `${route}/${published.publicationReceipt.providerVersion}`,
            { attributes: { enabled: false } },
          )
        ).status === 403,
        "AZURE_KV_CONSUMER_MODIFY_NOT_DENIED",
      );
      check(
        (await versions(first.session.store)).length === 1,
        "AZURE_KV_UNAUTHORIZED_WRITE_CREATED_VERSION",
      );
    });
    await scenario(
      "unauthorized-identity-and-foreign-scope-denied",
      async () => {
        await eventually(async () => {
          try {
            return (
              (
                await api(
                  "unauthorized",
                  "GET",
                  `/secrets/${first.session.store.objectRef}/${published.publicationReceipt.providerVersion}`,
                )
              ).status === 403
            );
          } catch {
            return false;
          }
        }, "AZURE_KV_UNAUTHORIZED_IDENTITY_FEDERATION_NOT_READY");
        const intent = {
          ...first.signed.publication,
          workspaceId: bridge.workspaceId,
        };
        const before = boundary.events.length;
        for (const change of [
          { workspaceId: crypto.randomUUID() },
          { groupId: crypto.randomUUID() },
        ])
          await rejects(
            async () =>
              createMaterialStore(bridge.stores(authFor("consumer")), {
                ...intent,
                ...change,
              }),
            ["material_scope_denied"],
          );
        check(
          boundary.events.length === before,
          "AZURE_KV_FOREIGN_SCOPE_CONTACTED_PROVIDER",
        );
        const foreign = createMaterialStore(
          bridge.stores(authFor("consumer")),
          { ...intent, materialVersionId: crypto.randomUUID() },
        );
        await rejects(
          () => foreign.fetch(published.publicationReceipt.providerVersion),
          ["material_auth_denied"],
        );
      },
    );
    await scenario("missing-version-no-latest-fallback", async () => {
      await rejects(
        () => approved.fetch("0".repeat(32)),
        ["material_version_unavailable"],
      );
      await rejects(
        () => approved.fetch(undefined),
        ["material_provider_version_invalid"],
      );
    });
    await scenario("real-401-renews-workload-token", async () => {
      const before = boundary.events.filter(
        (e) => e.kind === "entra" && e.status === 200,
      ).length;
      boundary.set(
        "real-401",
        `/secrets/${approved.objectRef}/${published.publicationReceipt.providerVersion}`,
      );
      await approved.fetch(published.publicationReceipt.providerVersion);
      check(
        boundary.events.some((e) => e.corrupt && e.status === 401) &&
          boundary.events.filter((e) => e.kind === "entra" && e.status === 200)
            .length > before,
        "AZURE_KV_REAL_401_REFRESH_NOT_OBSERVED",
      );
      boundary.clear();
    });
    await scenario("disabled-version-fails-closed", async () => {
      const route = `/secrets/${approved.objectRef}/${published.publicationReceipt.providerVersion}`;
      await eventually(async () => {
        try {
          return (
            (
              await api("attributes", "PATCH", route, {
                attributes: { enabled: false },
              })
            ).status === 200
          );
        } catch {
          return false;
        }
      }, "AZURE_KV_ATTRIBUTES_RBAC_NOT_READY_AT_RUN_VAULT");
      try {
        await rejects(
          () => approved.fetch(published.publicationReceipt.providerVersion),
          ["material_auth_denied", "material_version_unavailable"],
        );
      } finally {
        check(
          (
            await api("attributes", "PATCH", route, {
              attributes: { enabled: true },
            })
          ).status === 200,
          "AZURE_KV_VERSION_REENABLE_FAILED",
        );
      }
    });
    await scenario(
      "transient-reset-and-response-deadline-recovery",
      async () => {
        for (const kind of ["reset-get", "timeout-get"]) {
          const fault = boundary.set(
            kind,
            `/secrets/${approved.objectRef}/${published.publicationReceipt.providerVersion}`,
          );
          check(
            io.verifyMaterial(
              await approved.fetch(
                published.publicationReceipt.providerVersion,
              ),
            ) === first.bundle.fingerprintSha256 && fault.used,
            "AZURE_KV_TRANSPORT_RECOVERY_FAILED",
          );
          boundary.clear();
        }
      },
    );
    await scenario("committed-lost-response-durable-uncertainty", async () => {
      second = await bridge.publication(1);
      const route = `/secrets/${second.session.store.objectRef}`;
      const fault = boundary.set("ambiguous-put", route, { blockReads: true });
      await rejects(
        () => second.session.publish(second.bundle, second.lease),
        ["material_publication_uncertain"],
      );
      check(
        fault.committed && boundary.puts.get(route) === 1,
        "AZURE_KV_AMBIGUOUS_COMMIT_NOT_OBSERVED",
      );
      report.facts.ambiguousPutAttempts = boundary.puts.get(route);
      const checkpoint = JSON.parse(
        readProtectedFile(
          path.join(second.session.directory, "checkpoint.json"),
        ),
      );
      check(
        checkpoint.writeAttempted === true &&
          checkpoint.phase === "publication_started",
        "AZURE_KV_UNCERTAIN_JOURNAL_LOST",
      );
      await rejects(
        () => second.recreate().recover(second.lease),
        ["material_publication_uncertain", "material_store_unavailable"],
      );
      check(
        boundary.puts.get(route) === 1 &&
          JSON.parse(
            readProtectedFile(
              path.join(second.session.directory, "checkpoint.json"),
            ),
          ).writeAttempted === true,
        "AZURE_KV_AMBIGUOUS_PUT_REPEATED_OR_UNCERTAINTY_LOST",
      );
      boundary.clear();
    });
    await scenario(
      "restart-reconciles-one-exact-version-without-put",
      async () => {
        renewed = await second.recreate().recover(second.lease);
        check(
          renewed.status === "succeeded" &&
            boundary.puts.get(`/secrets/${second.session.store.objectRef}`) ===
              1 &&
            (await versions(second.session.store)).length === 1,
          "AZURE_KV_AMBIGUOUS_RECOVERY_CREATED_DUPLICATE",
        );
        report.facts.ambiguousPutAttempts = boundary.puts.get(
          `/secrets/${second.session.store.objectRef}`,
        );
        report.facts.recoveredProviderVersions = (
          await versions(second.session.store)
        ).length;
        check(
          io.verifyMaterial(
            await second.session.store.fetch(
              renewed.publicationReceipt.providerVersion,
            ),
          ) === second.bundle.fingerprintSha256,
          "AZURE_KV_RECOVERY_CHANGED_APPROVED_CERTIFICATE",
        );
        await bridge.accept(second, renewed);
        report.facts.acceptedProviderPins++;
        await approve([second.session.store]);
        const consumer = createMaterialStore(
          bridge.stores(authFor("consumer")),
          { ...second.signed.publication, workspaceId: bridge.workspaceId },
        );
        await eventually(async () => {
          try {
            await consumer.fetch(renewed.publicationReceipt.providerVersion);
            return true;
          } catch {
            return false;
          }
        }, "AZURE_KV_RENEWAL_CONSUMER_RBAC_NOT_READY");
      },
    );
    await scenario(
      "linux-pinned-install-interruption-reconciliation",
      async () => {
        const deployment = await bridge.rollout(
          second,
          renewed.publicationReceipt,
          authFor("consumer"),
        );
        let checks = 0;
        const interrupted = await bridge.lifecycle.executePinnedDeployment({
          ...deployment.options,
          checkLease: async () => {
            await deployment.lease();
            if (++checks === 3)
              policy.fail("AZURE_KV_CONTROLLED_INTERRUPTION_AFTER_INSTALL");
          },
        });
        check(
          interrupted.status === "orphaned_unknown_effect",
          "AZURE_KV_INTERRUPTION_NOT_UNCERTAIN",
        );
        const record = path.join(
          root,
          "consumer-state/material-bindings",
          `${deployment.options.job.materialDeployment.bindingId}.json`,
        );
        check(
          JSON.parse(readProtectedFile(record)).uncertain === true,
          "AZURE_KV_DEPLOYMENT_UNCERTAINTY_LOST",
        );
        await rejects(
          () => bridge.lifecycle.executePinnedDeployment(deployment.options),
          ["material_binding_uncertain"],
        );
        check(
          (await bridge.lifecycle.reconcilePinnedDeployment(deployment.options))
            .reconciled,
          "AZURE_KV_LOCAL_RECONCILIATION_FAILED",
        );
        const result = await bridge.lifecycle.executePinnedDeployment({
          ...deployment.options,
          recoveryOnly: true,
        });
        await bridge.acceptDeployment(deployment, result);
        check(
          io.verifyMaterial({
            certificatePem: fs.readFileSync(deployment.target.certPath, "utf8"),
            privateKeyPem: readProtectedFile(deployment.target.keyPath),
          }) === second.bundle.fingerprintSha256,
          "AZURE_KV_INSTALLED_CHAIN_MISMATCH",
        );
      },
    );
    await scenario("approved-retained-version-rollback", async () => {
      const deployment = await bridge.rollout(
        first,
        published.publicationReceipt,
        authFor("consumer"),
      );
      const result = await bridge.lifecycle.executePinnedDeployment(
        deployment.options,
      );
      await bridge.acceptDeployment(deployment, result);
      check(
        result.deploymentReceipt.fingerprintSha256 ===
          first.bundle.fingerprintSha256 &&
          result.deploymentReceipt.fingerprintSha256 !==
            second.bundle.fingerprintSha256,
        "AZURE_KV_RETAINED_ROLLBACK_IDENTITY_MISMATCH",
      );
    });
    await scenario("multiple-versions-never-adopt-latest", async () => {
      const intent = {
        ...first.signed.publication,
        workspaceId: bridge.workspaceId,
        materialVersionId: crypto.randomUUID(),
      };
      const bundle = {
        ...first.bundle,
        materialVersionId: intent.materialVersionId,
      };
      const store = createMaterialStore(bridge.stores(), intent);
      const receipt = await store.publish(bundle);
      check(
        (
          await api("issuer", "PUT", `/secrets/${store.objectRef}`, {
            value: "foreign-later-value",
            contentType: "text/plain",
            attributes: { enabled: true },
          })
        ).status === 200,
        "AZURE_KV_SECOND_VERSION_NOT_CREATED",
      );
      check(
        io.verifyMaterial(await store.fetch(receipt.providerVersion)) ===
          bundle.fingerprintSha256 && (await versions(store)).length === 2,
        "AZURE_KV_EXACT_VERSION_FELL_BACK_TO_LATEST",
      );
      await rejects(() => store.recover(), ["material_cas_conflict"]);
    });
    await scenario("rbac-revocation-and-restoration", async () => {
      await lab.consumerAccess(state, [approved.objectRef], false);
      await eventually(
        async () =>
          (
            await api(
              "consumer",
              "GET",
              `/secrets/${approved.objectRef}/${published.publicationReceipt.providerVersion}`,
            )
          ).status === 403,
        "AZURE_KV_CONSUMER_REVOCATION_NOT_PROPAGATED",
      );
      await rejects(
        () => approved.fetch(published.publicationReceipt.providerVersion),
        ["material_auth_denied"],
      );
      await lab.consumerAccess(state, [approved.objectRef], true);
      await eventually(
        async () =>
          (
            await api(
              "consumer",
              "GET",
              `/secrets/${approved.objectRef}/${published.publicationReceipt.providerVersion}`,
            )
          ).status === 200,
        "AZURE_KV_CONSUMER_RESTORATION_NOT_PROPAGATED",
      );
    });
    await scenario(
      "token-file-rotation-and-expired-sink-rejection",
      async () => {
        const sink = path.join(root, "consumer-token.json");
        const tokenFileAuth = { type: "token-file", tokenFile: sink };
        const client = createMaterialStore(bridge.stores(tokenFileAuth), {
          ...first.signed.publication,
          workspaceId: bridge.workspaceId,
        });
        lab.save(sink, {
          accessToken: await tokens.consumer(),
          expiresOn: Date.now() + 300000,
        });
        await client.fetch(published.publicationReceipt.providerVersion);
        lab.save(sink, {
          accessToken: await tokens.unauthorized(),
          expiresOn: Date.now() + 300000,
        });
        await rejects(
          () => client.fetch(published.publicationReceipt.providerVersion),
          ["material_auth_denied"],
        );
        lab.save(sink, {
          accessToken: await tokens.consumer(true),
          expiresOn: Date.now() + 300000,
        });
        await client.fetch(published.publicationReceipt.providerVersion);
        // Expired local sink metadata, explicitly not natural Azure token expiry.
        lab.save(sink, {
          accessToken: await tokens.consumer(),
          expiresOn: Date.now() - 1000,
        });
        await rejects(
          () => client.fetch(published.publicationReceipt.providerVersion),
          ["material_auth_unavailable"],
        );
      },
    );
    await scenario("real-oidc-assertion-expiry-and-renewal", async () => {
      clearInterval(renewer);
      await assertionTask;
      const issued = await io.assertion(root);
      const wait = issued.expiresAt + 90000 - Date.now();
      check(
        wait > 0 && wait < 20 * 60000,
        "AZURE_KV_ASSERTION_EXPIRY_OUTSIDE_BUDGET",
      );
      // Wait for genuine JWT expiry (including Entra clock tolerance), then
      // force an actual exchange. No backdated token or mocked identity server.
      await lab.sleep(wait);
      await eventually(
        async () => {
          const before = boundary.events.length;
          try {
            await credential(
              { ...config, auth: authFor("consumer") },
              config.timeoutMs,
            )(true);
            return false;
          } catch (error) {
            return (
              error.code === "material_auth_unavailable" &&
              boundary.events
                .slice(before)
                .some(
                  (e) => e.kind === "entra" && [400, 401].includes(e.status),
                )
            );
          }
        },
        "AZURE_KV_REAL_EXPIRED_ASSERTION_NOT_DENIED",
        5 * 60000,
      );
      await io.assertion(root);
      await tokens.consumer(true);
      const fresh = createMaterialStore(bridge.stores(authFor("consumer")), {
        ...first.signed.publication,
        workspaceId: bridge.workspaceId,
      });
      await fresh.fetch(published.publicationReceipt.providerVersion);
    });
    verifyPackage();
    report.facts.exactPackageVerified = true;
    report.status = "passed";
  } catch (error) {
    if (active) {
      active.status = "failed";
      active.code = io.safeCode(error);
    }
    report.status = "failed";
    throw Object.assign(new Error(io.safeCode(error)), {
      code: io.safeCode(error),
    });
  } finally {
    clearInterval(renewer);
    await assertionTask;
    boundary.restore();
    try {
      await bridge?.close();
      report.databaseCleanup = bridge ? "completed" : "not-created";
    } catch {
      report.status = "failed";
      report.databaseCleanup = "failed";
    }
    write();
  }
  reports.verify(report);
  console.log(
    "Real Azure provider and signed agent/PostgreSQL campaign passed; production release remains unqualified",
  );
}
function scrub() {
  const root = lab.privateRoot();
  // privateRoot verifies an absolute, non-link child of the actual RUNNER_TEMP.
  fs.rmSync(root, { recursive: true, force: true });
}
module.exports = { prepare, run, scrub, context };
if (require.main === module)
  Promise.resolve()
    .then(() => {
      const action = { prepare, run, scrub }[process.argv[2]];
      if (!action) policy.fail("AZURE_KV_ACTION_DENIED");
      return action();
    })
    .catch((error) => {
      console.error(io.safeCode(error));
      process.exitCode = 1;
    });
