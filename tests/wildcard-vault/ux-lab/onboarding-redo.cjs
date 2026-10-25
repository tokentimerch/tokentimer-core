"use strict";
// Real owner browser, authenticated public API reads, and the lab's existing
// verified rollout. No route mocks, session API writes, DB access or result
// injection. Configuration acknowledgement is navigation through the runbook;
// this check does not install its draft or qualify a production DNS provider.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const SOURCE = "tests/wildcard-vault/ux-lab/onboarding-redo.cjs";
const VAULT_TITLE = "Share a certificate through Vault";
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

async function inspect({ state, owner, base, api, versions, matrix, customer, wait, check, root }) {
  const route = `/api/v1/workspaces/${state.workspaceId}/onboarding/mega`;
  const session = async () => (await owner.request(route)).session;
  const summary = async () => (await owner.request(route + "/summary")).summary;
  const distribution = (value) => value.certops?.distribution?.items?.find((g) => g.id === state.groupId);
  assert.equal((await session()).exists, false, "Owner onboarding must start fresh in this disposable lab");
  await wait("real verified distribution before owner onboarding", async () => distribution(await summary())?.verified === true);

  // Capture every public job ID, not just the default first page. The bounded
  // receipt records hashes/counts, never job payloads or credential material.
  async function inventory() {
    const jobs = [];
    let total;
    do {
      const page = await owner.request(api() + `/jobs?limit=100&offset=${jobs.length}`);
      assert.ok(Array.isArray(page.items));
      assert.ok(Number.isInteger(page.pagination?.total));
      total ??= page.pagination.total;
      assert.equal(page.pagination.total, total, "Job inventory changed while reading it");
      assert.ok(total < 1000, "Disposable onboarding check has an unexpectedly large job inventory");
      assert.ok(page.items.length || jobs.length === total, "Job pagination did not advance");
      jobs.push(...page.items.map((job) => job.id));
    } while (jobs.length < total);
    assert.equal(new Set(jobs).size, total);
    const groups = (await owner.request(api() + "/distribution-groups")).groups.map((g) => g.id).sort();
    const materialVersions = (await versions()).map((v) => ({ id: v.id, state: v.state, fingerprint: v.fingerprint_sha256 })).sort((a, b) => a.id.localeCompare(b.id));
    const consumers = (await matrix()).map((row) => ({
      bindingId: row.binding_id,
      bindingState: row.binding_state,
      deploymentProfileRef: row.deployment_profile_ref,
      desiredVersion: row.desired_material_version_id,
      observedVersion: row.observed_material_version_id,
      converged: row.converged,
      deploymentJobId: row.latest_deployment?.jobId || null,
    })).sort((a, b) => a.bindingId.localeCompare(b.bindingId));
    const active = consumers.filter((row) => row.bindingState === "active");
    assert.deepEqual(active.map((row) => row.bindingId), state.bindings.map((binding) => binding.id).sort(), "The exact enrolled lab consumers must remain active");
    assert.ok(active.every((row) => row.converged === true), "Real active consumers must remain converged");
    // The earlier membership replay test deliberately removes a third binding.
    // The public matrix retains that history; preserve it in the snapshot too.
    const historical = consumers.filter((row) => row.bindingState !== "active");
    assert.equal(historical.length, 1, "The removed membership-test binding must remain in history");
    assert.equal(historical[0].bindingState, "removed");
    assert.equal(historical[0].deploymentProfileRef, "extra-membership-check");
    assert.equal(historical[0].converged, false);
    return { jobs: jobs.sort(), groups, materialVersions, consumers, acmeOrders: (await customer("facts", "issuer")).orders.length };
  }
  const before = await inventory();
  const browser = await require("playwright").chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1100 } });
  try {
    await context.addCookies([...owner.jar].map(([name, value]) => ({ name, value, url: base, httpOnly: true, sameSite: "Lax" })));
    const page = await context.newPage();
    page.setDefaultTimeout(30000);
    const failures = [];
    page.on("pageerror", () => failures.push("dashboard runtime error"));
    // Any browser write to the product must be the guide's own session/reset.
    // Observe rather than intercept requests so the test cannot manufacture
    // success or hide an unintended publish/deployment operation.
    const unexpectedWrites = [];
    page.on("request", (request) => {
      const pathname = new URL(request.url()).pathname;
      if (["GET", "HEAD", "OPTIONS"].includes(request.method())) return;
      if ((pathname === route && request.method() === "PUT") || (pathname === route + "/reset" && request.method() === "POST")) return;
      unexpectedWrites.push({ method: request.method(), path: pathname });
    });
    const frame = (title) => page.getByRole("region", { name: title, exact: true });
    const vaultRow = () => page.getByRole("list", { name: "Setup steps" }).getByRole("listitem").filter({ hasText: VAULT_TITLE });
    const assertNotDone = async () => {
      await vaultRow().getByText("Now", { exact: true }).waitFor();
      assert.equal(await vaultRow().getByText("Done", { exact: true }).count(), 0);
    };
    const requestFor = (response, method, pathname) => response.request().method() === method && new URL(response.url()).pathname === pathname;
    async function checkChoice(input) {
      // Chakra renders a clipped native input inside a visible label. Click
      // that real label without force, then verify the semantic input state.
      if (!(await input.isChecked())) await input.locator("xpath=ancestor::label[1]").click();
      assert.equal(await input.isChecked(), true, "The visible choice must check its associated input");
    }

    async function reachVault() {
      const goal = frame("What do you want to do first?");
      await checkChoice(goal.getByRole("radio", { name: "Share one certificate across servers with Vault", exact: true }));
      await goal.getByRole("button", { name: "Continue", exact: true }).click();
      const objective = frame("Where will the certificates live?");
      await checkChoice(objective.getByRole("radio", { name: /^Linux server/ }));
      await checkChoice(objective.getByRole("checkbox", { name: "My agent is already set up", exact: true }));
      await objective.getByRole("combobox", { name: "Choose your agent", exact: true }).selectOption(state.agents.issuer.id);
      await objective.getByRole("button", { name: "Continue", exact: true }).click();
      const config = frame("Prepare the agent configuration");
      const names = state.certificateMode === "wildcard" ? "*.wildcard.test, wildcard.test" : state.certificateMode === "ordinary" ? "nginx.wildcard.test" : "nginx.wildcard.test, haproxy.wildcard.test";
      await config.getByLabel("Names (comma separated)", { exact: false }).fill(names);
      await config.getByLabel("DNS zone", { exact: false }).fill("wildcard.test");
      // This is an unexecuted runbook draft. The already enrolled issuer keeps
      // its real Pebble configuration and its existing Vault custody intact.
      await config.getByRole("button", { name: "I saved this file", exact: true }).click();
      await frame("Install the agent").getByRole("button", { name: "Continue", exact: true }).click();
      await frame(VAULT_TITLE).waitFor();
      await assertNotDone();
      const current = await session();
      assert.equal(current.exists, true);
      assert.equal(current.intent.goal, "certops_vault");
      assert.equal(current.progress.certops.chosenAgentConfirmed, state.agents.issuer.id);
      assert.ok(!current.progress.certops.chosenDistributionId);
      assert.ok(!current.progress.certops.chosenDistributionConfirmed);
      const group = distribution(await summary());
      assert.equal(group?.verified, true, "Completion must be backed by a real verified rollout");
      assert.equal(group.existedBeforeSession, true, "Pre-existing verified work must be session-scoped");
      assert.ok(Date.parse(group.createdAt) < Date.parse(current.createdAt));
      assert.ok(Date.parse(group.lastVerifiedAt) < Date.parse(current.createdAt));
      assert.equal(await frame(VAULT_TITLE).getByRole("checkbox", { name: "My Vault distribution is already set up", exact: true }).isChecked(), false);
      await frame(VAULT_TITLE).getByTestId("existing-distributions-note").waitFor();
      return current;
    }

    async function chooseAndConfirm() {
      const vault = frame(VAULT_TITLE);
      await checkChoice(vault.getByRole("checkbox", { name: "My Vault distribution is already set up", exact: true }));
      const saved = page.waitForResponse((response) => requestFor(response, "PUT", route));
      await vault.getByRole("combobox", { name: "Choose your distribution", exact: true }).selectOption(state.groupId);
      assert.equal((await saved).status(), 200);
      await wait("owner distribution choice saved before confirmation", async () => (await session()).progress.certops?.chosenDistributionId === state.groupId, 30000);
      assert.ok(!(await session()).progress.certops.chosenDistributionConfirmed);
      await assertNotDone();
      await vault.getByText("Distribution verified", { exact: true }).waitFor();
      const confirmed = page.waitForResponse((response) => requestFor(response, "PUT", route));
      await vault.getByTestId("vault-use-distribution").click();
      assert.equal((await confirmed).status(), 200);
      await vaultRow().getByText("Done", { exact: true }).waitFor();
      const current = await session();
      assert.equal(current.progress.certops.chosenDistributionId, state.groupId);
      assert.equal(current.progress.certops.chosenDistributionConfirmed, state.groupId);
      return current;
    }

    await page.goto(base + "/onboarding?area=certops&workspace=" + state.workspaceId);
    const first = await reachVault();
    await chooseAndConfirm();
    await page.goto(base + "/preferences?workspace=" + state.workspaceId);
    const reset = page.waitForResponse((response) => requestFor(response, "POST", route + "/reset"));
    await page.getByRole("button", { name: "Start over", exact: true }).click();
    const resetResponse = await reset;
    assert.equal(resetResponse.status(), 200);
    assert.equal((await resetResponse.json()).reset, true);
    await page.waitForURL((url) => url.pathname === "/onboarding");
    const cleared = await session();
    assert.equal(cleared.exists, false);
    assert.equal(cleared.revision, 0);
    assert.deepEqual(cleared.progress, {});
    assert.deepEqual(cleared.operationRefs, {});

    const restarted = await reachVault();
    assert.ok(Date.parse(restarted.createdAt) > Date.parse(first.createdAt));
    // Persisted reload must not silently reuse the old verified group either.
    await page.reload();
    await frame(VAULT_TITLE).waitFor();
    await assertNotDone();
    assert.equal(await frame(VAULT_TITLE).getByRole("checkbox", { name: "My Vault distribution is already set up", exact: true }).isChecked(), false);
    const completed = await chooseAndConfirm();
    await page.reload();
    await vaultRow().getByText("Done", { exact: true }).waitFor();
    await vaultRow().getByRole("button", { name: VAULT_TITLE + ", review", exact: true }).click();
    await frame(VAULT_TITLE).getByText("Distribution verified", { exact: true }).waitFor();
    assert.equal(await frame(VAULT_TITLE).getByRole("combobox", { name: "Choose your distribution", exact: true }).inputValue(), state.groupId);
    assert.deepEqual(await inventory(), before, "Starting over and explicitly reusing must preserve the real group, material, consumers, jobs and ACME orders");
    assert.deepEqual(failures, []);
    assert.deepEqual(unexpectedWrites, [], "Only onboarding session/reset writes are expected");

    const screenshot = "distribution-onboarding-redo.png";
    await frame(VAULT_TITLE).scrollIntoViewIfNeeded();
    await page.screenshot({ path: path.join(root, screenshot) });
    const receipt = {
      schemaVersion: 1,
      scenario: "owner-vault-start-over-explicit-reuse",
      passed: true,
      coreCommit: state.coreCommit,
      runId: state.runId,
      certificateMode: state.certificateMode,
      fixtureSource: { file: SOURCE, sha256: sha256(fs.readFileSync(__filename)) },
      workspaceId: state.workspaceId,
      distributionGroupId: state.groupId,
      firstSessionCreatedAt: first.createdAt,
      restartedSessionCreatedAt: restarted.createdAt,
      finalSessionRevision: completed.revision,
      verifiedBeforeStartOver: true,
      ownerStartOverResetSession: true,
      existingDistributionStillVerified: true,
      oldDistributionDidNotCompleteNewSession: true,
      reloadBeforeChoiceRemainedIncomplete: true,
      choiceWithoutContinueRemainedIncomplete: true,
      explicitReuseCompletedStep: true,
      completedChoiceSurvivedReload: true,
      inventoryUnchanged: true,
      inventorySha256: sha256(JSON.stringify(before)),
      counts: { jobs: before.jobs.length, groups: before.groups.length, materialVersions: before.materialVersions.length, consumers: before.consumers.length, acmeOrders: before.acmeOrders },
      browserRuntimeErrors: failures.length,
      unexpectedProductWrites: unexpectedWrites.length,
      databaseInjection: false,
      responseInterception: false,
      configurationRunbookOnly: true,
      installationQualified: false,
      publishedReleaseQualified: false,
      scope: "Disposable Core lab, existing verified distribution and already enrolled issuer; runbook acknowledgement only, no production provider configuration or installation qualification.",
      screenshot: { file: screenshot, sha256: sha256(fs.readFileSync(path.join(root, screenshot))) },
      finishedAt: new Date().toISOString(),
    };
    const receiptFile = path.join(root, "onboarding-redo.json");
    fs.writeFileSync(receiptFile, JSON.stringify(receipt, null, 2) + "\n");
    check("owner Start over clears Vault onboarding completion; existing verified distribution requires explicit reuse and Continue", { evidence: "onboarding-redo.json" });
    return { file: "onboarding-redo.json", sha256: sha256(fs.readFileSync(receiptFile)) };
  } finally {
    await context.close();
    await browser.close();
  }
}

module.exports = { inspect };
