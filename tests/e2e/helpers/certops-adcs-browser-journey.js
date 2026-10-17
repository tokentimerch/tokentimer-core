"use strict";
/** Supported AD CS browser lifecycle on the owned SYSTEM domain member.
 * The UI creates/checks/pins an issuer and attaches a renewal profile to an
 * existing native certificate. The actual default scheduler sweep then creates
 * a real enrollment; native CA, CNG, IIS and trusted TLS independently prove it.
 * No UI route interception, fabricated safe verdict, first-issue UI or generic
 * manual AD CS renewal is claimed. Invoked last in comprehensive lab lanes. */
const { verifyNativeRequestId } = require("./certops-adcs-live-enroll-acl");
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const REQUIRED_SCENARIOS = Object.freeze([
  "adcs-real-browser-issuer-native-preflight",
  "adcs-real-browser-confirmed-ca-pin",
  "adcs-real-browser-profile-attachment",
  "adcs-real-browser-automation-native-enrollment",
  "adcs-real-browser-installed-enrollment-visible",
  "adcs-real-browser-owned-cleanup",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-adcs-browser-enrollment.js",
  "tests/e2e/helpers/certops-native-issuer-reassignment.js",
  "tests/e2e/certops-adcs-real-e2e.test.js",
  "infra/certops-adcs/read-report.ps1",
  ".github/workflows/certops-enterprise-adcs-qualification.yml",
  "tests/e2e/helpers/certops-adcs-live-enroll-acl.js",
  "packages/agent/src/issuers/adcs.js",
  ".dockerignore",
  "tests/e2e/helpers/certops-adcs-browser-journey.js",
  "infra/certops-adcs/browser-control-plane.sh",
  "infra/certops-adcs/browser-windows-tools.ps1",
  "infra/certops-adcs/browser-api-trust.ps1",
  "apps/dashboard/src/components/certops/AdcsIssuerWizard.jsx",
  "apps/dashboard/src/components/certops/AdcsProfileWizard.jsx",
  "apps/dashboard/src/pages/certops/CertOpsAdcs.jsx",
  "apps/dashboard/src/pages/certops/CertOpsRenewals.jsx",
  "apps/dashboard/src/components/certops/certopsEnrollmentsApi.js",
  "apps/dashboard/src/components/certops/certopsRenewalApi.js",
  "apps/dashboard/src/components/certops/certopsApi.js",
  "apps/api/services/certops/renewalScheduler.js",
  "apps/api/services/certops/adcsPreflightGate.js",
  "apps/api/services/certops/certificateEnrollments.js",
  "package.json",
  "pnpm-lock.yaml",
  "deploy/compose/Dockerfile.dashboard",
  "deploy/compose/docker-entrypoint-dashboard.sh",
  "deploy/compose/nginx.conf",
  "infra/certops-adcs/provision-lab.ps1",
  "infra/certops-adcs/run-windows-tests.ps1",
  "infra/certops-adcs/owned-issued-request.ps1",
  "packages/agent/src/adcs-windows-iis.js",
]);
const FLAGS = Object.freeze([
  "browserIssuerCreation",
  "nativeSafePreflight",
  "noEnrollmentBeforeConfirmation",
  "browserCaConfirmation",
  "postConfirmationNativePreflight",
  "browserProfileCreation",
  "browserProfileAttachment",
  "actualDueSelection",
  "defaultSweepCreatedEnrollment",
  "automaticSourceAndRealMode",
  "claimBoundEvidence",
  "installedEnrollment",
  "freshLeafAndSpki",
  "nativeCaRequestMatched",
  "nonexportableMachineCng",
  "nativeIisSniMatched",
  "independentTrustedTls",
  "browserInstalledStateVisible",
  "noSyntheticResponses",
  "noDateOrJournalOverrides",
  "ownedEnrollmentRegistered",
  "browserAndTrustCleaned",
  "otherProfilePoliciesRestored",
]);
const SCOPE = "browser-issuer-profile-default-scheduler-native-adcs";
function verifyProof(proof) {
  assert.ok(proof && typeof proof === "object" && !Array.isArray(proof));
  assert.deepEqual(
    Object.keys(proof).sort(),
    [
      ...FLAGS,
      "scope",
      "lifecycle",
      "scheduler",
      "browserEngine",
      "browserMutationCount",
      "successfulEnrollments",
      "fingerprints",
      "spkiFingerprints",
      "requestId",
      "enrollmentId",
      "jobId",
      "profileId",
      "issuerId",
    ].sort(),
  );
  assert.equal(proof.scope, SCOPE);
  assert.equal(
    proof.lifecycle,
    "renew-existing-inventory-not-first-issue-or-manual-job",
  );
  assert.equal(
    proof.scheduler,
    "production-default-sweep-not-background-worker-loop",
  );
  assert.equal(proof.browserEngine, "chromium");
  assert.equal(proof.browserMutationCount, 6);
  assert.equal(proof.successfulEnrollments, 1);
  for (const flag of FLAGS) assert.equal(proof[flag], true, flag);
  for (const field of ["fingerprints", "spkiFingerprints"]) {
    assert.ok(Array.isArray(proof[field]) && proof[field].length === 2);
    assert.equal(new Set(proof[field]).size, 2);
    for (const item of proof[field]) assert.match(item, /^[a-f0-9]{64}$/);
  }
  for (const field of ["enrollmentId", "jobId", "profileId", "issuerId"])
    assert.match(
      proof[field],
      /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i,
    );
  assert.match(proof.requestId, /^[1-9][0-9]{0,9}$/);
  assert.ok(Number(proof.requestId) <= 0xffffffff);
  return true;
}
function currentAuthorityGroup(certificates, expectedKey) {
  assert.match(expectedKey,/^[a-f0-9]{64}$/i);
  const group=certificates.filter(value=>value.keySha256===expectedKey).sort((a,b)=>(Date.parse(b.notBefore)||0)-(Date.parse(a.notBefore)||0));
  assert.ok(group.length,"Native preflight must contain the independently current CA key");
  const certificate=group.find(value=>value.thumbprintSha1);
  assert.ok(certificate,"Current native CA group needs its visible public certificate fingerprint");
  assert.match(certificate.thumbprintSha1,/^[a-f0-9]{40}$/i);
  const der=Buffer.from(certificate.certificateB64,"base64");
  assert.equal(crypto.createHash("sha1").update(der).digest("hex"),certificate.thumbprintSha1.toLowerCase());
  return certificate;
}
function createOwnedBrowserResource({ getServer, receipt, removeTrust }) {
  let released = false;
  const resource = {
    hasLiveChild() {
      if (released) return false;
      const server = getServer();
      if (!server) return false;
      const child = server.process();
      return (
        !child?.pid || (child.exitCode === null && child.signalCode === null)
      );
    },
    hasOwnershipReceipt: () => !released && fs.existsSync(receipt),
    async close() {
      if (released) return;
      const server = getServer();
      if (resource.hasLiveChild()) {
        try {
          await server.close();
        } catch {
          try {
            await server.kill();
          } catch {
            throw new Error(
              "Owned Chromium could not be terminated; preserve browser trust receipt and state",
            );
          }
        }
      }
      assert.equal(
        resource.hasLiveChild(),
        false,
        "Cannot remove browser trust while Chromium remains alive",
      );
      if (resource.hasOwnershipReceipt()) removeTrust();
      assert.equal(
        resource.hasOwnershipReceipt(),
        false,
        "Owned browser trust receipt remains; preserve state",
      );
      released = true;
    },
  };
  return resource;
}
const normalized = (value) => String(value).replace(/:/g, "").toLowerCase();
function describe(cert) {
  return {
    certificate: cert,
    fingerprint: normalized(cert.fingerprint256),
    spki: crypto
      .createHash("sha256")
      .update(cert.publicKey.export({ type: "spki", format: "der" }))
      .digest("hex"),
    thumb: normalized(cert.fingerprint).toUpperCase(),
  };
}
async function qualifyAdcsBrowserJourney(context) {
  const {
    gate,
    fixture,
    api,
    agentRowId,
    configDir,
    workDir,
    run,
    renewalFixture,
    until,
    jobFinished,
    ps,
    command,
    tlsAuthority,
    ownedEnrollmentIds,
    ownedThumbprints,
    ownedBrowserResources,
    ownedBrowserPreflightJobIds,
    ownedTlsProbes,
  } = context;
  assert.ok(Array.isArray(ownedTlsProbes), "Parent must retain native browser TLS ownership");
  const probes=require("./certops-native-issuer-reassignment").createOwnedTlsProbes();
  ownedTlsProbes.push(probes);
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  assert.equal(process.env.CERTOPS_ADCS_BROWSER, "1");
  assert.notEqual(process.env.CERTOPS_ADCS_PENDING_ELAPSED, "1");
  const root = path.resolve(__dirname, "../../.."),
    origin = "https://10.64.0.6",
    { item, site, port } = renewalFixture;
  assert.equal(item.id, "rsa2048");
  assert.match(
    item.domain,
    /^certops-adcs-[a-f0-9]{10}-rsa2048\.example\.test$/,
  );
  assert.match(site, /^TTADCS-[a-f0-9]{10}-rsa2048$/);
  assert.ok(Number.isInteger(port) && port > 0 && port <= 65535);
  assert.equal(
    ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),
    "S-1-5-18",
  );
  const runtime = JSON.parse(
    fs.readFileSync("C:\\ttqualification\\browser-runtime.json", "utf8"),
  );
  assert.equal(runtime.candidateSha, process.env.GITHUB_SHA);
  assert.equal(
    runtime.playwrightVersion,
    require(path.join(root, "package.json")).devDependencies.playwright,
  );
  assert.equal(
    runtime.bootstrapSourceSha256,
    crypto
      .createHash("sha256")
      .update(
        fs.readFileSync(
          path.join(root, "infra/certops-adcs/browser-windows-tools.ps1"),
        ),
      )
      .digest("hex"),
  );
  assert.equal(runtime.browserCache, "C:\\ttqualification\\browser-cache");
  process.env.PLAYWRIGHT_BROWSERS_PATH = runtime.browserCache;
  assert.equal(require("playwright/package.json").version,require(path.join(root,"package.json")).devDependencies.playwright,"Resolved browser library must match the exact locked manifest pin");
  const { chromium } = require("playwright"),
    trustScript = path.join(root, "infra/certops-adcs/browser-api-trust.ps1"),
    trustReceipt = path.join(workDir, "browser-api-trust.json");
  gate.report.fixtureSources ??= [];
  for (const file of REQUIRED_SOURCES) {
    const sha256 = crypto
      .createHash("sha256")
      .update(fs.readFileSync(path.join(root, file)))
      .digest("hex");
    const prior = gate.report.fixtureSources.find(
      (source) => source.file === file,
    );
    if (prior) assert.equal(prior.sha256, sha256);
    else gate.report.fixtureSources.push({ file, sha256 });
  }
  assert.ok(Array.isArray(ownedBrowserResources));
  assert.ok(Array.isArray(ownedBrowserPreflightJobIds));
  let browser,
    browserServer,
    page,
    primary,
    issuerId,
    profileId,
    preflight,
    authority,
    initial,
    final,
    selectedSource,
    enrollment,
    job,
    requestId,
    mutations = 0,
    stage = "browser-prerequisites";
  const resource = createOwnedBrowserResource({
    getServer: () => browserServer,
    receipt: trustReceipt,
    removeTrust: () =>
      command("powershell.exe", [
        "-NoProfile",
        "-NonInteractive",
        "-File",
        trustScript,
        "-Mode",
        "Remove",
        "-Receipt",
        trustReceipt,
      ]),
  });
  ownedBrowserResources.push(resource);
  const policies = [],
    facts = {
      scope: SCOPE,
      lifecycle: "renew-existing-inventory-not-first-issue-or-manual-job",
      scheduler: "production-default-sweep-not-background-worker-loop",
      browserEngine: "chromium",
      browserMutationCount: 6,
      successfulEnrollments: 1,
    };
  const query = (sql, args = []) => fixture.pool.query(sql, args);
  async function issuer() {
    const response = await fixture.request(
      `${api}/issuers?includeUnconfigured=true&limit=100`,
    );
    assert.equal(response.status, 200);
    return response.body.items.find((value) => value.id === issuerId);
  }
  async function openDisclosure(id) {
    const control = page.locator(`button[aria-controls="${id}"]`);
    await control.waitFor();
    if ((await control.getAttribute("aria-expanded")) !== "true")
      await control.click();
  }
  async function mutation(button, pathname, expectedStatus) {
    const [response] = await Promise.all([
      page.waitForResponse(
        (response) =>
          response.request().method() === "POST" &&
          new URL(response.url()).pathname === pathname,
      ),
      button.click(),
    ]);
    assert.equal(response.status(), expectedStatus);
    mutations++;
    return response;
  }
  const peer = () => probes.observe({host:"127.0.0.1",port,servername:item.domain,ca:preflight.caCertificates.flatMap(value=>[tlsAuthority(value)].flat()),rejectUnauthorized:true}, socket => {
    assert.equal(socket.authorized,true);
    const cert=new crypto.X509Certificate(socket.getPeerCertificate().raw);
    assert.equal(cert.checkHost(item.domain),item.domain);
    return describe(cert);
  });
  try {
    // Isolate one actual default sweep using public profile policy operations;
    // the main fixture has no continuously running scheduler worker. Restore
    // every changed policy even on browser/native failure.
    const profiles = await fixture.request(`${api}/profiles?limit=100`);
    assert.equal(profiles.status, 200);
    assert.ok(
      (profiles.body.pagination?.total ??
        profiles.body.total ??
        profiles.body.items.length) <= 100,
    );
    for (const value of profiles.body.items)
      if (value.autoRenewEnabled) {
        policies.push(value.id);
        const changed = await fixture.request(
          `${api}/profiles/${value.id}`,
          "PATCH",
          { autoRenewEnabled: false },
        );
        assert.equal(changed.status, 200);
      }
    command("powershell.exe", [
      "-NoProfile",
      "-NonInteractive",
      "-File",
      trustScript,
      "-Mode",
      "Add",
      "-Receipt",
      trustReceipt,
    ]);
    browserServer = await chromium.launchServer({
      headless: true,
      host: "127.0.0.1",
    });
    browser = await chromium.connect(browserServer.wsEndpoint(), {
      timeout: 30000,
    });
    const browserContext = await browser.newContext({
      ignoreHTTPSErrors: false,
    });
    page = await browserContext.newPage();
    page.setDefaultTimeout(90000);
    stage = "browser-login";
    await page.goto(origin + "/login");
    await page.getByLabel("Email", { exact: true }).fill(fixture.email);
    await page.getByLabel("Password", { exact: true }).fill(fixture.password);
    await page.getByRole("button", { name: "Sign In", exact: true }).click();
    await page.waitForURL((url) => !url.pathname.includes("login"));
    const renewals = new URL("/certops/renewals", origin);
    renewals.searchParams.set("workspace", fixture.workspaceId);
    await page.goto(renewals.href);
    await gate.scenario(
      REQUIRED_SCENARIOS[0],
      async () => {
        stage = "issuer-native-preflight";
        await openDisclosure("certops-adcs-section");
        await page
          .getByRole("button", { name: "New issuer", exact: true })
          .click();
        const dialog = page.getByRole("dialog");
        await dialog
          .getByLabel("Issuer name", { exact: true })
          .fill(`Browser native issuer ${run}`);
        await dialog
          .getByRole("button", { name: "Continue", exact: true })
          .click();
        await dialog
          .getByLabel("Preflight agent", { exact: true })
          .selectOption(agentRowId);
        await dialog
          .getByLabel("CA config", { exact: true })
          .fill("tt-ca.lab.certops.test\\TTQualificationRoot");
        await dialog
          .getByLabel("Template", { exact: true })
          .fill("TTQualificationRSAShort");
        const createdResponse = page.waitForResponse(
          (response) =>
            response.request().method() === "POST" &&
            new URL(response.url()).pathname === `${api}/issuers`,
        );
        const dispatchedResponse = page.waitForResponse(
          (response) =>
            response.request().method() === "POST" &&
            new URL(response.url()).pathname.endsWith("/preflight"),
        );
        const [created, dispatched] = await Promise.all([
          createdResponse,
          dispatchedResponse,
          dialog
            .getByRole("button", { name: "Run check", exact: true })
            .click(),
        ]);
        assert.equal(created.status(), 201);
        issuerId = (await created.json()).issuer.id;
        mutations++;
        assert.equal(dispatched.status(), 201);
        assert.equal(
          new URL(dispatched.url()).pathname,
          `${api}/issuers/${issuerId}/preflight`,
        );
        const dispatch = await dispatched.json();
        ownedBrowserPreflightJobIds.push(dispatch.job.id);
        mutations++;
        await jobFinished(dispatch.job.id);
        await dialog
          .getByRole("button", { name: "Use this certificate", exact: true })
          .first()
          .waitFor();
        preflight = (await issuer()).lastPreflight;
        assert.equal(preflight.templateCheck.verdict, "safe");
        assert.equal(preflight.caCheck.verdict, "safe");
        assert.equal(preflight.template, "TTQualificationRSAShort");
        assert.ok(preflight.templateCheck.templateOid);
        assert.equal((await issuer()).currentVersion, 0);
        assert.equal((await query("SELECT count(*)::int AS count FROM certificate_enrollments WHERE workspace_id=$1 AND issuer_id=$2",[fixture.workspaceId,issuerId])).rows[0].count,0,"The browser must confirm its new issuer before any enrollment");
        facts.noEnrollmentBeforeConfirmation=true;
        const nativeJob = (
          await query(
            "SELECT status,assigned_agent_id,claim_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
            [fixture.workspaceId, dispatch.job.id],
          )
        ).rows[0];
        assert.equal(nativeJob.status, "succeeded");
        assert.equal(nativeJob.assigned_agent_id, agentRowId);
        assert.ok(nativeJob.claim_id);
        initial = await peer();
        facts.browserIssuerCreation = facts.nativeSafePreflight = true;
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "Real browser creates and dispatches issuer preflight; the installed SYSTEM agent reads the real CA/template and reports a fresh safe verdict, without mocked responses",
      },
    );
    await gate.scenario(
      REQUIRED_SCENARIOS[1],
      async () => {
        stage = "browser-ca-confirmation";
        const expectedAuthority=currentAuthorityGroup(preflight.caCertificates,renewalFixture.authority.keySha256);
        // Each UI HStack contains one visible SHA1 label and its own confirmation
        // button. Select that known current key group, regardless of date/order.
        const currentRow=page.getByRole("dialog").getByText(new RegExp(`^${expectedAuthority.thumbprintSha1}(?: ·|$)`)).locator("xpath=../..");
        const response = await mutation(
          currentRow.getByRole("button", { name: "Use this certificate", exact: true }),
          `${api}/issuers/${issuerId}/confirm`,
          200,
        );
        const body = response.request().postDataJSON();
        assert.equal(body.caKeySha256,renewalFixture.authority.keySha256,"Browser must confirm the independently current CA key");
        authority = preflight.caCertificates.find(
          (value) => value.keySha256 === body.caKeySha256,
        );
        assert.ok(authority);
        assert.equal(body.caConfig, preflight.caConfig);
        assert.equal(body.template, preflight.template);
        const saved = await issuer();
        assert.equal(saved.currentVersion, 1);
        assert.equal(saved.revalidationRequired, false);
        assert.equal(saved.confirmedKeySha256, authority.keySha256);
        await page
          .getByRole("dialog")
          .getByRole("button", { name: "Done", exact: true })
          .click();
        facts.browserCaConfirmation = true;
        // Production eligibility requires a successful native check created at
        // or after confirmation. Use the existing Check again UI; never backdate
        // evidence or weaken the scheduler's freshness gate.
        const issuerName = `Browser native issuer ${run}`;
        await page
          .getByRole("button", { name: `Expand ${issuerName}`, exact: true })
          .click();
        const card = page
          .getByRole("button", { name: `Collapse ${issuerName}`, exact: true })
          .locator("xpath=..");
        await card
          .getByRole("button", { name: "Check again", exact: true })
          .click();
        await card
          .getByLabel(`Agent for ${issuerName}`, { exact: true })
          .selectOption(agentRowId);
        const checked = await mutation(
          card.getByRole("button", {
            name: `Run check for ${issuerName}`,
            exact: true,
          }),
          `${api}/issuers/${issuerId}/preflight`,
          201,
        );
        const checkedJob = (await checked.json()).job.id;
        ownedBrowserPreflightJobIds.push(checkedJob);
        await jobFinished(checkedJob);
        const eligibility = require("../../../apps/api/services/certops/adcsPreflightGate");
        const version = await eligibility.loadCurrentAdcsIssuerVersion({
          db: fixture.pool,
          workspaceId: fixture.workspaceId,
          issuerId,
        });
        const eligible = await eligibility.loadQualifyingAdcsAgents({
          db: fixture.pool,
          workspaceId: fixture.workspaceId,
          issuerId,
          version,
          reference: item.domain,
        });
        assert.ok(eligible.some((value) => value.id === agentRowId));
        facts.postConfirmationNativePreflight = true;
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "Actual browser confirmation pins only a public key returned by the genuine native preflight, with matching CA/template and independently persisted issuer version",
      },
    );
    await gate.scenario(
      REQUIRED_SCENARIOS[2],
      async () => {
        stage = "browser-profile-attachment";
        selectedSource = await until(
          async () =>
            (
              await query(
                "SELECT mc.id FROM managed_certificates mc JOIN certificate_instances ci ON ci.workspace_id=mc.workspace_id AND ci.managed_certificate_id=mc.id JOIN certificate_targets ct ON ct.workspace_id=ci.workspace_id AND ct.id=ci.target_id WHERE mc.workspace_id=$1 AND mc.source='agent_windows' AND ci.observed_fingerprint_sha256=$2 AND ct.windows_site=$3 ORDER BY ci.observed_at DESC LIMIT 1",
                [fixture.workspaceId, initial.fingerprint, site],
              )
            ).rows[0],
        );
        await openDisclosure("certops-renewal-profiles");
        await page
          .getByRole("button", { name: "New AD CS profile", exact: true })
          .click();
        const dialog = page.getByRole("dialog");
        await dialog
          .getByLabel("Profile name", { exact: true })
          .fill(`Browser native profile ${run}`);
        await dialog
          .getByLabel("AD CS issuer", { exact: true })
          .selectOption(issuerId);
        await dialog
          .getByRole("button", { name: "Continue", exact: true })
          .click();
        for (const [label, value] of [
          ["Certificate name", item.domain],
          ["IIS site", site],
          ["IIS port", String(port)],
          ["SNI hostname", item.domain],
          ["Certificate store", "My"],
          ["Lead time", "30"],
        ])
          await dialog.getByLabel(label, { exact: true }).fill(value);
        await dialog
          .getByLabel("Key algorithm", { exact: true })
          .selectOption("rsa");
        await dialog
          .getByLabel("Key size", { exact: true })
          .selectOption("2048");
        await dialog
          .getByRole("button", { name: "Review", exact: true })
          .click();
        const created = await mutation(
          dialog.getByRole("button", { name: "Create profile", exact: true }),
          `${api}/profiles`,
          201,
        );
        profileId = (await created.json()).id;
        const attachButton = dialog.getByRole("button", {
          name: "Attach and enable automation",
          exact: true,
        });
        await attachButton.waitFor();
        const picker = dialog.getByLabel("Certificate to attach", {
          exact: true,
        });
        if (await picker.count()) await picker.selectOption(selectedSource.id);
        await mutation(
          attachButton,
          `${api}/sources/${selectedSource.id}/replace-management`,
          201,
        );
        const periods = (
          await query(
            "SELECT id,automation_enabled,renewal_profile_id FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL",
            [fixture.workspaceId, selectedSource.id],
          )
        ).rows;
        assert.equal(periods.length, 1);
        assert.equal(periods[0].automation_enabled, true);
        assert.equal(periods[0].renewal_profile_id, profileId);
        await dialog.getByRole("button", { name: "Done", exact: true }).click();
        facts.browserProfileCreation = facts.browserProfileAttachment = true;
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "Real browser authors a confirmed-issuer IIS profile and replaces the exact existing native source's management period with automation enabled; no first-issue UI is invented",
      },
    );
    await gate.scenario(
      REQUIRED_SCENARIOS[3],
      async () => {
        stage = "default-sweep-native-enrollment";
        const scheduler = require("../../../apps/api/services/certops/renewalScheduler");
        const due = await scheduler.findCertificatesDueForRenewal({
          db: fixture.pool,
          thresholdDays: scheduler.DEFAULT_RENEWAL_THRESHOLD_DAYS,
          terminalStatuses: scheduler.RENEWAL_JOB_TERMINAL_STATUSES,
        });
        assert.ok(
          due.some(
            (value) =>
              value.workspace_id === fixture.workspaceId &&
              value.id === selectedSource.id,
          ),
        );
        const expiry = (
          await query(
            "SELECT not_after FROM managed_certificates WHERE workspace_id=$1 AND id=$2",
            [fixture.workspaceId, selectedSource.id],
          )
        ).rows[0].not_after;
        const key = scheduler.renewalIdempotencyKey(selectedSource.id, expiry);
        assert.equal(
          (
            await query(
              "SELECT count(*)::int AS n FROM certificate_jobs WHERE workspace_id=$1 AND idempotency_key=$2",
              [fixture.workspaceId, key],
            )
          ).rows[0].n,
          0,
        );
        const sweep = await scheduler.runRenewalSchedulerSweep({
          dbPool: fixture.pool,
          env: process.env,
        });
        assert.equal(sweep.lockAcquired, true);
        assert.equal(sweep.created, 1);
        assert.deepEqual(sweep.errors, []);
        job = await until(
          async () =>
            (
              await query(
                "SELECT id,status,claim_id,source,mode FROM certificate_jobs WHERE workspace_id=$1 AND idempotency_key=$2",
                [fixture.workspaceId, key],
              )
            ).rows[0],
        );
        enrollment = (
          await query(
            "SELECT id FROM certificate_enrollments WHERE workspace_id=$1 AND current_job_id=$2",
            [fixture.workspaceId, job.id],
          )
        ).rows[0];
        assert.ok(enrollment);
        ownedEnrollmentIds.push(enrollment.id);
        await jobFinished(job.id);
        const persisted = (
          await query(
            "SELECT state,request_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",
            [fixture.workspaceId, enrollment.id],
          )
        ).rows[0];
        assert.equal(persisted.state, "installed");
        assert.equal(job.source, "automation");
        assert.equal(job.mode, "real");
        final = await peer();
        ownedThumbprints.add(final.thumb);
        assert.notEqual(final.fingerprint, initial.fingerprint);
        assert.notEqual(final.spki, initial.spki);
        const native = JSON.parse(
          command("powershell.exe", [
            "-NoProfile",
            "-NonInteractive",
            "-File",
            path.join(root, "infra/certops-adcs/owned-issued-request.ps1"),
            "-CommonName",
            item.domain,
            "-FingerprintSha256",
            final.fingerprint,
          ]),
        );
        requestId = String(native.requestId);
        assert.equal(native.disposition, 20);
        assert.equal(normalized(native.fingerprintSha256), final.fingerprint);
        if (persisted.request_id != null)
          assert.equal(String(persisted.request_id), requestId);
        const container =
          require("../../../packages/agent/src/windows-cert-store").buildEnrollmentContainerName(
            enrollment.id,
          );
        const receipt =
          require("../../../packages/agent/src/windows-cert-store").readIssuedContainerRecord(
            { stateDir: configDir, containerName: container },
          );
        assert.equal(receipt.status, "enrolled_by_agent");
        assert.equal(receipt.jobId, job.id);
        assert.equal(receipt.certificateId, selectedSource.id);
        assert.equal(receipt.acceptedThumbprint, final.thumb);
        assert.equal(receipt.acceptedStore, "My");
        const journal =
          require("../../../packages/agent/src/issuers/adcs-enrollment").readEnrollmentJournal(
            configDir,
            enrollment.id,
          );
        assert.equal(journal.kind, "valid");
        assert.equal(journal.journal.state, "installed");
        assert.equal(journal.journal.csrSpkiSha256, final.spki);
        verifyNativeRequestId(native.requestId, journal.journal.requestId, persisted.request_id);
        assert.equal(
          ps(
            `$c=Get-Item 'Cert:\\LocalMachine\\My\\${final.thumb}';$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);try{if($k.Key.KeyName -ne '${container}' -or -not $k.Key.IsMachineKey -or $k.Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None -or $k.KeySize -ne 2048){throw 'Browser renewal custody mismatch'};'protected-rsa2048'}finally{$k.Dispose();$c.Dispose()}`,
          ),
          "protected-rsa2048",
        );
        const binding = JSON.parse(
          ps(
            `Import-Module WebAdministration;$b=@(Get-WebBinding -Name '${site}' -Protocol https|Where-Object bindingInformation -eq '*:${port}:${item.domain}');$keys=@(Get-ChildItem -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslSniBindingInfo'|Where-Object {[string]$_.GetValue('HostnamePort') -ieq '${item.domain}:${port}'});if($b.Count -ne 1 -or $keys.Count -ne 1){throw 'Owned browser binding missing'};@{hash=[BitConverter]::ToString([byte[]]$keys[0].GetValue('SslCertHash')).Replace('-','');flags=[int]$b[0].sslFlags}|ConvertTo-Json -Compress`,
          ),
        );
        assert.equal(binding.hash, final.thumb);
        assert.equal(binding.flags, 1);
        const current = (
          await query(
            "SELECT claim_id,status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
            [fixture.workspaceId, job.id],
          )
        ).rows[0];
        assert.equal(current.status, "succeeded");
        assert.ok(current.claim_id);
        const evidence = (
          await query(
            "SELECT metadata FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2 AND claim_id=$3 AND evidence_type='validation.passed' AND metadata->>'step'='verify'",
            [fixture.workspaceId, job.id, current.claim_id],
          )
        ).rows;
        assert.ok(
          evidence.some(
            (value) =>
              normalized(value.metadata.fingerprintSha256) ===
              final.fingerprint,
          ),
        );
        Object.assign(facts, {
          actualDueSelection: true,
          defaultSweepCreatedEnrollment: true,
          automaticSourceAndRealMode: true,
          claimBoundEvidence: true,
          installedEnrollment: true,
          freshLeafAndSpki: true,
          nativeCaRequestMatched: true,
          nonexportableMachineCng: true,
          nativeIisSniMatched: true,
          independentTrustedTls: true,
          ownedEnrollmentRegistered: true,
        });
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "One unmodified default SQL-NOW scheduler sweep admits the real UI-enabled native source, followed by independent CA request, protected CNG key, exact IIS SNI, trusted TLS and claim-bound evidence; not a continuously running worker loop",
      },
    );
    await gate.scenario(
      REQUIRED_SCENARIOS[4],
      async () => {
        stage = "browser-installed-visibility";
        await page.reload();
        await openDisclosure("certops-adcs-section");
        await page.getByRole("checkbox", { name: /^Show finished/ }).check();
        const marker = page.getByText(enrollment.id.slice(0, 8), {
          exact: true,
        });
        await marker.waitFor();
        const card = marker.locator("xpath=..");
        assert.ok((await card.innerText()).includes("Installed"));
        const list = await fixture.request(`${api}/enrollments?limit=100`);
        assert.equal(list.status, 200);
        assert.equal(
          list.body.items.find((value) => value.id === enrollment.id).state,
          "installed",
        );
        facts.browserInstalledStateVisible = true;
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "Reloaded real dashboard Show finished displays the exact installed enrollment created by this browser-enabled native renewal, agreeing with the authenticated public API",
      },
    );
    assert.equal(mutations, 6);
    Object.assign(facts, {
      noSyntheticResponses: true,
      noDateOrJournalOverrides: true,
      fingerprints: [initial.fingerprint, final.fingerprint],
      spkiFingerprints: [initial.spki, final.spki],
      requestId,
      enrollmentId: enrollment.id,
      jobId: job.id,
      profileId,
      issuerId,
    });
  } catch (error) {
    const code = /^[A-Z0-9_]{1,64}$/.test(error?.code || "")
      ? error.code
      : "UNCLASSIFIED";
    primary = new Error(
      `Native AD CS browser journey failed at ${stage} (${code})`,
    );
    throw primary;
  } finally {
    const clean = async () => {
      const failures = [];
      try {await probes.drain();} catch(error){failures.push(error);}
      try {
        await resource.close();
      } catch (error) {
        failures.push(error);
      }
      // Recover ownership even if the scheduler committed an enrollment before
      // throwing. This issuer was created by this browser run alone.
      if (issuerId)
        try {
          const owned = (
            await query(
              "SELECT id FROM certificate_enrollments WHERE workspace_id=$1 AND issuer_id=$2",
              [fixture.workspaceId, issuerId],
            )
          ).rows;
          for (const value of owned) {
            if (!ownedEnrollmentIds.includes(value.id))
              ownedEnrollmentIds.push(value.id);
            const record =
              require("../../../packages/agent/src/windows-cert-store").readIssuedContainerRecord(
                {
                  stateDir: configDir,
                  containerName:
                    require("../../../packages/agent/src/windows-cert-store").buildEnrollmentContainerName(
                      value.id,
                    ),
                },
              );
            if (/^[A-F0-9]{40}$/i.test(record?.acceptedThumbprint || ""))
              ownedThumbprints.add(record.acceptedThumbprint.toUpperCase());
          }
        } catch (error) {
          failures.push(error);
        }
      for (const id of policies.reverse())
        try {
          const restored = await fixture.request(
            `${api}/profiles/${id}`,
            "PATCH",
            { autoRenewEnabled: true },
          );
          assert.equal(restored.status, 200);
          const observed = await fixture.request(`${api}/profiles/${id}`);
          assert.equal(observed.status, 200);
          assert.equal(observed.body.autoRenewEnabled, true);
        } catch (error) {
          failures.push(error);
        }
      if (failures.length)
        throw new AggregateError(
          failures,
          "Owned AD CS browser cleanup failed",
        );
      facts.browserAndTrustCleaned = facts.otherProfilePoliciesRestored = true;
    };
    try {
      await gate.scenario(REQUIRED_SCENARIOS[5], clean, {
        evidenceLevel: "real-host",
        oracle:
          "Owned Chromium is drained, only newly added exact public trust is removed, and changed public profile policies are restored; parent owns enrollment/native fixture cleanup",
      });
    } catch (error) {
      if (primary)
        throw new AggregateError(
          [primary, error],
          "AD CS browser journey and cleanup failed",
        );
      throw error;
    }
  }
  verifyProof(facts);
  gate.report.nativeBrowserAdcs = facts;
}
module.exports = {
  REQUIRED_SCENARIOS,
  REQUIRED_SOURCES,
  FLAGS,
  SCOPE,
  verifyProof,
  createOwnedBrowserResource,
  currentAuthorityGroup,
  qualifyAdcsBrowserJourney,
};
