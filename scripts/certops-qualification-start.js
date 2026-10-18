"use strict";
/** Read-only starting plan for hosted qualification. Prints reviewed commands;
 * never dispatches Actions, configures credentials, provisions or deletes a lab.
 * Initial smoke checks do not satisfy every standard-hosted or full matrix cell. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path");
const ROOT = path.resolve(__dirname, ".."),
  REPOSITORY = "tokentimerch/tokentimer-core";
const PHASES = Object.freeze([
  {
    id: "tooling",
    description: "Fast source, report and security checks",
    runs: [
      { workflow: "certops-qualification.yml", inputs: { lane: "tooling" } },
    ],
  },
  {
    id: "api",
    description: "Isolated API/PostgreSQL supporting suites; no enterprise CA",
    runs: [
      { workflow: "certops-qualification.yml", inputs: { lane: "stack" } },
    ],
  },
  {
    id: "windows",
    description:
      "Hosted Windows controls, then one installed agent/IIS profile",
    runs: [
      { workflow: "certops-qualification.yml", inputs: { lane: "windows" } },
      {
        workflow: "certops-windows-e2e.yml",
        inputs: {
          windows_server: "windows-2022",
          key_profile: "rsa-2048",
          historical_upgrade: "false",
          wer_probe: "false",
        },
      },
    ],
  },
  {
    id: "linux",
    description:
      "Hosted Linux installation and one real local-CA client profile",
    runs: [
      { workflow: "certops-linux-systemd.yml", inputs: {} },
      {
        workflow: "certops-real-acme.yml",
        inputs: { client: "certbot", eab: "none" },
      },
    ],
  },
  {
    id: "browser-dns",
    description: "Real dashboard and owned local DNS; no live provider account",
    runs: [
      { workflow: "certops-browser-qualification.yml", inputs: {} },
      { workflow: "certops-dns-routing-qualification.yml", inputs: {} },
      { workflow: "certops-dns-provider-errors.yml", inputs: {} },
    ],
  },
  {
    id: "kubernetes",
    description:
      "Disposable local kind/cert-manager tests, not a cloud cluster",
    runs: [
      { workflow: "certops-kubernetes-qualification.yml", inputs: {} },
      { workflow: "certops-kubernetes-http01-qualification.yml", inputs: {} },
    ],
  },
]);
function command(run) {
  return [
    "gh workflow run",
    run.workflow,
    "--repo",
    REPOSITORY,
    "--ref main",
    ...Object.entries(run.inputs).flatMap(([key, value]) => [
      "-f",
      `${key}=${value}`,
    ]),
  ].join(" ");
}
function validatePlan(phases = PHASES, root = ROOT) {
  assert.ok(Array.isArray(phases) && phases.length > 0);
  for (const phase of phases)
    for (const run of phase.runs) {
      assert.match(run.workflow, /^certops-[a-z0-9-]+\.yml$/);
      const text = fs.readFileSync(
        path.join(root, ".github/workflows", run.workflow),
        "utf8",
      );
      assert.match(text, /^  workflow_dispatch:/m);
      assert.match(text, /github\.ref == 'refs\/heads\/main'/);
      assert.doesNotMatch(
        text,
        /azure\/(?:login|cli)@|AZURE_(?:CLIENT|TENANT|SUBSCRIPTION)_ID|provision-lab\.ps1|certops-adcs-lab/,
      );
      for (const [key, value] of Object.entries(run.inputs)) {
        assert.match(key, /^[a-z_]+$/);
        assert.match(value, /^[a-z0-9.-]+$/);
        assert.match(text, new RegExp(`^      ${key}:`, "m"));
      }
    }
  return true;
}
function buildPlan(candidateSha) {
  if (candidateSha !== undefined) assert.match(candidateSha, /^[a-f0-9]{40}$/);
  validatePlan();
  return {
    schemaVersion: 1,
    executionStatus: "not-run",
    dispatchesWorkflows: false,
    configuresRemoteResources: false,
    azureLabCredentialsRequired: false,
    scope: "initial-hosted-smoke-not-complete-matrix",
    candidateSha: candidateSha || null,
    phases: PHASES.map((phase) => ({
      ...phase,
      runs: phase.runs.map((run) => ({
        ...run,
        inputs: { ...run.inputs },
        command: command(run),
      })),
    })),
    collection: {
      workflow: "certops-release-qualification.yml",
      profile: "standard-hosted",
      warning:
        "Collect only after every selected profile cell has evidence. This profile includes live DNS-provider and blocked published-package cells; the initial smoke plan does not fill them. It never qualifies omitted AD CS/elapsed cells or the full matrix.",
    },
  };
}
function profileInventory() {
  const h = require("./certops-qualification-profiles"),
    matrix = require("./certops-qualification-manifest");
  return {
    schemaVersion: 1,
    executionStatus: "not-run",
    profiles: Object.keys(h.PROFILES).map((profile) => {
      const s = h.selectProfile(matrix, profile);
      return {
        profile,
        selectedCount: s.selectedSlotIds.length,
        omittedCount: s.omittedSlotIds.length,
        selectedSlotIds: s.selectedSlotIds,
        omittedSlotIds: s.omittedSlotIds,
      };
    }),
  };
}
function main(args = process.argv.slice(2)) {
  let candidate,
    profiles = false,
    json = false;
  while (args.length) {
    const arg = args.shift();
    if (arg === "--json") json = true;
    else if (arg === "--profiles") profiles = true;
    else if (arg === "--candidate") {
      assert.ok(!candidate);
      candidate = args.shift();
      assert.match(candidate || "", /^[a-f0-9]{40}$/);
    } else
      throw new Error(
        "Usage: node scripts/certops-qualification-start.js [--candidate <40-hex-sha>] [--json]; no dispatch option",
      );
  }
  if (profiles) {
    assert.equal(
      candidate,
      undefined,
      "Profile inventory is not an execution/candidate verdict",
    );
    console.log(JSON.stringify(profileInventory(), null, 2));
    return;
  }
  const plan = buildPlan(candidate);
  if (json) {
    console.log(JSON.stringify(plan, null, 2));
    return;
  }
  console.log(
    "Azure-free first qualification: plan only; nothing dispatched or configured.\nRun from trusted main and verify every run uses the same exact candidate SHA.\nStop after a failed phase; inspect its bounded report before expanding scope.\n",
  );
  for (const phase of plan.phases) {
    console.log(`${phase.id}: ${phase.description}`);
    for (const run of phase.runs) console.log(run.command);
    console.log("");
  }
  console.log(
    "Then expand hosted profiles using docs/certops/qualification/reporting/first-qualification.md.\n" +
      plan.collection.warning,
  );
}
module.exports = {
  PHASES,
  command,
  validatePlan,
  buildPlan,
  profileInventory,
  main,
};
if (require.main === module)
  try {
    main();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
