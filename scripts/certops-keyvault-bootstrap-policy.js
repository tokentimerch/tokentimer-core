"use strict";
// Bootstrap-only cleanup contract. Replace with the full feature policy on merge.
const PIN = "1d5515a9d83b3ff5799dfb4e34dbb9679c5d18ea";
const SCRUB =
  'node -e \'const fs = require("node:fs"), lab = require("./infra/certops-azure-keyvault/lab"); fs.rmSync(lab.privateRoot(), { recursive: true, force: true });\'';
function validate(workflow) {
  const errors = [];
  const exact = (actual, expected) =>
    JSON.stringify(actual) === JSON.stringify(expected);
  const job = workflow.jobs?.cleanup;
  if (!exact(Object.keys(workflow.jobs || {}), ["cleanup"]) || !job)
    return ["Bootstrap janitor must have exactly one cleanup job"];
  if (
    !exact(Object.keys(workflow.on || {}), ["schedule", "workflow_dispatch"]) ||
    !exact(workflow.on.schedule, [{ cron: "43 * * * *" }]) ||
    workflow.on.workflow_dispatch != null
  )
    errors.push(
      "Bootstrap cleanup needs its hourly schedule and input-free dispatch",
    );
  if (
    !exact(workflow.permissions, { contents: "read" }) ||
    workflow.env ||
    !exact(workflow.concurrency, {
      group: "certops-azure-keyvault-cleanup",
      "cancel-in-progress": false,
    })
  )
    errors.push(
      "Bootstrap workflow privileges/concurrency must remain bounded",
    );
  if (
    job.if !== "github.ref == 'refs/heads/main'" ||
    job.environment !== "certops-azure-keyvault-cleanup" ||
    job["timeout-minutes"] !== 20 ||
    job["continue-on-error"] ||
    !exact(job.permissions, {
      contents: "read",
      actions: "read",
      "id-token": "write",
    })
  )
    errors.push(
      "Bootstrap cleanup must use trusted main and the separate cleanup identity",
    );
  if (
    !exact(job.env, {
      AZURE_CLIENT_ID: "${{ vars.AZURE_CLIENT_ID }}",
      AZURE_TENANT_ID: "${{ vars.AZURE_TENANT_ID }}",
      AZURE_SUBSCRIPTION_ID: "${{ vars.AZURE_SUBSCRIPTION_ID }}",
      GH_TOKEN: "${{ github.token }}",
    })
  )
    errors.push(
      "Bootstrap cleanup cannot accept credentials or spending gates",
    );
  const steps = job.steps || [];
  const checkout = steps[0];
  if (
    steps.length !== 5 ||
    checkout?.uses !==
      "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" ||
    !exact(checkout.with, {
      ref: PIN,
      "persist-credentials": false,
      "sparse-checkout-cone-mode": false,
      "sparse-checkout":
        "/infra/certops-azure-keyvault/\n/infra/certops-adcs/login-oidc.ps1\n",
    }) ||
    steps[1]?.uses !==
      "actions/setup-node@53b83947a5a98c8d113130e565377fae1a50d02f" ||
    !exact(steps[1]?.with, { "node-version": "24" })
  )
    errors.push(
      "Bootstrap cleanup requires its reviewed immutable helper/action pins",
    );
  if (
    steps[2]?.run !== "./infra/certops-azure-keyvault/login-oidc.ps1" ||
    steps[2]?.shell !== "pwsh" ||
    steps[3]?.run !== "node infra/certops-azure-keyvault/lab.js janitor" ||
    steps[4]?.run !== SCRUB ||
    steps[4]?.if !== "always()" ||
    steps.some(
      (step, index) =>
        step["continue-on-error"] ||
        (index !== 4 && step.if) ||
        (index < 2 && step.run) ||
        (index >= 2 && step.uses),
    )
  )
    errors.push(
      "Bootstrap commands must only authenticate, check/delete owned expired groups and scrub",
    );
  return errors;
}
module.exports = { validate };
