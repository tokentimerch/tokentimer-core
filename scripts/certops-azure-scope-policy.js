"use strict";
/** Paid qualification infrastructure is an explicit repository opt-in. Scheduled jobs
 * may only finish/clean an already owned manual campaign, never create a lab. */
const KV = "certops-azure-keyvault-qualification.yml";
const KV_CLEANUP = "certops-azure-keyvault-janitor.yml";
const PROVISION = Object.freeze([
  "certops-enterprise-adcs-qualification.yml",
  KV,
]);
const LIFECYCLE = Object.freeze(["certops-adcs-lab-janitor.yml", KV_CLEANUP]);
const MAIN = "github.ref == 'refs/heads/main'";
const PROVISION_IF = MAIN + " && vars.CERTOPS_ADCS_LAB_ENABLED == 'true'";
const KEYVAULT_IF =
  MAIN + " && vars.CERTOPS_AZURE_KEYVAULT_LAB_ENABLED == 'true'";
const LIFECYCLE_IF = MAIN;
function allowedCondition(name, value) {
  return PROVISION.includes(name)
    ? value === (name === KV ? KEYVAULT_IF : PROVISION_IF)
    : LIFECYCLE.includes(name) && value === LIFECYCLE_IF;
}
function keyvaultPolicy(name, workflow, errors) {
  const janitor = name === KV_CLEANUP;
  if (janitor) {
    if (
      JSON.stringify(Object.keys(workflow.on || {})) !==
        JSON.stringify(["schedule", "workflow_dispatch"]) ||
      JSON.stringify(workflow.on.schedule) !==
        JSON.stringify([{ cron: "43 * * * *" }]) ||
      workflow.on.workflow_dispatch != null
    )
      errors.push(
        "Key Vault cleanup requires its hourly schedule and input-free dispatch",
      );
    if (
      JSON.stringify(workflow.jobs?.cleanup?.env) !==
      JSON.stringify({
        AZURE_CLIENT_ID: "${{ vars.AZURE_CLIENT_ID }}",
        AZURE_TENANT_ID: "${{ vars.AZURE_TENANT_ID }}",
        AZURE_SUBSCRIPTION_ID: "${{ vars.AZURE_SUBSCRIPTION_ID }}",
        GH_TOKEN: "${{ github.token }}",
      })
    )
      errors.push(
        "Cleanup must use only its separate identity variables, without spending gates",
      );
  }
  const expectedJobs = janitor ? ["cleanup"] : ["preflight", "lab"];
  if (
    JSON.stringify(Object.keys(workflow.jobs || {})) !==
    JSON.stringify(expectedJobs)
  )
    errors.push("Key Vault job inventory must be reviewed explicitly");
  if (
    !workflow.permissions ||
    workflow.permissions.contents !== "read" ||
    Object.keys(workflow.permissions).length !== 1 ||
    workflow.env
  )
    errors.push(
      "OIDC and Azure variables belong only to the protected Azure job",
    );
  if (
    workflow.concurrency?.["cancel-in-progress"] !== false ||
    workflow.concurrency?.group !==
      `certops-azure-keyvault-${janitor ? "cleanup" : "provisioning"}`
  )
    errors.push(
      "Paid Key Vault campaigns require a fixed non-cancelling concurrency boundary",
    );
  const text = JSON.stringify(workflow);
  const allowedAzure = new Set([
    "AZURE_CLIENT_ID",
    "AZURE_TENANT_ID",
    "AZURE_SUBSCRIPTION_ID",
    "AZURE_KV_ISSUER_ROLE_ID",
    "AZURE_KV_ATTRIBUTES_ROLE_ID",
  ]);
  if (
    [...text.matchAll(/\bAZURE_[A-Z0-9_]+/g)].some(
      (match) => !allowedAzure.has(match[0]),
    ) ||
    /\$\{\{\s*secrets\./.test(text)
  )
    errors.push(
      "Only reviewed OIDC variable references are allowed, never Azure credential secrets",
    );
  for (const [id, job] of Object.entries(workflow.jobs || {})) {
    const preflight = !janitor && id === "preflight";
    if (preflight) {
      if (
        job.environment ||
        !job.permissions ||
        Object.entries(job.permissions).some(
          ([key, value]) =>
            !["contents", "actions", "deployments"].includes(key) ||
            value !== "read",
        ) ||
        /\bAZURE_(?:CLIENT|TENANT|SUBSCRIPTION|KV)_/.test(JSON.stringify(job))
      )
        errors.push(
          "Preflight must remain unprivileged and outside Azure environments",
        );
      const first = job.steps?.[0];
      if (
        !first?.run?.includes('test "$GITHUB_REF" = refs/heads/main') ||
        !first.run.includes('test "$GITHUB_EVENT_NAME" = workflow_dispatch') ||
        !first.run.includes('test "$OPT_IN" = true')
      )
        errors.push(
          "Preflight must reject wrong refs and missing opt-in before checkout",
        );
      if (
        (job.steps || []).some((step) =>
          /login-oidc|lab\.js\s+(?:provision|cleanup|janitor)|\baz\s/.test(
            step.run || "",
          ),
        )
      )
        errors.push("Preflight cannot authenticate or mutate Azure");
    } else {
      if (!allowedCondition(name, job.if))
        errors.push(
          "Exact repository opt-in and trusted-main condition required",
        );
      if (
        job.environment !==
        `certops-azure-keyvault-${janitor ? "cleanup" : "lab"}`
      )
        errors.push("Dedicated protected Key Vault environment required");
      if (
        job.permissions?.["id-token"] !== "write" ||
        job.permissions.contents !== "read" ||
        Object.entries(job.permissions).some(
          ([key, value]) =>
            !["contents", "actions", "id-token"].includes(key) ||
            (key !== "id-token" && value !== "read"),
        )
      )
        errors.push("Azure job permissions must be explicitly bounded");
      if (
        !Number.isInteger(job["timeout-minutes"]) ||
        job["timeout-minutes"] > (janitor ? 20 : 90) ||
        job["timeout-minutes"] < 1
      )
        errors.push("Azure job needs a bounded timeout");
      if (
        !janitor &&
        (job.needs !== "preflight" ||
          job.env?.TT_REAL_AZURE !== "1" ||
          job.env?.TT_AZURE_QUALIFICATION_REQUIRED !== "1")
      )
        errors.push("Real Azure campaign must be mandatory after preflight");
      const steps = job.steps || [];
      for (const command of [
        "node tests/e2e/azure-keyvault-real.cjs scrub",
        ...(!janitor
          ? ["node infra/certops-azure-keyvault/lab.js cleanup"]
          : []),
      ])
        if (
          !steps.some((step) => step.run === command && step.if === "always()")
        )
          errors.push(
            "Always-run private staging and owned-resource cleanup required",
          );
      if (
        janitor &&
        !steps.some(
          (step) =>
            step.run === "node infra/certops-azure-keyvault/lab.js janitor" &&
            !step.if,
        )
      )
        errors.push(
          "Janitor must use the ownership-checked Key Vault cleanup helper",
        );
      if (
        janitor &&
        steps.some(
          (step) =>
            step.run &&
            ![
              "./infra/certops-azure-keyvault/login-oidc.ps1",
              "node infra/certops-azure-keyvault/lab.js janitor",
              "node tests/e2e/azure-keyvault-real.cjs scrub",
            ].includes(step.run),
        )
      )
        errors.push(
          "Janitor command inventory cannot provision or accept arbitrary Azure commands",
        );
      if (
        janitor &&
        (steps.length !== 5 ||
          !steps.some(
            (step) =>
              step.run === "./infra/certops-azure-keyvault/login-oidc.ps1" &&
              step.shell === "pwsh" &&
              !step.if,
          ) ||
          steps.filter((step) => step.uses).length !== 2)
      )
        errors.push(
          "Cleanup authentication, deletion and private staging scrub must remain mandatory",
        );
      if (!janitor) {
        for (const command of [
          "node infra/certops-azure-keyvault/lab.js provision",
          "node tests/e2e/azure-keyvault-real.cjs prepare",
          "node tests/e2e/azure-keyvault-real.cjs run",
        ])
          if (
            !steps.some(
              (step) =>
                step.run === command && !step.if && !step["continue-on-error"],
            )
          )
            errors.push("All real Azure campaign stages are mandatory");
        const guard = steps.find((step) => step.id === "evidence-check");
        const upload = steps.find((step) =>
          step.uses?.startsWith("actions/upload-artifact@"),
        );
        if (
          guard?.run !==
            "node scripts/certops-azure-keyvault-report.js --artifact-check qualification-results" ||
          guard.if !== "always()" ||
          guard["continue-on-error"] ||
          upload?.if !==
            "always() && steps.evidence-check.outcome == 'success'" ||
          upload.with?.path?.trim() !==
            "qualification-results/azure-keyvault-evidence.json\nqualification-results/azure-keyvault-cleanup.json" ||
          upload.with?.["if-no-files-found"] !== "error" ||
          steps.filter((step) =>
            step.uses?.startsWith("actions/upload-artifact@"),
          ).length !== 1
        )
          errors.push(
            "Artifact upload must be gated by the closed sanitized evidence allowlist",
          );
      }
    }
    if (
      job["continue-on-error"] ||
      (job.steps || []).some((step) => step["continue-on-error"])
    )
      errors.push(
        "Key Vault campaign cannot hide failed prerequisites or scenarios",
      );
    if (
      (job.steps || []).some(
        (step) => step.uses && !/^[^@]+@[a-f0-9]{40}$/.test(step.uses),
      )
    )
      errors.push("Key Vault actions require immutable reviewed pins");
    for (const step of job.steps || [])
      if (
        step.uses?.startsWith("actions/checkout@") &&
        (step.with?.ref ||
          step.with?.repository ||
          step.with?.["persist-credentials"] !== false)
      )
        errors.push(
          "Checkout must use this trusted workflow SHA without persisted credentials",
        );
  }
  if (!janitor) {
    const inputs = workflow.on?.workflow_dispatch?.inputs;
    if (
      !inputs ||
      Object.keys(inputs).join() !== "location" ||
      inputs.location.type !== "choice" ||
      JSON.stringify(inputs.location.options) !==
        JSON.stringify(["swedencentral", "westeurope", "northeurope"])
    )
      errors.push("Only the reviewed bounded region choice is dispatchable");
  }
}
function validate(name, workflow) {
  const errors = [];
  const known = PROVISION.includes(name) || LIFECYCLE.includes(name);
  const runs = Object.values(workflow.jobs || {}).flatMap((job) =>
    (job.steps || []).map((step) => step.run || ""),
  );
  const azure =
    JSON.stringify(workflow).includes("AZURE_") ||
    Object.values(workflow.jobs || {}).some((job) =>
      (job.steps || []).some(
        (step) =>
          typeof step.uses === "string" && step.uses.startsWith("azure/login@"),
      ),
    ) ||
    runs.some((run) =>
      /\baz\s+(?:login|rest|keyvault|identity|role|group\s+create|vm\s+create|deployment\s+(?:(?:group|sub)\s+)?create)\b/.test(
        run,
      ),
    ) ||
    runs.some((run) =>
      /infra\/certops-(?:adcs\/(?:login-oidc|provision-lab)|azure-keyvault\/)|azure-keyvault-real\.cjs|certops-(?:retention24h|retention-cadence|adcs-ttl24h)-azure\.js/.test(
        run,
      ),
    );
  if (azure && !known)
    errors.push(
      "Azure workflow is outside the reviewed qualification lifecycle inventory",
    );
  if (!known) return errors;
  const events = Object.keys(workflow.on || {});
  if (PROVISION.includes(name) && events.join(",") !== "workflow_dispatch")
    errors.push("Azure provisioning must be explicit manual dispatch only");
  if (
    LIFECYCLE.includes(name) &&
    events.some((event) => !["workflow_dispatch", "schedule"].includes(event))
  )
    errors.push(
      "Azure lifecycle may only finalize or clean an existing manual campaign",
    );
  if (
    LIFECYCLE.includes(name) &&
    runs.some((run) =>
      /provision-lab|lab\.js\s+provision|\baz\s+(?:keyvault\s+create|identity\s+create|role\s+assignment\s+create|group\s+create|vm\s+create|deployment\s+(?:(?:group|sub)\s+)?create)\b/.test(
        run,
      ),
    )
  )
    errors.push("Scheduled Azure lifecycle cannot provision resources");
  if ([KV, KV_CLEANUP].includes(name)) {
    keyvaultPolicy(name, workflow, errors);
    return errors;
  }
  for (const job of Object.values(workflow.jobs || {})) {
    if (!allowedCondition(name, job.if))
      errors.push(
        "Exact repository opt-in and trusted-main condition required",
      );
    if (LIFECYCLE.includes(name) && job.environment !== "certops-adcs-cleanup")
      errors.push(
        "Scheduled cleanup/finalization requires the independent unattended cleanup environment",
      );
  }
  return errors;
}
module.exports = {
  PROVISION,
  LIFECYCLE,
  PROVISION_IF,
  KEYVAULT_IF,
  LIFECYCLE_IF,
  allowedCondition,
  validate,
};
