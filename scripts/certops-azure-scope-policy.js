"use strict";
/** Paid domain infrastructure is an explicit repository opt-in. Scheduled jobs
 * may only finish/clean an already owned manual campaign, never create a lab. */
const PROVISION = Object.freeze(["certops-enterprise-adcs-qualification.yml"]);
const LIFECYCLE = Object.freeze(["certops-adcs-lab-janitor.yml"]);
const MAIN = "github.ref == 'refs/heads/main'";
const PROVISION_IF = MAIN + " && vars.CERTOPS_ADCS_LAB_ENABLED == 'true'";
const LIFECYCLE_IF = MAIN;
function allowedCondition(name, value) {
  return PROVISION.includes(name)
    ? value === PROVISION_IF
    : LIFECYCLE.includes(name) && value === LIFECYCLE_IF;
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
      /\baz\s+(?:login|group\s+create|vm\s+create|deployment\s+(?:(?:group|sub)\s+)?create)\b/.test(
        run,
      ),
    ) ||
    runs.some((run) =>
      /infra\/certops-adcs\/(?:login-oidc|provision-lab)|certops-(?:retention24h|retention-cadence|adcs-ttl24h)-azure\.js/.test(
        run,
      ),
    );
  if (azure && !known)
    errors.push(
      "Azure workflow is outside the reviewed domain lifecycle inventory",
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
      /provision-lab|\baz\s+(?:group\s+create|vm\s+create|deployment\s+(?:(?:group|sub)\s+)?create)\b/.test(
        run,
      ),
    )
  )
    errors.push("Scheduled Azure lifecycle cannot provision resources");
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
  LIFECYCLE_IF,
  allowedCondition,
  validate,
};
