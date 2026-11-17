"use strict";
/** Paid qualification infrastructure is an explicit repository opt-in. Scheduled jobs
 * may only finish/clean an already owned manual campaign, never create a lab. */
const KV = "certops-azure-keyvault-qualification.yml";
const KV_CLEANUP = "certops-azure-keyvault-janitor.yml";
const IMDS = "certops-azure-imds-qualification.yml";
const PROVISION = Object.freeze([
  KV,
  IMDS,
  "certops-native-issuer-reassignment.yml",
  "certops-enterprise-adcs-qualification.yml",
  "certops-enterprise-adcs-hierarchy-qualification.yml",
  "certops-enterprise-adcs-pending-elapsed.yml",
  "certops-enterprise-adcs-journal-phase-experiment.yml",
  "certops-enterprise-adcs-response-loss-experiment.yml",
  "certops-retention24h-prepare.yml",
  "certops-adcs-ttl24h-prepare.yml",
  "certops-retention-cadence-prepare.yml",
]);
const LIFECYCLE = Object.freeze([
  KV_CLEANUP,
  "certops-adcs-lab-janitor.yml",
  "certops-retention24h-finalize.yml",
  "certops-retention24h-janitor.yml",
  "certops-adcs-ttl24h-finalize.yml",
  "certops-adcs-ttl24h-janitor.yml",
  "certops-retention-cadence-finalize.yml",
  "certops-retention-cadence-janitor.yml",
]);
const MAIN = "github.ref == 'refs/heads/main'";
const PROVISION_IF = MAIN + " && vars.CERTOPS_ADCS_LAB_ENABLED == 'true'";
const KEYVAULT_IF =
  MAIN + " && vars.CERTOPS_AZURE_KEYVAULT_LAB_ENABLED == 'true'";
const EXPIRY_IF = KEYVAULT_IF + " && inputs.natural_expiry";
const PROVIDER_IF = KEYVAULT_IF + " && !inputs.natural_expiry";
const EXPIRY_UPLOAD_IF = "success() && steps.expiry-observation.outcome == 'success' && steps.expiry-cleanup.outcome == 'success'";
const IMDS_IF = MAIN + " && vars.CERTOPS_AZURE_IMDS_LAB_ENABLED == 'true'";
const IMDS_UPLOAD_IF = "success() && steps.collect.outcome == 'success' && steps.scrub.outcome == 'success'";
const LIFECYCLE_IF = MAIN;
const SELF_APPROVAL = "TT_AZURE_LAB_SELF_APPROVAL";
const SELF_APPROVAL_REFERENCE = "${{ secrets.CERTOPS_AZURE_LAB_SELF_APPROVAL }}";
const hasScopedApproval = step => step?.env?.[SELF_APPROVAL] === SELF_APPROVAL_REFERENCE;
function allowedCondition(name, value) {
  if (name === KV) return [PROVIDER_IF, EXPIRY_IF, KEYVAULT_IF + " && inputs.final_package"].includes(value);
  if (name === IMDS) return value === IMDS_IF;
  return PROVISION.includes(name)
    ? value === PROVISION_IF
    : LIFECYCLE.includes(name) && value === LIFECYCLE_IF;
}

function imdsPolicy(workflow, errors) {
  const job = workflow.jobs?.lab;
  if (Object.keys(workflow.jobs || {}).join() !== "lab" ||
      workflow.concurrency?.group !== "certops-azure-imds-qualification" ||
      workflow.concurrency?.["cancel-in-progress"] !== false ||
      JSON.stringify(workflow.permissions) !== JSON.stringify({ contents: "read" }) ||
      job?.name !== "IMDS qualification" || job.if !== IMDS_IF || job["runs-on"] !== "ubuntu-latest" ||
      job.environment !== "certops-azure-imds-lab" || job["timeout-minutes"] !== 90 ||
      JSON.stringify(job.permissions) !== JSON.stringify({ contents: "read", actions: "read", "id-token": "write" }) ||
      job.services || job.strategy || job["continue-on-error"]) {
    errors.push("IMDS requires one bounded protected main job with its dedicated opt-in");
    return;
  }
  const inputs = workflow.on?.workflow_dispatch?.inputs || {};
  if (Object.keys(inputs).sort().join() !== "package_artifact_id,package_run_id,package_sha256" ||
      Object.values(inputs).some(input => input.type !== "string" || input.required !== true)) {
    errors.push("IMDS requires the immutable producer run, artifact and checksum");
  }
  const [checkout, node, verify, login, launch, reauth, collect, scrub, upload] = job.steps || [];
  const loginStep = step => step?.shell === "pwsh" && step.run === "./infra/certops-azure-keyvault/login-oidc.ps1" && !step.if;
  if (job.steps?.length !== 9 || job.steps.some(step =>
      step["continue-on-error"] || (step !== launch && step.env?.TT_IMDS_APPROVED_PLAN_B64 !== undefined) ||
      (![verify, launch, collect].includes(step) && step.env?.[SELF_APPROVAL] !== undefined)) ||
      !checkout?.uses?.startsWith("actions/checkout@") || checkout.if ||
      checkout.with?.["persist-credentials"] !== false || checkout.with.ref || checkout.with.repository ||
      !node?.uses?.startsWith("actions/setup-node@") || node.if || node.with?.["node-version"] !== "24.22.3" ||
      verify?.id !== "verify-package" || verify.if || !verify.run?.includes("scripts/certops-final-package-source.cjs") ||
      !verify.run?.trimEnd().endsWith("node infra/certops-azure-keyvault/lab.js github-imds-approval") ||
      ![verify, launch, collect].every(hasScopedApproval) ||
      JSON.stringify(workflow).split(SELF_APPROVAL_REFERENCE).length !== 4 ||
      job.env?.TT_IMDS_APPROVED_PLAN_B64 !== undefined || job.env?.[SELF_APPROVAL] !== undefined ||
      !loginStep(login) || launch?.id !== "launch" || launch.if ||
      launch.env?.TT_IMDS_APPROVED_PLAN_B64 !== "${{ secrets.TT_IMDS_APPROVED_PLAN_B64 }}" ||
      !launch.run?.includes("infra/certops-azure-keyvault/imds/launch.cjs launch") || !loginStep(reauth) ||
      collect?.id !== "collect" || collect.if || !collect.run?.includes("infra/certops-azure-keyvault/imds/launch.cjs collect") ||
      scrub?.id !== "scrub" || scrub.if !== "always()" || !scrub.run?.includes('rm -rf -- "$private" "$retained"') ||
      !upload?.uses?.startsWith("actions/upload-artifact@") || upload.if !== IMDS_UPLOAD_IF ||
      upload.with?.name !== "azure-imds-final-package" ||
      upload.with?.path !== "qualification-results/azure-imds-final-package.json" ||
      upload.with?.["if-no-files-found"] !== "error") {
    errors.push("IMDS must verify the package before login and expose only the post-teardown, scrubbed profile");
  }
}

function expiryPolicy(job, provider) {
  const steps = job.steps || [];
  const [checkout, node, approval, stage, login, provision, observation, reauth, cleanup, finalize, upload] = steps;
  const command = (step, action, condition) => step?.run === `node tests/e2e/azure-keyvault-natural-expiry.cjs ${action}` && step.if === condition;
  const loginCommand = "./infra/certops-azure-keyvault/login-oidc.ps1";
  const evidence = "azure-natural-expiration-final-package";
  return job.needs === "preflight" && job.if === EXPIRY_IF && job["runs-on"] === "ubuntu-latest" &&
    job["timeout-minutes"] === 125 && job.environment === "certops-azure-keyvault-lab" &&
    JSON.stringify(job.permissions) === JSON.stringify({ contents: "read", actions: "read", "id-token": "write" }) &&
    !job.services && !job.strategy &&
    JSON.stringify(job.env) === JSON.stringify({
      ...Object.fromEntries([
        "CERTOPS_AZURE_KEYVAULT_LAB_ENABLED", "AZURE_CLIENT_ID", "AZURE_TENANT_ID",
        "AZURE_SUBSCRIPTION_ID", "AZURE_KV_ISSUER_ROLE_ID", "AZURE_KV_ATTRIBUTES_ROLE_ID",
      ].map(name => [name, "${{ vars." + name + " }}"])),
      LAB_LOCATION: "${{ inputs.location }}",
      GH_TOKEN: "${{ github.token }}",
      AZURE_CORE_COLLECT_TELEMETRY: "no",
      TT_AZURE_EXPIRY_PACKAGE_RUN_ID: "${{ inputs.package_run_id }}",
      TT_AZURE_EXPIRY_PACKAGE_ARTIFACT_ID: "${{ inputs.package_artifact_id }}",
      TT_AZURE_PACKAGE_SHA256: "${{ inputs.package_sha256 }}",
    }) &&
    provider?.if === PROVIDER_IF &&
    steps.length === 11 && steps.every(step => (step === approval ? Object.keys(step.env || {}).length === 1 && hasScopedApproval(step) : !step.env) && !step["continue-on-error"]) &&
    checkout?.uses?.startsWith("actions/checkout@") && !checkout.if &&
    checkout.with?.["persist-credentials"] === false && !checkout.with.ref && !checkout.with.repository &&
    node?.uses?.startsWith("actions/setup-node@") && !node.if && node.with?.["node-version"] === "24.22.3" &&
    approval?.run === "node infra/certops-azure-keyvault/lab.js github-approval" && approval.id === "expiry-approval" && !approval.if &&
    command(stage, "stage-package") && login?.run === loginCommand && login.shell === "pwsh" && !login.if &&
    provision?.run === "node infra/certops-azure-keyvault/lab.js provision" && !provision.if &&
    observation?.id === "expiry-observation" && command(observation, "launch") &&
    reauth?.run === loginCommand && reauth.shell === "pwsh" && reauth.id === "expiry-cleanup-auth" &&
    reauth.if === "always() && steps.expiry-approval.outcome == 'success'" &&
    cleanup?.id === "expiry-cleanup" && command(cleanup, "cleanup", "always() && steps.expiry-cleanup-auth.outcome == 'success'") &&
    command(finalize, "finalize", "always()") &&
    upload?.uses?.startsWith("actions/upload-artifact@") && upload.if === EXPIRY_UPLOAD_IF &&
    upload.with?.name === evidence && upload.with?.path === `qualification-results/${evidence}.json` &&
    upload.with?.["if-no-files-found"] === "error";
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
  const expectedJobs = janitor ? ["cleanup"] : ["preflight", "lab", "natural-expiry", "collect-final-package"];
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
    "AZURE_CORE_COLLECT_TELEMETRY",
  ]);
  if (
    [...text.matchAll(/\bAZURE_[A-Z0-9_]+/g)].some(
      (match) => !allowedAzure.has(match[0]),
    ) ||
    /\$\{\{\s*secrets\./.test(janitor ? text : text.replaceAll(SELF_APPROVAL_REFERENCE, "")) ||
    (!janitor && text.split(SELF_APPROVAL_REFERENCE).length !== 3)
  )
    errors.push(
      "Only reviewed OIDC variable references are allowed, never Azure credential secrets",
    );
  for (const [id, job] of Object.entries(workflow.jobs || {})) {
    if (!janitor && id === "natural-expiry") {
      if (!expiryPolicy(job, workflow.jobs.lab))
        errors.push("Natural expiry must validate the producer before authentication and verify drainage and teardown before uploading evidence");
      continue;
    }
    if (!janitor && id === "collect-final-package") {
      const steps = job.steps || [];
      const downloads = steps.filter(step => step.uses?.startsWith("actions/download-artifact@"));
      const uploads = steps.filter(step => step.uses?.startsWith("actions/upload-artifact@"));
      if (job.if !== KEYVAULT_IF + " && inputs.final_package" || JSON.stringify(job.needs) !== JSON.stringify(["preflight", "lab"]) ||
          job.environment || job["continue-on-error"] || JSON.stringify(job.permissions) !== JSON.stringify({contents:"read",actions:"read"}) ||
          job["timeout-minutes"] !== 5 || downloads.length !== 2 ||
          JSON.stringify(job.env) !== JSON.stringify({
            CERTOPS_AZURE_KEYVAULT_LAB_ENABLED: "${{ vars.CERTOPS_AZURE_KEYVAULT_LAB_ENABLED }}",
            TT_AZURE_PACKAGE_ARTIFACT_ID: "${{ needs.preflight.outputs.artifact_id }}",
            TT_AZURE_PACKAGE_SHA256: "${{ inputs.package_sha256 }}",
          }) ||
          downloads[0].with?.["artifact-ids"] !== "${{ needs.preflight.outputs.artifact_id }}" ||
          downloads[1].with?.["artifact-ids"] !== "${{ needs.lab.outputs.evidence_id }}" ||
          downloads[0].with?.path !== "${{ runner.temp }}/azure-release-candidate/artifacts" ||
          downloads[1].with?.path !== "${{ runner.temp }}/azure-final-evidence" ||
          downloads.some(step => step.with?.["digest-mismatch"] !== "error" || step.with?.["merge-multiple"] !== true) ||
          uploads.length !== 1 || uploads[0].if !== "always()" ||
          uploads[0].with?.name !== "azure-keyvault-final-package-verdict" ||
          uploads[0].with?.path !== "qualification-results/azure-keyvault-final-package-verdict.json" ||
          uploads[0].with?.["if-no-files-found"] !== "error" ||
          !steps.some(step => step.run?.includes("certops-azure-keyvault-package.cjs collect")) ||
          steps.some(step => step["continue-on-error"] || (step.uses && !/^[^@]+@[a-f0-9]{40}$/.test(step.uses)) ||
            (step.uses?.startsWith("actions/checkout@") && (step.with?.["persist-credentials"] !== false || step.with?.ref || step.with?.repository))) ||
          /\bAZURE_(?:CLIENT|TENANT|SUBSCRIPTION|KV)_|secrets\./.test(JSON.stringify(job)) ||
          steps.some(step => /login-oidc|lab\.js|\baz\s/.test(step.run || ""))) {
        errors.push("Exact-package collector must be read-only and bind both immutable same-run artifacts");
      }
      continue;
    }
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
        !first.run.includes('test "$OPT_IN" = true') ||
        !first.run.includes('[[ "$PACKAGE_SHA256" =~ ^[a-f0-9]{64}$ ]]') ||
        first.env?.FINAL_PACKAGE !== "${{ inputs.final_package }}" || first.env?.PACKAGE_SHA256 !== "${{ inputs.package_sha256 }}" ||
        first.env?.NATURAL_EXPIRY !== "${{ inputs.natural_expiry }}" ||
        first.env?.PACKAGE_RUN_ID !== "${{ inputs.package_run_id }}" || first.env?.PACKAGE_ARTIFACT_ID !== "${{ inputs.package_artifact_id }}" ||
        !first.run.includes('test "$FINAL_PACKAGE" = false') ||
        !first.run.includes('[[ "$PACKAGE_RUN_ID" =~ ^[1-9][0-9]{0,15}$ && "$PACKAGE_ARTIFACT_ID" =~ ^[1-9][0-9]{0,15}$ ]]')
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
      const build = job.steps?.find(step => step.name === "Build and verify the universal package before Azure authentication");
      const upload = job.steps?.find(step => step.id === "package");
      const scan = job.steps?.find(step => step.name === "Scan the retained candidate for fixed High and Critical advisories");
      if (build?.if !== "inputs.final_package" || build.env?.PACKAGE_SHA256 !== "${{ inputs.package_sha256 }}" ||
          build.env?.GOTOOLCHAIN !== "local" || build.env?.GOFLAGS !== "-buildvcs=false" ||
          !job.steps.some(step => step.uses?.startsWith("actions/setup-node@") && step.with?.["node-version"] === "24.22.3") ||
          !build.run?.includes("certops-azure-keyvault-package.cjs build") ||
          scan?.if !== "inputs.final_package" || !scan.run?.includes("acb14a030010fe9bdb9594b4ae108d9d14ef2f926d936aa0916dc62c89c058ea") ||
          !scan.run?.includes("--fail-on high --only-fixed") || job.steps.indexOf(scan) <= job.steps.indexOf(build) ||
          upload?.if !== "inputs.final_package" || upload.with?.name !== "azure-release-candidate" ||
          upload.with?.path !== "qualification-results/azure-release-candidate/" ||
          upload.with?.["if-no-files-found"] !== "error" || job.steps.indexOf(upload) <= job.steps.indexOf(scan) ||
          job.outputs?.artifact_id !== "${{ steps.package.outputs.artifact-id }}") {
        errors.push("Exact-package preflight must verify one expected digest before retaining the candidate");
      }
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
      if (
        !steps.some(
          (step) =>
            step.run === "node tests/e2e/azure-keyvault-real.cjs scrub" &&
            step.if === "always()",
        )
      )
        errors.push("Always-run private staging scrub required");
      if (!janitor) {
        const approval = steps.findIndex(
          (step) => step.id === "independent-approval",
        );
        const loginSteps = steps.filter(
          (step) =>
            step.run === "./infra/certops-azure-keyvault/login-oidc.ps1",
        );
        const cleanupCondition =
          "always() && steps.independent-approval.outcome == 'success'";
        if (
          approval < 0 ||
          steps[approval].run !==
            "node infra/certops-azure-keyvault/lab.js github-approval" ||
          steps[approval].if ||
          steps[approval]["continue-on-error"] || !hasScopedApproval(steps[approval]) ||
          job.env?.[SELF_APPROVAL] !== undefined ||
          steps.some((step, index) => index !== approval && step.env?.[SELF_APPROVAL] !== undefined) ||
          steps
            .slice(0, approval)
            .some(
              (step) =>
                step.run ||
                !/^actions\/(?:checkout|setup-node)@[a-f0-9]{40}$/.test(
                  step.uses || "",
                ),
            ) ||
          steps.findIndex(
            (step) =>
              step.run === "node infra/certops-azure-keyvault/lab.js provision",
          ) <= approval ||
          loginSteps.length !== 2 ||
          steps.indexOf(loginSteps[0]) <= approval ||
          loginSteps[0].if ||
          steps.indexOf(loginSteps[1]) <= approval ||
          loginSteps[1].if !== cleanupCondition ||
          !steps.some(
            (step) =>
              step.run === "node infra/certops-azure-keyvault/lab.js cleanup" &&
              step.if === cleanupCondition,
          )
        )
          errors.push(
            "Protected run approval must precede Azure login and guard cleanup authentication",
          );
      }
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
        const candidate = steps.filter(step => step.uses?.startsWith("actions/download-artifact@"));
        const login = steps.findIndex(step => step.run === "./infra/certops-azure-keyvault/login-oidc.ps1");
        if (candidate.length !== 1 || candidate[0].if !== "inputs.final_package" ||
            candidate[0].with?.["artifact-ids"] !== "${{ needs.preflight.outputs.artifact_id }}" ||
            candidate[0].with?.path !== "${{ runner.temp }}/azure-release-candidate/artifacts" ||
            candidate[0].with?.["digest-mismatch"] !== "error" || candidate[0].with?.["merge-multiple"] !== true ||
            steps.indexOf(candidate[0]) >= login || job.env?.TT_AZURE_FINAL_PACKAGE !== "${{ inputs.final_package && '1' || '0' }}" ||
            job.env?.TT_AZURE_PACKAGE_ARTIFACT_ID !== "${{ needs.preflight.outputs.artifact_id }}" ||
            job.env?.TT_AZURE_PACKAGE_SHA256 !== "${{ inputs.package_sha256 }}") {
          errors.push("Exact-package lab must consume the immutable selected artifact before authentication");
        }
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
      Object.keys(inputs).join() !== "location,final_package,package_sha256,natural_expiry,package_run_id,package_artifact_id" ||
      inputs.final_package?.type !== "boolean" || inputs.final_package.default !== false ||
      inputs.package_sha256?.type !== "string" || inputs.package_sha256.default !== "" ||
      inputs.natural_expiry?.type !== "boolean" || inputs.natural_expiry.default !== false ||
      ["package_run_id", "package_artifact_id"].some(key => inputs[key]?.type !== "string" || inputs[key].default !== "") ||
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
  if (name === IMDS) {
    imdsPolicy(workflow, errors);
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
  EXPIRY_UPLOAD_IF,
  IMDS_UPLOAD_IF,
  LIFECYCLE_IF,
  allowedCondition,
  validate,
};
