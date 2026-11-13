"use strict";

// Only unapplied migrations move. Never rename or renumber an applied row.
const ENROLLMENT = "certops_certificate_enrollments";
const EVIDENCE = "certops_adcs_evidence_types";
const ISSUER = "certops_profile_issuer";
const ALERT = "certops_job_alert_context";
const DISTRIBUTION = "certops_material_distribution";
const REVIEW = "certops_distribution_review";
const TRANSFER = "certops_distribution_transfer";
const canonical = [
  ENROLLMENT,
  EVIDENCE,
  ISSUER,
  ALERT,
  DISTRIBUTION,
  REVIEW,
  TRANSFER,
];
const histories = [
  canonical,
  [ENROLLMENT, EVIDENCE, ISSUER, DISTRIBUTION, REVIEW, TRANSFER, ALERT],
  [DISTRIBUTION, REVIEW, TRANSFER, ENROLLMENT, EVIDENCE, ISSUER, ALERT],
  [ENROLLMENT, DISTRIBUTION, REVIEW, TRANSFER, EVIDENCE, ISSUER, ALERT],
];
const mcpAppendNames = [
  "pagerduty_operator_actions",
  "remove_pagerduty_rest_lookup",
  "operator_connections",
  "operator_enrollment_grants",
  "operator_action_requests",
  "operator_oauth",
  "operator_connection_lifetimes",
  "operator_inventory",
  "operator_oauth_retention",
  "operator_issuance",
  "certops_issuance_job_identity",
  "certops_issuance_identity_transfer",
];

function composeMigrations(migrations, recorded = []) {
  for (const [offset, name] of canonical.entries()) {
    const matches = migrations.filter((entry) => entry.name === name);
    if (matches.length !== 1 || matches[0].version !== 70 + offset)
      throw new Error("Missing or inconsistent pinned Core migration: " + name);
  }
  if (
    new Set(migrations.map((entry) => entry.name)).size !== migrations.length ||
    new Set(migrations.map((entry) => entry.version)).size !== migrations.length
  )
    throw new Error(
      "Missing or inconsistent pinned Core migration registry: Duplicate Core migration version or name",
    );
  // The executor validates pre-70 aliases by their original versions.
  // Released histories can legitimately repeat one of those old names.
  const featureHistory = recorded.filter((entry) => entry.version >= 70);
  if (
    new Set(featureHistory.map((entry) => entry.name)).size !== featureHistory.length ||
    new Set(recorded.map((entry) => entry.version)).size !== recorded.length
  )
    throw new Error("Unsupported Core migration history: duplicate entries");
  const tail = featureHistory
    .slice()
    .sort((a, b) => a.version - b.version);
  const prefix = tail.filter((row) => row.version < 78);
  const order = histories.find((names) =>
    prefix.every(
      (row, index) =>
        row.version === 70 + index &&
        (index < names.length
          ? row.name === names[index]
          : migrations.some(
              (entry) => entry.version === 77 && entry.name === row.name,
            )),
    ),
  );
  if (!order)
    throw new Error(
      "Unsupported Core migration history at version " + tail[0]?.version,
    );
  const rows = tail.filter((row) => row.version >= 78);
  if (rows.length && prefix.length !== 8)
    throw new Error("Unsupported Core migration history: incomplete prefix");
  const extensions = migrations
    .filter((entry) => entry.version >= 78)
    .slice()
    .sort((a, b) => a.version - b.version);
  const byName = new Map(extensions.map((entry) => [entry.name, entry]));
  // Validate the already-applied preview with the previous registry before
  // appending main's newer migrations under unoccupied identities.
  const hasRetirementPreview = byName.get("certops_retirement_dossiers")?.version !== 109 &&
    rows.some((row) => row.version === 109 && row.name === "certops_retirement_dossiers");
  let recognizedRetirementPreview = false;
  if (hasRetirementPreview) {
    const oldRegistry = migrations.filter((entry) => !["certops_period_creator_delete", "recipient_member_verification", "auto_sync_owner_username"].includes(entry.name))
      .map((entry) => entry.name === "certops_retirement_dossiers" ? { ...entry, version: 109 } : entry);
    const oldRows = recorded.filter((row) => row.version <= 109);
    const oldComposed = composeMigrations(oldRegistry, oldRows);
    const oldIdentity = new Map(oldComposed.map((entry) => [entry.name, entry.version]));
    const appended = [
      "certops_period_creator_delete", "recipient_member_verification", "auto_sync_owner_username", "certops_material_reconciliation",
      ...extensions.filter((entry) => entry.version >= 114).map((entry) => entry.name),
    ];
    recognizedRetirementPreview = oldRows.every((row) => row.version < 70 || oldIdentity.get(row.name) === row.version) &&
      rows.filter((row) => row.version > 109).every((row, index) => row.version === 110 + index && row.name === appended[index]);
    if (!recognizedRetirementPreview) throw new Error("Unsupported Core retirement preview migration history");
  }
  // This reviewed preview predates main's PagerDuty migrations at 94/95.
  // Keep its applied identities and finish any partial MCP tail before appending.
  const priorMcpNames = ["certops_installed_file_distribution", "auto_sync_provider_stats", "auto_sync_run_metrics", "auto_sync_metric_labels", "auto_sync_system_metrics", "certops_material_providers", "recipient_channel_verification", "weekly_digest_recipient_claim_token", "pagerduty_incident_lifecycle", "pagerduty_resolution_reason", "operator_connections", "operator_enrollment_grants", "operator_action_requests"];
  const priorMcpVersions = [78, 79, 80, 81, 82, 83, 84, 85, 92, 93, 94, 95, 96];
  const priorMcp = rows.some((row) => row.version === 94 && row.name === "operator_connections");
  const priorAppend = mcpAppendNames.filter((name) => byName.has(name) && !priorMcpNames.includes(name));
  const priorAppendWithAuthority = [...priorAppend];
  if (byName.has("certops_manual_rollout_authority"))
    priorAppendWithAuthority.splice(2, 0, "certops_manual_rollout_authority");
  // A preview may have applied some MCP companions before an independent
  // feature arrived. Recognize each reviewed append prefix, then preserve
  // that exact ledger while placing only unapplied definitions afterward.
  let priorOrder = null;
  if (priorMcp) {
    for (const append of [priorAppend, priorAppendWithAuthority]) {
      for (let length = 0; length <= append.length; length++) {
        const appliedAppend = append.slice(0, length);
        const remaining = extensions.map((entry) => entry.name).filter((name) => !priorMcpNames.includes(name) && !appliedAppend.includes(name));
        const lifecycle = new Set([
          "certops_distribution_lifecycle", "certops_distribution_incident_delivery",
          "certops_stable_consumer_discovery", "certops_material_cleanup",
          "certops_consumer_verification_failures", "certops_distribution_resolution_delivery",
          "certops_consumer_staging", "certops_review_authority_epochs",
        ]);
        // Keep the existing MCP preview append order when no later lifecycle
        // migration has been applied, but recognize either historical ordering.
        const independent = remaining.filter((name) => !lifecycle.has(name));
        const companions = remaining.filter((name) => lifecycle.has(name));
        const historicalOrders = Array.from({ length: independent.length + 1 }, (_entry, cut) =>
          [...independent.slice(0, cut), ...companions, ...independent.slice(cut)],
        );
        for (const tail of [[...independent, ...companions], remaining, ...historicalOrders]) {
          const names = [...priorMcpNames, ...appliedAppend, ...tail];
          const versions = [...priorMcpVersions, ...names.slice(priorMcpNames.length).map((_name, index) => 97 + index)];
          if (rows.every((row, index) => row.name === names[index] && row.version === versions[index])) { priorOrder = names; break; }
        }
        if (priorOrder) break;
      }
      if (priorOrder) break;
    }
  }
  // Earlier MCP draft builds used 96–103 after the PagerDuty tail, before
  // main reserved those slots for independent CertOps work. Keep any applied
  // draft identities and append the missing authority migration afterward.
  const priorDraft = rows.some((row) => row.version === 96 && row.name === "operator_connections");
  if (!priorOrder && priorDraft) {
    const draftNames = [...priorMcpNames.slice(0, 10), "pagerduty_operator_actions", "remove_pagerduty_rest_lookup", ...mcpAppendNames.slice(2).filter((name) => !["certops_issuance_job_identity", "certops_issuance_identity_transfer"].includes(name))];
    const draftVersions = [78, 79, 80, 81, 82, 83, 84, 85, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103];
    const names = [...draftNames, ...extensions.map((entry) => entry.name).filter((name) => !draftNames.includes(name))];
    const versions = [...draftVersions, ...names.slice(draftNames.length).map((_name, index) => 104 + index)];
    if (rows.every((row, index) => row.name === names[index] && row.version === versions[index])) priorOrder = names;
  }
  const recognizedPriorMcp = priorOrder !== null;
  const unknown = rows.find((row) => !byName.has(row.name));
  if (unknown)
    throw new Error(
      "Unsupported Core migration history: unknown extension " + unknown.name,
    );
  // Old contiguous previews retain their actual identities. New independent
  // feature tails may leave only registered reservations absent; arbitrary gaps
  // or numeric aliases are never accepted.
  if (
    rows.some(
      (row) => row.name === "certops_material_providers" && row.version === 80,
    )
  )
    throw new Error(
      "Unsupported Core migration history: unrecognized provider preview",
    );
  const contiguous = rows.every((row, index) => row.version === 78 + index);
  // The observed-revocation candidate used 112–116 before main allocated
  // 112–113. Preserve only that exact reviewed preview tail; new installs
  // use the canonical sequence after main's migrations.
  const observedPreviewTail = [
    "certops_observed_revocation",
    "store_issuance_explicit_renewal_consent",
    "certops_acme_store_enrollment_identity",
    "certops_adcs_expected_identity_receipts",
    "certops_windows_iis_consent",
  ];
  const previewBase = rows.filter((row) => row.version < 112);
  const previewTail = rows.filter((row) => row.version >= 112);
  let previewLength = 0;
  while (previewLength < observedPreviewTail.length &&
    previewTail[previewLength]?.version === 112 + previewLength &&
    previewTail[previewLength]?.name === observedPreviewTail[previewLength]) previewLength++;
  const appendedRows = previewTail.slice(previewLength);
  const previewNames = new Set([...previewBase.map((row) => row.name), ...observedPreviewTail.slice(0, previewLength)]);
  const expectedAppend = extensions.filter((entry) => !previewNames.has(entry.name));
  const recognizedObservedPreview = previewLength > 0 &&
    previewBase.every((row) => row.version === byName.get(row.name).version) &&
    appendedRows.every((row, index) => row.version === 112 + previewLength + index && row.name === expectedAppend[index]?.name);
  if (!contiguous) {
    const base = [
      "certops_installed_file_distribution",
      "auto_sync_provider_stats",
      "auto_sync_run_metrics",
      "auto_sync_metric_labels",
    ];
    if (
      !base.every((name, index) =>
        rows.some((row) => row.version === 78 + index && row.name === name),
      ) ||
      (rows.some((row) => row.version !== byName.get(row.name).version) && !recognizedPriorMcp && !recognizedRetirementPreview && !recognizedObservedPreview)
    )
      throw new Error("Unsupported Core migration history: noncanonical gap");
  }

  let contiguousOrder = null;
  if (contiguous && rows.length && !recognizedRetirementPreview) {
    const I = "certops_installed_file_distribution",
      S = "auto_sync_provider_stats",
      R = "auto_sync_run_metrics",
      L = "auto_sync_metric_labels";
    const P = "certops_material_providers",
      C = "recipient_channel_verification",
      D = "weekly_digest_recipient_claim_token",
      PD = "pagerduty_incident_lifecycle";
    const lifecycle = [
      "certops_distribution_lifecycle",
      "certops_distribution_incident_delivery",
      "certops_stable_consumer_discovery",
      "certops_material_cleanup",
      "certops_consumer_verification_failures",
    ];
    const Z = "certops_distribution_resolution_delivery";
    const seeds = [
      [],
      // Applied MCP preview through 85 retains its ledger and appends other features.
      [I, S, R, L, "auto_sync_system_metrics", "operator_connections", "operator_enrollment_grants", "operator_action_requests"],
      [I, S, R, P, L, "auto_sync_system_metrics", C, D, PD, "pagerduty_resolution_reason", "operator_connections", "operator_enrollment_grants", "operator_action_requests"],
      [I, S, R, L, "auto_sync_system_metrics", "operator_connections", "operator_enrollment_grants", "operator_action_requests", P, C, D, PD, "pagerduty_resolution_reason"],
      [P],
      [I, P],
      [I, S, R, P],
      [I, S, R, L, P],
      [I, S, R, C, D],
      [I, S, R, L, C, D],
      [I, PD],
      [I, S, R, PD],
      [I, S, R, ...lifecycle],
      [I, S, R, L, ...lifecycle],
      [I, S, R, P, C, D, PD, ...lifecycle],
      [I, S, R, L, ...lifecycle, P, C, D, PD, Z],
      // The provider preview can receive recipient and PagerDuty schemas before
      // lifecycle is integrated. Its committed append order remains immutable.
      [I, S, R, P, L, "auto_sync_system_metrics", C, D, PD, "pagerduty_resolution_reason"],
      [I, S, R, P, L, "auto_sync_system_metrics", C, D, PD, "pagerduty_resolution_reason", "pagerduty_operator_actions", "remove_pagerduty_rest_lookup"],
      [I, S, R, P, L, "auto_sync_system_metrics", C, D, PD, "pagerduty_resolution_reason", "pagerduty_operator_actions", "remove_pagerduty_rest_lookup",
        "certops_manual_rollout_authority", "store_issuance_explicit_renewal_consent", "certops_acme_store_enrollment_identity", "certops_adcs_expected_identity_receipts"],
    ];
    const laterCompanions = new Set([...lifecycle, Z, "certops_consumer_staging", "certops_review_authority_epochs"]);
    const integratedSeeds = seeds.flatMap((seed) =>
      [mcpAppendNames, mcpAppendNames.slice(2),
        [...mcpAppendNames.slice(2, 5), ...mcpAppendNames.slice(0, 2), ...mcpAppendNames.slice(5)],
      ].flatMap((append) =>
        Array.from({ length: append.length + 1 }, (_entry, length) =>
          [...seed, ...append.slice(0, length).filter((name) => !seed.includes(name))],
        ),
      ),
    );
    const recognized = integratedSeeds.some((seed) => {
      const remaining = extensions.map((entry) => entry.name).filter((name) => !seed.includes(name));
      const prefix = seed.filter((name) => byName.has(name));
      const ordinary = [...prefix, ...remaining];
      const independent = remaining.filter((name) => !laterCompanions.has(name));
      const companions = remaining.filter((name) => laterCompanions.has(name));
      // A preview may have applied only part of an independent tail before
      // the reserved companions arrived. Preserve that exact append order.
      const companionOrders = Array.from({ length: independent.length + 1 }, (_entry, cut) =>
        [...prefix, ...independent.slice(0, cut), ...companions, ...independent.slice(cut)],
      );
      return [ordinary, ...companionOrders].some((names) => {
        const applied = new Set(rows.map((row) => row.name));
        const lastApplied = Math.max(-1, ...names.map((name, index) => applied.has(name) ? index : -1));
        const skipped = names.slice(0, lastApplied + 1).filter((name) => !applied.has(name));
        const orderedApplied = names.filter((name) => applied.has(name));
        const matches = skipped.every((name) => name.startsWith("operator_") || ["certops_issuance_job_identity", "certops_issuance_identity_transfer"].includes(name)) &&
          rows.every((row, index) => row.name === orderedApplied[index]);
        if (matches) contiguousOrder = [...orderedApplied, ...names.filter((name) => !applied.has(name))];
        return matches;
      });
    });
    if (!recognized)
      throw new Error(
        "Unsupported Core migration history: unrecognized preview order",
      );
  }
  const dependencies = {
    recipient_member_verification: ["recipient_channel_verification"],
    certops_issuance_identity_transfer: ["certops_issuance_job_identity"],
    certops_issuance_job_identity: ["operator_issuance"],
    operator_issuance: ["operator_action_requests"],
    operator_connection_lifetimes: ["operator_connections", "operator_enrollment_grants", "operator_oauth"],
    operator_inventory: ["operator_connections"],
    operator_oauth_retention: ["operator_oauth"],
    operator_oauth: ["operator_connections"],
    operator_enrollment_grants: ["operator_connections"],
    operator_action_requests: ["operator_connections"],
    auto_sync_run_metrics: ["auto_sync_provider_stats"],
    auto_sync_metric_labels: ["auto_sync_run_metrics"],
    auto_sync_system_metrics: ["auto_sync_metric_labels"],
    auto_sync_owner_username: ["auto_sync_metric_labels"],
    certops_distribution_lifecycle: ["certops_installed_file_distribution"],
    certops_distribution_incident_delivery: ["certops_distribution_lifecycle"],
    certops_material_cleanup: ["certops_distribution_lifecycle"],
    certops_consumer_verification_failures: ["certops_material_cleanup"],
    weekly_digest_recipient_claim_token: ["recipient_channel_verification"],
    certops_distribution_resolution_delivery: [
      "certops_distribution_incident_delivery",
    ],
    certops_consumer_staging: ["certops_distribution_lifecycle"],
    certops_review_authority_epochs: ["certops_distribution_lifecycle"],
  };
  const seen = new Set();
  for (const row of rows) {
    if ((dependencies[row.name] || []).some((name) => !seen.has(name)))
      throw new Error(
        "Unsupported Core migration history: incomplete dependency " + row.name,
      );
    seen.add(row.name);
  }
  const assigned = new Map(rows.map((row) => [row.name, row.version]));
  const used = new Set(rows.map((row) => row.version));
  const preview = rows.some(
    (row) => row.version !== byName.get(row.name).version,
  );
  let next =
    (preview
      ? Math.max(77, ...rows.map((row) => row.version))
      : Math.max(
          77,
          ...extensions.map((entry) => entry.version),
          ...rows.map((row) => row.version),
        )) + 1;
  const reviewedOrder = recognizedPriorMcp ? priorOrder : contiguousOrder;
  const executionOrder = reviewedOrder ? [...extensions].sort((a, b) => reviewedOrder.indexOf(a.name) - reviewedOrder.indexOf(b.name)) : extensions;
  for (const entry of executionOrder) {
    if (assigned.has(entry.name)) continue;
    const dependencyFloor = Math.max(
      77,
      ...(dependencies[entry.name] || []).map(
        (name) => assigned.get(name) || 77,
      ),
    );
    const version =
      preview || used.has(entry.version) || entry.version <= dependencyFloor
        ? ((next = Math.max(next, dependencyFloor + 1)), next++)
        : entry.version;
    assigned.set(entry.name, version);
    used.add(version);
  }
  const distributionFirst = order[0] === DISTRIBUTION;
  const replacements = new Map(
    order.map((name, offset) => {
      const migration = migrations.find((entry) => entry.name === name);
      const sql =
        distributionFirst && name === ENROLLMENT
          ? migration.sql.replace(
              "'continue-enrollment', 'adcs-preflight'",
              "'continue-enrollment', 'adcs-preflight', 'deploy-from-store'",
            )
          : distributionFirst && name === DISTRIBUTION
            ? migration.sql.replace(
                "'continue-enrollment','adcs-preflight'",
                "'continue-enrollment'",
              )
            : migration.sql;
      return [name, { ...migration, version: 70 + offset, sql }];
    }),
  );
  return migrations
    .map(
      (entry) =>
        replacements.get(entry.name) ||
        (assigned.has(entry.name)
          ? { ...entry, version: assigned.get(entry.name) }
          : entry),
    )
    .sort((a, b) => a.version - b.version);
}
module.exports = { composeMigrations };
