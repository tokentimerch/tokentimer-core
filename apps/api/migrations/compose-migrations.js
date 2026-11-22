"use strict";

// Only unapplied migrations move. Never rename or renumber an applied row.
const ENROLLMENT = "certops_certificate_enrollments";
const EVIDENCE = "certops_adcs_evidence_types";
const ISSUER = "certops_profile_issuer";
const ALERT = "certops_job_alert_context";
const DISTRIBUTION = "certops_material_distribution";
const REVIEW = "certops_distribution_review";
const TRANSFER = "certops_distribution_transfer";
const OBSERVED_REVOCATION = "certops_observed_revocation";
const ADCS_RECEIPT_DEADLINE = "certops_adcs_receipt_deadline";
const ADCS_PREFLIGHT_INDEX = "certops_adcs_preflight_lookup_index";
const storePreviewMigrations = [
  "store_issuance_explicit_renewal_consent",
  "certops_acme_store_enrollment_identity",
  "certops_adcs_expected_identity_receipts",
  ADCS_RECEIPT_DEADLINE,
];
const iisPreviewMigrations = [
  "certops_windows_iis_consent",
  "certops_material_adcs_operation_union",
  "certops_iis_absence_proofs",
  "certops_enrollment_jobs_index",
];
const storeAndIisFeatures = new Set([
  ...storePreviewMigrations, ...iisPreviewMigrations, ADCS_PREFLIGHT_INDEX,
]);
// Exact version/name pairs from the integrated Windows Store/IIS preview.
const legacyCombinedTail = [OBSERVED_REVOCATION, ...storePreviewMigrations.slice(0, 3), ...iisPreviewMigrations];
const legacyCombinedVersions = new Map(legacyCombinedTail.map((name, index) => [name, 115 + index]));
// These independent, unapplied schemas may arrive after an observation preview.
const independentFeatureNames = new Set(Object.entries(require("./migration-reservations.cjs").reservations)
  .filter(([version]) => Number(version) >= 115 && Number(version) <= 126 && Number(version) !== 122)
  .map(([, name]) => name));
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

function reviewedFeatureOrders(names, rows) {
  const orders = [names];
  if (!names.includes(OBSERVED_REVOCATION) || !names.some((name) =>
    name !== OBSERVED_REVOCATION && legacyCombinedVersions.has(name))) return orders;

  // The combined preview registered observation before unreleased Store/IIS
  // features. Independent previews could have installed either group first.
  const legacy = names.filter((name) => name !== OBSERVED_REVOCATION);
  const firstStore = legacy.findIndex((name) => legacyCombinedVersions.has(name));
  legacy.splice(firstStore, 0, OBSERVED_REVOCATION);
  orders.push(legacy);
  const previousOrders = [
    names.filter((name) => name === OBSERVED_REVOCATION || !legacyCombinedVersions.has(name)),
    names.filter((name) => name !== OBSERVED_REVOCATION),
    legacy,
  ];
  if (rows.some((row) => row.name === ADCS_RECEIPT_DEADLINE)) {
    // Earlier Store previews applied the receipt deadline before these independent definitions.
    previousOrders.push(
      names.filter((name) => name !== OBSERVED_REVOCATION && name !== ADCS_PREFLIGHT_INDEX && !iisPreviewMigrations.includes(name) &&
        name !== "agent_credential_rotations" && name !== "agent_credential_rotation_ack"),
      names.filter((name) => name !== "agent_credential_rotations" && name !== "agent_credential_rotation_ack"),
      names.filter((name) => name !== ADCS_PREFLIGHT_INDEX && name !== "agent_credential_rotations" && name !== "agent_credential_rotation_ack"),
    );
  }
  for (const oldOrder of previousOrders) {
    const mismatch = rows.findIndex((row, index) => row.name !== oldOrder[index]);
    const applied = oldOrder.slice(0, mismatch < 0 ? rows.length : mismatch);
    if (applied.some((name) => legacyCombinedVersions.has(name))) {
      orders.push([...applied, ...names.filter((name) => !applied.includes(name))]);
    }
  }
  return orders;
}

function assertUnambiguousRotationHistory(recorded = [], registry = []) {
  const canonical = new Map(registry.map(({ version, name }) => [version, name]));
  const earlierPreview = recorded.some((row) => row.version >= 70 && row.version < 109 &&
    canonical.has(row.version) && canonical.get(row.version) !== row.name);
  if (!earlierPreview && recorded.some((row) => [109, 110].includes(row.version) &&
      ["agent_credential_rotations", "agent_credential_rotation_ack"].includes(row.name))) {
    throw new Error("Unsupported ambiguous agent credential rotation preview history");
  }
}

function composeMigrations(migrations, recorded = []) {
  assertUnambiguousRotationHistory(recorded, migrations);
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
  // A reviewed #714 preview may have applied its index before PagerDuty
  // recovery and the reserved #614 tails. Keep that exact append order.
  const afterPreflightIndex = (names) => {
    const tails = new Set(["distribution_pagerduty_recovery", "agent_credential_rotations", "agent_credential_rotation_ack"]);
    const retained = names.filter(name => !tails.has(name));
    const position = retained.indexOf(ADCS_PREFLIGHT_INDEX);
    return position < 0 ? names : [...retained.slice(0,position+1), ...names.filter(name=>tails.has(name)), ...retained.slice(position+1)];
  };
  // The expiration preview applied its schema immediately after PagerDuty recovery.
  // Recognize that ordering when the ledger already contains the preview identity.
  const expiration = byName.get("auto_sync_creation_expiration");
  const recordedExpiration = rows.find((row) => row.name === expiration?.name);
  const legacyExpiration = recordedExpiration?.version === 115 &&
    rows.some((row) => row.version === 114 && row.name === "distribution_pagerduty_recovery") &&
    rows.every((row) => row.name !== OBSERVED_REVOCATION || row.version > recordedExpiration.version);
  const reviewExtensions = legacyExpiration ? [
    ...extensions.filter((entry) => entry.version <= 114),
    expiration,
    ...extensions.filter((entry) => entry.version > 114 && entry !== expiration),
  ] : extensions;
  // Validate the already-applied preview with the previous registry before
  // appending main's newer migrations under unoccupied identities.
  const hasRetirementPreview = byName.get("certops_retirement_dossiers")?.version !== 109 &&
    rows.some((row) => row.version === 109 && row.name === "certops_retirement_dossiers");
  let recognizedRetirementPreview = false;
  let retirementOrder = null;
  if (hasRetirementPreview) {
    const oldRegistry = migrations.filter((entry) => !["certops_period_creator_delete", "recipient_member_verification", "auto_sync_owner_username"].includes(entry.name))
      .map((entry) => entry.name === "certops_retirement_dossiers" ? { ...entry, version: 109 } : entry);
    const oldRows = recorded.filter((row) => row.version <= 109);
    const oldComposed = composeMigrations(oldRegistry, oldRows);
    const oldIdentity = new Map(oldComposed.map((entry) => [entry.name, entry.version]));
    const appendNames = reviewExtensions
      .filter((entry) => entry.version >= 109 && entry.name !== "certops_retirement_dossiers")
      .map((entry) => entry.name);
    const appendedRows = rows.filter((row) => row.version > 109);
    // Preserve compact Store-only preview ledgers when adding the IIS definitions.
    const storeTail = storePreviewMigrations.filter((name) => byName.has(name));
    const baseAppend = ["certops_period_creator_delete", "recipient_member_verification", "auto_sync_owner_username", "certops_material_reconciliation"].filter(name => byName.has(name));
    const recovery = byName.has("distribution_pagerduty_recovery") ? ["distribution_pagerduty_recovery"] : [];
    const observed = byName.has(OBSERVED_REVOCATION) ? [OBSERVED_REVOCATION] : [];
    const storeOrders = [
      [...baseAppend, ...recovery, ...observed, ...storeTail],
      [...baseAppend, ...recovery, ...storeTail.slice(0, 3), ...observed, ...storeTail.slice(3)],
      ...Array.from({ length: storeTail.length + 1 }, (_, count) =>
        [...baseAppend, ...storeTail.slice(0, count), ...recovery, ...storeTail.slice(count), ...observed]),
    ];
    const storePrefixes = storeOrders.flatMap((order) => Array.from({ length: order.length + 1 }, (_, length) => {
      const applied = order.slice(0, length);
      return [...applied, ...appendNames.filter((name) => !applied.includes(name))];
    }));
    const rotations = ["agent_credential_rotations", "agent_credential_rotation_ack"].filter((name) => byName.has(name));
    const store = storeTail;
    const canonicalTail = reviewExtensions.filter((entry) => entry.version >= 114).map((entry) => entry.name);
    const otherTail = canonicalTail.filter((name) => ![...store, ...recovery, ...rotations].includes(name));
    // Keep the canonical default. Recognize only ordered Store prefixes and
    // the intact rotation pair around recovery, then append newer definitions.
    const appendOrders = [[...baseAppend, ...canonicalTail], ...storePrefixes];
    const revocation = otherTail.filter(name => name === "certops_observed_revocation");
    const remainingTail = otherTail.filter(name => !revocation.includes(name));
    for (let count = 0; count <= store.length; count++) {
      const tail = [...store.slice(0, count), ...recovery, ...store.slice(count)];
      for (let cut = 0; cut <= tail.length; cut++) {
        appendOrders.push([...baseAppend, ...tail.slice(0, cut), ...rotations, ...tail.slice(cut), ...otherTail]);
      }
      // Store previews could have been extended by the canonical remainder.
      appendOrders.push([...baseAppend, ...store.slice(0, count),
        ...canonicalTail.filter(name => !store.slice(0, count).includes(name))]);
    }
    if (revocation.length && recovery.length) {
      appendOrders.push([...baseAppend, ...recovery, ...revocation, ...store, ...rotations, ...remainingTail]);
    }
    // The rotation preview could finish before Store and IIS were present.
    const beforeStore = canonicalTail.filter(name =>
      !store.includes(name) && !iisPreviewMigrations.includes(name) &&
      name !== ADCS_PREFLIGHT_INDEX && !rotations.includes(name) && !recovery.includes(name));
    for (const prefix of [
      [...baseAppend, ...rotations, ...recovery, ...beforeStore],
      [...baseAppend, ...recovery, ...rotations, ...beforeStore],
      [...baseAppend, ...recovery, ...revocation, ...rotations,
        ...beforeStore.filter(name => !revocation.includes(name))],
    ]) {
      for (let length = 0; length <= prefix.length; length++) {
        const applied = prefix.slice(0, length);
        appendOrders.push([...applied, ...appendNames.filter(name => !applied.includes(name))]);
      }
    }
    const reviewed = appendOrders
      .flatMap(names => reviewedFeatureOrders(names, appendedRows))
      .flatMap(names => [names, afterPreflightIndex(names)]);
    reviewed.sort((left, right) => {
      for (let index = 0; index < left.length; index++) {
        const difference = byName.get(left[index]).version - byName.get(right[index]).version;
        if (difference) return difference;
      }
      return 0;
    });
    const rotationAwaitingAck = appendedRows.at(-1)?.name === "agent_credential_rotations" &&
      rotations.includes("agent_credential_rotation_ack");
    const appended = reviewed.find((names) =>
      (!rotationAwaitingAck || names[appendedRows.length] === "agent_credential_rotation_ack") &&
      appendedRows.every((row, index) => row.version === 110 + index && row.name === names[index]));
    recognizedRetirementPreview = oldRows.every((row) => row.version < 70 || oldIdentity.get(row.name) === row.version) &&
      Boolean(appended);
    if (!recognizedRetirementPreview) throw new Error("Unsupported Core retirement preview migration history");
    retirementOrder = [...extensions.map((entry) => entry.name).filter((name) => !appended.includes(name)), ...appended];
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
        const remaining = reviewExtensions.map((entry) => entry.name).filter((name) => !priorMcpNames.includes(name) && !appliedAppend.includes(name));
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
        // A prior MCP preview could have applied agent rotation before the
        // retirement features existed. Preserve that reviewed append order.
        const laterRetirement = new Set(["certops_retirement_dossiers", "certops_material_reconciliation",
          "distribution_pagerduty_recovery", "certops_observed_revocation"]);
        const beforeRetirement = [...independent.filter((name) => !laterRetirement.has(name)), ...independent.filter((name) => laterRetirement.has(name))];
        const beforeStore = beforeRetirement.filter((name) => !storeAndIisFeatures.has(name));
        const afterStore = beforeRetirement.filter((name) => storeAndIisFeatures.has(name));
        const historicalOrders = [independent, beforeRetirement].flatMap((ordered) =>
          Array.from({ length: ordered.length + 1 }, (_entry, cut) =>
            [...ordered.slice(0, cut), ...companions, ...ordered.slice(cut)]),
        );
        const preStoreOrders = [beforeStore, beforeStore.filter(name => name !== expiration?.name)]
          .flatMap((earlier) => Array.from({ length: earlier.length + 1 }, (_, cut) => {
            const omitted = beforeStore.filter(name => !earlier.includes(name));
            return [...earlier.slice(0, cut), ...companions, ...earlier.slice(cut), ...afterStore, ...omitted];
          }));
        for (const tail of [[...independent, ...companions], remaining, ...historicalOrders, ...preStoreOrders]) {
          priorOrder = reviewedFeatureOrders([...priorMcpNames, ...appliedAppend, ...tail], rows)
            .find((names) => rows.every((row, index) =>
              row.name === names[index] && row.version === (priorMcpVersions[index] ?? 97 + index - priorMcpVersions.length))) || null;
          if (priorOrder) break;
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
    const names = [...draftNames, ...reviewExtensions.map((entry) => entry.name).filter((name) => !draftNames.includes(name))];
    priorOrder = reviewedFeatureOrders(names, rows).find((candidate) => rows.every((row, index) =>
      row.name === candidate[index] && row.version === (draftVersions[index] ?? 104 + index - draftVersions.length))) || null;
  }
  const recognizedPriorMcp = priorOrder !== null;
  // An earlier preview applied both credential-rotation migrations before
  // later reservations were integrated. Accept only its complete ledger and
  // prefixes of the exact append order produced when upgrading it.
  const previewVersions = [...Array.from({ length: 16 }, (_, i) => 70 + i),
    92, 93, 94, 95, ...Array.from({ length: 14 }, (_, i) => 98 + i)];
  const previewPrefix = previewVersions.map((version) => migrations.find((entry) => entry.version === version));
  const previewComplete = previewPrefix.every(Boolean);
  const oldRotation = [
    { version: 112, name: "agent_credential_rotations" },
    { version: 113, name: "agent_credential_rotation_ack" },
  ];
  const legacy = [...previewPrefix.filter(Boolean), ...oldRotation];
  const legacyNames = new Set(legacy.map((entry) => entry.name));
  const append = extensions.filter((entry) => !legacyNames.has(entry.name))
    .map((entry, index) => ({ version: 114 + index, name: entry.name }));
  const expected = [...legacy, ...append];
  const recognizedRotationPreview = previewComplete && tail.length >= legacy.length &&
    tail.length <= expected.length && tail.every((row, index) =>
      row.version === expected[index].version && row.name === expected[index].name);
  // The initial rotation preview used version 99 before the MCP tail existed.
  // Preserve that identity and accept only the deterministic upgrade prefixes.
  const rotation99Versions = [...Array.from({ length: 16 }, (_, i) => 70 + i), 92, 93, 94, 95, 98];
  const rotation99Base = rotation99Versions.map((version) => migrations.find((entry) => entry.version === version));
  const rotation99Prefix = [...rotation99Base, { version: 99, name: "agent_credential_rotations" }];
  const rotation99Names = new Set(rotation99Prefix.filter(Boolean).map((entry) => entry.name));
  const rotation99Pending = extensions.filter((entry) => !rotation99Names.has(entry.name));
  const recognizedRotation99 = rotation99Base.every(Boolean) && tail.length >= rotation99Prefix.length &&
    rotation99Prefix.every((entry, index) => tail[index].version === entry.version && tail[index].name === entry.name) &&
    tail.slice(rotation99Prefix.length).every((row, index) =>
      row.version === 100 + index && row.name === rotation99Pending[index]?.name);
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
  const extensionNames = extensions.map((entry) => entry.name);
  const recognizedObservedPreview = previewLength > 0 &&
    previewBase.every((row) => row.version === byName.get(row.name).version) &&
    reviewedFeatureOrders(extensionNames, rows).some((names) => {
      const expectedAppend = names.filter((name) => !previewNames.has(name));
      return appendedRows.every((row, index) =>
        row.version === 112 + previewLength + index && row.name === expectedAppend[index]);
    });

  // Accept the exact old combined registration, followed only by a prefix
  // of the migrations that our runner would append to that ledger.
  const legacyHead = rows.findIndex((row) =>
    row.version !== (legacyCombinedVersions.get(row.name) ?? byName.get(row.name).version));
  const legacyPrefix = legacyHead < 0 ? rows : rows.slice(0, legacyHead);
  const legacyApplied = new Set(legacyPrefix.map((row) => row.name));
  const legacyRemaining = extensionNames.filter((name) => !legacyApplied.has(name));
  const recognizedLegacyCombined = legacyPrefix.some((row) =>
    row.version !== byName.get(row.name).version) &&
    rows.slice(legacyPrefix.length).every((row, index) =>
      row.version === legacyPrefix.at(-1).version + 1 + index && row.name === legacyRemaining[index]);
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
      (rows.some((row) => row.version !== byName.get(row.name).version) &&
        !recognizedPriorMcp && !recognizedRetirementPreview && !recognizedObservedPreview && !recognizedLegacyCombined &&
        !recognizedRotationPreview && !recognizedRotation99)
    )
      throw new Error("Unsupported Core migration history: noncanonical gap");
  }

  // Reviewed candidates applied rotation at 114/115 before recovery, or at
  // 115/116 after recovery. Rebuild those exact plans before adding reservations.
  let contiguousOrder = null;
  const oldRotationRow = rows.find((row) => [114, 115].includes(row.version) && row.name === "agent_credential_rotations");
  const newIndependentNames = new Set([
    "certops_observed_revocation", "store_issuance_explicit_renewal_consent",
    "certops_acme_store_enrollment_identity", "certops_adcs_expected_identity_receipts",
    "certops_windows_iis_consent", "certops_material_adcs_operation_union",
    "certops_iis_absence_proofs", "certops_enrollment_jobs_index", "distribution_pagerduty_recovery",
    ADCS_PREFLIGHT_INDEX, ADCS_RECEIPT_DEADLINE,
  ]);
  if (contiguous && !recognizedRetirementPreview && !recognizedObservedPreview && !recognizedLegacyCombined && oldRotationRow && migrations.some((entry) => newIndependentNames.has(entry.name))) {
    const rotationVersion = oldRotationRow.version;
    const excluded = new Set(newIndependentNames);
    if (rotationVersion === 115) excluded.delete("distribution_pagerduty_recovery");
    const legacyRegistry = migrations.filter((entry) => !excluded.has(entry.name))
      .map((entry) => entry.name === "agent_credential_rotations" ? { ...entry, version: rotationVersion }
        : entry.name === "agent_credential_rotation_ack" ? { ...entry, version: rotationVersion + 1 } : entry);
    const legacyPlan = composeMigrations(legacyRegistry, featureHistory.filter((row) => row.version < rotationVersion));
    const oldTail = legacyPlan.filter((entry) => entry.version >= 78 && entry.version <= rotationVersion + 1);
    const appliedNames = new Set(oldTail.map((entry) => entry.name));
    const legacyNames = new Set(legacyPlan.map((entry) => entry.name));
    const pending = extensions.filter((entry) => !appliedNames.has(entry.name));
    const legacyPending = [
      ...legacyPlan.filter((entry) => entry.version > rotationVersion + 1),
      ...extensions.filter((entry) => !legacyNames.has(entry.name)),
    ];
    for (const suffix of [pending, legacyPending]) {
      const appended = suffix.map((entry, index) => ({ ...entry, version: rotationVersion + 2 + index }));
      const expected = [...oldTail, ...appended];
      if (rows.length <= expected.length && rows.every((row, index) =>
        row.version === expected[index].version && row.name === expected[index].name)) {
        contiguousOrder = expected.map((entry) => entry.name);
        break;
      }
    }
  }
  if (contiguous && rows.length && !recognizedRetirementPreview && !recognizedObservedPreview && !recognizedLegacyCombined && !contiguousOrder) {
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
      [I, S, R, P, L, "auto_sync_system_metrics", C, D, PD, "pagerduty_resolution_reason", "pagerduty_operator_actions", "remove_pagerduty_rest_lookup", "agent_credential_rotations"],
      [I, S, R, P, L, "auto_sync_system_metrics", C, D, PD, "pagerduty_resolution_reason", "pagerduty_operator_actions", "remove_pagerduty_rest_lookup", "agent_credential_rotations", "agent_credential_rotation_ack"],
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
      const remaining = reviewExtensions.map((entry) => entry.name).filter((name) => !seed.includes(name));
      const prefix = seed.filter((name) => byName.has(name));
      const ordinary = [...prefix, ...remaining];
      const independent = remaining.filter((name) => !laterCompanions.has(name));
      const companions = remaining.filter((name) => laterCompanions.has(name));
      // A preview may have applied only part of an independent tail before
      // the reserved companions arrived. Preserve that exact append order.
      const companionOrders = Array.from({ length: independent.length + 1 }, (_entry, cut) =>
        [...prefix, ...independent.slice(0, cut), ...companions, ...independent.slice(cut)],
      );
      // A previously applied observation preview can receive the independent
      // Store/IIS/rotation definitions later. Preserve its complete prefix.
      const reviewedOrders = [ordinary, ...companionOrders];
      const independentAppends = reviewedOrders.map((names) => [
        ...names.filter((name) => !independentFeatureNames.has(name)),
        ...names.filter((name) => independentFeatureNames.has(name)),
      ]);
      // The composed rotation/revocation preview could exist before the
      // reserved Store and IIS schemas became available.
      const deferred = new Set(Object.entries(require("./migration-reservations.cjs").reservations)
        .filter(([version]) => (Number(version) >= 115 && Number(version) <= 121) || Number(version) === 126)
        .map(([, name]) => name));
      const deferredAppends = reviewedOrders.map(names => [
        ...names.filter(name => !deferred.has(name)), ...names.filter(name => deferred.has(name)),
      ]);
      return [...reviewedOrders, ...independentAppends, ...deferredAppends]
        .flatMap(names => reviewedFeatureOrders(names, rows))
        .flatMap(names => [names, afterPreflightIndex(names)]).some((names) => {
        const applied = new Set(rows.map((row) => row.name));
        const lastApplied = Math.max(-1, ...names.map((name, index) => applied.has(name) ? index : -1));
        const skipped = names.slice(0, lastApplied + 1).filter((name) => !applied.has(name));
        const orderedApplied = names.filter((name) => applied.has(name));
        const matches = skipped.every((name) => independentFeatureNames.has(name) || name.startsWith("operator_") || ["certops_issuance_job_identity", "certops_issuance_identity_transfer"].includes(name)) &&
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
    [ADCS_RECEIPT_DEADLINE]: ["certops_adcs_expected_identity_receipts"],
    agent_credential_rotation_ack: ["agent_credential_rotations"],
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
    auto_sync_creation_expiration: ["auto_sync_owner_username"],
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
  const reviewedOrder = recognizedPriorMcp ? priorOrder : retirementOrder || contiguousOrder;
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
module.exports = { composeMigrations, assertUnambiguousRotationHistory };
