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
      rows.some((row) => row.version !== byName.get(row.name).version)
    )
      throw new Error("Unsupported Core migration history: noncanonical gap");
  }

  if (contiguous && rows.length) {
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
      [I, S, R, P, L, "auto_sync_system_metrics", C, D, PD, "pagerduty_resolution_reason", "pagerduty_operator_actions", "remove_pagerduty_rest_lookup", "agent_credential_rotations"],
    ];
    const laterCompanions = new Set([...lifecycle, Z, "certops_consumer_staging", "certops_review_authority_epochs"]);
    const recognized = seeds.some((seed) => {
      const remaining = extensions.map((entry) => entry.name).filter((name) => !seed.includes(name));
      const ordinary = [...seed.filter((name) => byName.has(name)), ...remaining];
      // A previously supported preview can receive the independent manual
      // authority fix before the reserved lifecycle companions are installed.
      // Preserve that recorded append order when the companions arrive later.
      const manualFirst = [...seed.filter((name) => byName.has(name)),
        ...remaining.filter((name) => !laterCompanions.has(name)),
        ...remaining.filter((name) => laterCompanions.has(name))];
      return [ordinary, manualFirst].some((names) => rows.every((row, index) => row.name === names[index]));
    });
    if (!recognized)
      throw new Error(
        "Unsupported Core migration history: unrecognized preview order",
      );
  }
  const dependencies = {
    auto_sync_run_metrics: ["auto_sync_provider_stats"],
    auto_sync_metric_labels: ["auto_sync_run_metrics"],
    auto_sync_system_metrics: ["auto_sync_metric_labels"],
    certops_distribution_lifecycle: ["certops_installed_file_distribution"],
    certops_distribution_incident_delivery: ["certops_distribution_lifecycle"],
    certops_material_cleanup: ["certops_distribution_lifecycle"],
    certops_consumer_verification_failures: ["certops_material_cleanup"],
    weekly_digest_recipient_claim_token: ["recipient_channel_verification"],
    certops_distribution_resolution_delivery: [
      "certops_distribution_incident_delivery",
    ],
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
  for (const entry of extensions) {
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
