// Which items the guide created and which contact groups are attached to
// them. Pure rules for the recipients step, so they are testable without React.

import { existingAssetStepIds } from './assetRefs.js';
import { normalizeContactGroupIds } from '../../utils/contactGroupAssignment.js';
import {
  agentOnPlatform,
  candidateAgents,
  effectiveInfrastructure,
} from './certopsMatrix.js';
import { scopeCertops } from './certopsScope.js';
import { scopeAdcs } from './adcsModel.js';

// The step reads every item once and writes one by one, so it stays bounded.
export const MAX_ITEMS = 50;
// Certificates an agent found are listed up to this many; the server caps its
// list at the same number.
export const MAX_OBSERVED = MAX_ITEMS;

// The goals whose items can carry a group from this step: what the guide
// creates (websites, assets, issued certificates) and what the session's agent
// or controller reports.
const TICK_GOALS = new Set([
  'monitor_https',
  'track_asset',
  'certops_observe',
  'certops_automate',
  'certops_adcs',
  'certops_vault',
]);
export const canTickGoal = goal => TICK_GOALS.has(goal);

// Which certificates a CertOps goal made or found: the issue job, the publish
// job, the AD CS renewal profile's certificates and enrollments, or the
// agent's reports, as the summary lists them. AD CS has its item as soon as a
// profile is attached to a certificate, long before the first enrollment.
const CERTIFICATE_SOURCES = {
  certops_observe: ['observed'],
  certops_automate: ['issue'],
  certops_vault: ['publish'],
  certops_adcs: ['profile', 'enrollment'],
};
export const isCertificateGoal = goal => goal in CERTIFICATE_SOURCES;

// Goals with no item of their own: they only confirm the workspace default
// group and say why.
const DEFAULT_ONLY_GOALS = new Set(['alerting']);
export const isDefaultOnlyGoal = goal => DEFAULT_ONLY_GOALS.has(goal);

const text = v => String(v);
const unique = list => Array.from(new Set(list.map(text)));

/**
 * The certificates this pick's agent (or controller) reported. An agent that
 * was already in the workspace counts only when the operator chose it, and
 * only an agent on the pick's exact system counts, as for the install step.
 * `truncated` means the server listed fewer than it found.
 */
export function observedForPick(certops, saved = {}) {
  const reported =
    certops && certops !== 'unknown' ? certops.observedCertificates : null;
  const items = Array.isArray(reported?.items) ? reported.items : [];
  const infra = effectiveInfrastructure('observe', saved.infrastructure);
  let found;
  if (infra === 'kubernetes') {
    found = items.filter(
      c =>
        c.source === 'cert_manager' &&
        (!saved.clusterId || c.clusterId === saved.clusterId)
    );
  } else {
    const agents = Array.isArray(certops?.agents?.items)
      ? certops.agents.items
      : [];
    const mine = new Set(
      candidateAgents(agents, saved.chosenAgentId)
        .filter(a => agentOnPlatform(a, infra))
        .map(a => a.id)
    );
    found = items.filter(
      c => c.source !== 'cert_manager' && mine.has(c.agentId)
    );
  }
  return { items: found, truncated: (reported?.total || 0) > items.length };
}

/**
 * The tokens this guide created, split into websites, assets and CertOps
 * certificates, plus why ticks cannot be offered when the set cannot be
 * trusted. operationRefs tokenIds holds website certificates and asset-step
 * ids together; assetTokenIds (newer sessions) or the session's monitors tell
 * them apart. CertOps certificates come from the summary, which resolves the
 * jobs and enrollments of this session to their inventory tokens.
 * noToken counts items that exist but have no token yet to carry a group.
 * @returns {{ websites: string[], assets: string[], certificates: string[], noToken: number, blocked: string|null }}
 */
export function planSessionItems({
  goal,
  refs = {},
  summary = null,
  progress = null,
}) {
  if (!canTickGoal(goal)) {
    return {
      websites: [],
      assets: [],
      certificates: [],
      noToken: 0,
      blocked: null,
    };
  }
  if (goal === 'certops_observe') {
    const saved = scopeCertops(progress?.certops, 'observe');
    const { items: found, truncated } = observedForPick(
      summary?.certops,
      saved
    );
    return {
      websites: [],
      assets: [],
      certificates: unique(
        found.filter(c => c.tokenId != null).map(c => c.tokenId)
      ),
      noToken: found.filter(c => c.tokenId == null).length,
      blocked: truncated ? 'capObserved' : null,
    };
  }
  if (isCertificateGoal(goal)) {
    const sources = CERTIFICATE_SOURCES[goal];
    const made = (summary?.certops?.sessionCertificates || []).filter(c =>
      sources.includes(c?.source)
    );
    const certificates = unique(
      made.filter(c => c.tokenId != null).map(c => c.tokenId)
    );
    return {
      websites: [],
      assets: [],
      certificates,
      noToken: made.filter(c => c.tokenId == null).length,
      blocked: certificates.length > MAX_ITEMS ? 'cap' : null,
    };
  }
  const references = summary?.references || {};
  const liveTokens = Array.isArray(references.tokenIds?.existing)
    ? new Set(references.tokenIds.existing.map(text))
    : null;
  const tokenIds = (refs.tokenIds || []).filter(
    id => !liveTokens || liveTokens.has(text(id))
  );

  const sessionMonitors = new Set((refs.monitorIds || []).map(text));
  const listed = (summary?.monitors?.items || []).filter(m =>
    sessionMonitors.has(text(m.id))
  );
  const monitorTokens = unique(
    listed.filter(m => m.tokenId != null).map(m => m.tokenId)
  );
  // A website without a certificate record has no token to carry a group.
  const noToken = listed.filter(m => m.tokenId == null).length;

  let websites;
  let assets;
  if (Array.isArray(refs.assetTokenIds)) {
    const own = new Set(refs.assetTokenIds.map(text));
    assets = unique(existingAssetStepIds(refs, references));
    websites = unique([...tokenIds, ...monitorTokens]).filter(
      id => !own.has(id)
    );
  } else if (sessionMonitors.size > 0 || refs.monitorUrl) {
    // Saved before assetTokenIds existed. The asset goal could add both kinds
    // then, so a token no monitor points at is an asset; for the website goal
    // every token is a website certificate.
    const monitorOwned = new Set(
      (summary?.monitors?.items || [])
        .filter(m => m.tokenId != null)
        .map(m => text(m.tokenId))
    );
    const all = unique([...tokenIds, ...monitorTokens]);
    if (goal === 'track_asset') {
      websites = all.filter(id => monitorOwned.has(id));
      assets = all.filter(id => !monitorOwned.has(id));
    } else {
      websites = all;
      assets = [];
    }
  } else {
    websites = [];
    assets = unique(existingAssetStepIds(refs, references));
  }

  const blocked = websites.length + assets.length > MAX_ITEMS ? 'cap' : null;
  return { websites, assets, certificates: [], noToken, blocked };
}
/**
 * Whether the alerting that belongs to THIS goal is set up in this session.
 * A group existing in the workspace proves nothing about the items the guide
 * created, so each goal is judged on its own evidence:
 * - monitor_https: every website the guide added carries a reachable group
 *   AND the operator confirmed it in this goal. A certificate token is born
 *   with the workspace default group, so the groups alone prove nothing about
 *   what the operator saw. Websites without a certificate record yet cannot
 *   carry one; when none of them can, the operator confirms the workspace
 *   default group instead.
 * - track_asset: the same, for the assets the guide added.
 * - CertOps goals that create a certificate (ACME, AD CS, Vault): the same,
 *   for the certificates made in this session; with none yet, the operator
 *   confirms the workspace default group.
 * - everything else (imports, alerting, observe): the operator confirmed the
 *   recipients for this goal and the default group still reaches someone.
 * A group counts only if it exists and reaches a recipient. Skipping is
 * handled by the planner, not here.
 */
export function recipientsSatisfied({ goal, refs, progress, reality }) {
  if (!reality || !goal) return false;
  const confirmed = progress?.recipientsConfirmedFor === goal;
  if (canTickGoal(goal)) {
    const plan = planSessionItems({
      goal,
      refs: refs || {},
      summary: reality,
      progress,
    });
    const ids = tickIds(goal, plan);
    if (ids.length) return confirmed && itemsReachGroups(ids, reality);
    if (!confirmsDefault(goal, plan)) return false;
  }
  const defaults = reality.alerts?.contactGroups;
  const reaches =
    (defaults?.defaultHasRecipient ?? defaults?.defaultHasEmailRecipient) ===
    true;
  return confirmed && reaches;
}

/** Whether every one of these tokens carries a reachable group. */
export function itemsReachGroups(ids, reality) {
  const groups = reality?.references?.tokenGroups;
  if (!groups || !ids.length) return false;
  return ids.every(id => (groups[text(id)] || []).length > 0);
}

/**
 * Whether the operator may continue from the ticks: there is something to
 * tick and all of it reaches a group. Confirming is the Continue click.
 */
export function canContinueTicks({ goal, refs, reality, progress }) {
  if (!reality || !canTickGoal(goal)) return false;
  const plan = planSessionItems({
    goal,
    refs: refs || {},
    summary: reality,
    progress,
  });
  return itemsReachGroups(tickIds(goal, plan), reality);
}

/** The token ids a goal's ticks apply to. */
export function tickIds(goal, plan) {
  if (goal === 'monitor_https') return plan.websites;
  if (goal === 'track_asset') return plan.assets;
  return plan.certificates;
}

/**
 * Whether a goal that normally ticks has nothing to tick yet and falls back
 * to confirming the workspace default group: websites that cannot carry a
 * group until their first check, or CertOps picks with no certificate yet.
 */
export function confirmsDefault(goal, plan) {
  if (!canTickGoal(goal) || tickIds(goal, plan).length > 0) return false;
  if (goal === 'monitor_https') return plan.noToken > 0;
  return isCertificateGoal(goal);
}

/** 'all' | 'some' | 'none': how many items carry the group. */
export function tickState(groupId, items) {
  if (!items.length) return 'none';
  const id = text(groupId);
  const have = items.filter(i => i.groupIds.includes(id)).length;
  if (have === 0) return 'none';
  return have === items.length ? 'all' : 'some';
}

/**
 * The group list an item should have after ticking or unticking one group.
 * Without plural writes an item holds one group, so ticking replaces it.
 */
export function nextGroupIds(current, groupId, add, plural = true) {
  const id = text(groupId);
  if (!add) return normalizeContactGroupIds(current.filter(g => g !== id));
  return normalizeContactGroupIds(plural ? [...current, id] : [id]);
}

/** Items that need a write to reach the wanted tick state for a group. */
export function itemsToChange(groupId, items, add) {
  const id = text(groupId);
  return items.filter(i => i.groupIds.includes(id) !== add);
}

// How many items the recipients step names before saying "and N more".
export const ITEMS_SHOWN = 10;

function quoted(name) {
  return name ? `"${name}"` : '';
}

/** One sentence under the heading that says what the ticks mean. */
export function describeTicks({
  goal,
  items,
  defaultName,
  noToken = 0,
  existingIds = null,
}) {
  const fallback = defaultName
    ? `Anything without a group uses the workspace default group ${quoted(defaultName)}.`
    : 'No default group is set, so anything without a group has no recipient.';
  if (!canTickGoal(goal)) {
    if (goal === 'import_file') {
      return defaultName
        ? `Imported rows use the groups named in your file (contact_group_ids), or the workspace default group ${quoted(defaultName)}.`
        : 'Imported rows use the groups named in your file (contact_group_ids). No default group is set, so any without a group have no recipient.';
    }
    if (goal === 'import_integration') {
      return defaultName
        ? `Imported assets use the groups chosen in the import dialog, or the workspace default group ${quoted(defaultName)}.`
        : 'Imported assets use the groups chosen in the import dialog. No default group is set, so any without a group have no recipient.';
    }
    return defaultName
      ? `Alerts for this setup use the group chosen elsewhere, or the workspace default group ${quoted(defaultName)}.`
      : 'Alerts for this setup use the group chosen elsewhere. No default group is set.';
  }
  const hasWebsites = items.some(i => i.kind === 'website');
  const hasAssets = items.some(i => i.kind === 'asset');
  const hasCertificates = items.some(i => i.kind === 'certificate');
  if (!hasWebsites && !hasAssets && !hasCertificates) {
    if (noToken) return describeNoToken(noToken, goal, defaultName);
    return isCertificateGoal(goal)
      ? describeNoCertificate(defaultName, goal)
      : 'Add something first, then choose its groups here.';
  }
  const what = hasCertificates
    ? goal === 'certops_observe'
      ? 'the certificates your agent found'
      : 'the certificates'
    : hasWebsites && hasAssets
      ? 'the websites and assets'
      : hasWebsites
        ? 'the websites'
        : 'the assets';
  const ungrouped = items.filter(
    i => !i.groupIds.some(id => !existingIds || existingIds.has(id))
  );
  const origin = goal === 'certops_observe' ? '' : ' you added in this guide';
  return `Ticked groups receive alerts for ${what}${origin}. ${
    ungrouped.length
      ? describeUngrouped({ items: ungrouped, defaultName })
      : fallback
  }`;
}

/**
 * What an AD CS pick still lacks before it has a certificate to tick: the
 * renewal profile itself ('profile') or its attachment to a certificate
 * ('attach'). Null when nothing is lacking or the server does not say.
 */
export function adcsGap({ summary, progress }) {
  const saved = scopeCertops(progress?.certops, 'adcs');
  const adcs = scopeAdcs(summary?.certops?.adcs, saved.chosenIssuerId);
  if (!adcs || summary?.certops === 'unknown') return null;
  if (!(adcs.profiles > 0)) return 'profile';
  return adcs.attached === 0 ? 'attach' : null;
}

/** Note for items that carry no group, from the live default group. */
export function describeUngrouped({ items, defaultName }) {
  const count = items.length;
  if (!count) return '';
  const kinds = new Set(items.map(i => i.kind));
  const noun =
    kinds.size > 1
      ? 'item'
      : kinds.has('website')
        ? 'website'
        : kinds.has('certificate')
          ? 'certificate'
          : 'asset';
  const [subject, verb] =
    count === 1 ? [`1 ${noun} has`, 'uses'] : [`${count} ${noun}s have`, 'use'];
  return defaultName
    ? `${subject} no group and ${verb} the workspace default group ${quoted(defaultName)}.`
    : `${subject} no group and no default group is set, so there is no recipient until a group is set.`;
}

/**
 * Items that exist but have no token yet to carry a group. A website gets its
 * certificate record at the first check that reads a certificate, with the
 * workspace default group; a CertOps certificate gets its token once issued.
 */
export function describeNoToken(
  count,
  goal = 'monitor_https',
  defaultName = ''
) {
  if (!count) return '';
  if (isCertificateGoal(goal)) {
    const subject =
      count === 1
        ? '1 certificate from this setup has'
        : `${count} certificates from this setup have`;
    return `${subject} no inventory record yet, so ${count === 1 ? 'its' : 'their'} groups cannot be set here.`;
  }
  const subject =
    count === 1
      ? '1 website you added has'
      : `${count} websites you added have`;
  const tail = defaultName
    ? ` Until then ${count === 1 ? 'it uses' : 'they use'} the workspace default group ${quoted(defaultName)}; you can change that in Alert Preferences.`
    : '';
  return `${subject} no certificate record yet, so ${count === 1 ? 'its' : 'their'} groups cannot be set here.${tail}`;
}

/** A CertOps pick that has not produced a certificate with a token yet. */
export function describeNoCertificate(defaultName = '', goal = '') {
  if (goal === 'certops_observe') {
    return defaultName
      ? `No certificates found yet. Certificates your agent finds later use the workspace default group ${quoted(defaultName)}.`
      : 'No certificates found yet, and no default group is set.';
  }
  if (goal === 'certops_adcs') {
    const tail = defaultName
      ? ` Until then the workspace default group ${quoted(defaultName)} is used.`
      : ' No default group is set, so there is no recipient until one is.';
    return `No certificate is attached to the renewal profile yet, so there is nothing to tick.${tail}`;
  }
  return defaultName
    ? `Nothing was created yet that could carry a group: the workspace default group ${quoted(defaultName)} is used.`
    : 'Nothing was created yet that could carry a group, and no default group is set.';
}

/** The items one tick applies to: the first few by name, then a count. */
export function summarizeItems(items) {
  const shown = items.slice(0, ITEMS_SHOWN).map(i => i.name);
  return { shown, more: Math.max(0, items.length - shown.length) };
}

/** The heading over the item names, for what the ticks apply to. */
export function describeItemsCovered(items, goal) {
  const count = items.length;
  const kinds = new Set(items.map(i => i.kind));
  const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
  if (kinds.size > 1) return `${plural(count, 'item')} from this guide`;
  if (kinds.has('website')) return `${plural(count, 'website')} you added`;
  if (kinds.has('asset')) return `${plural(count, 'asset')} you added`;
  return goal === 'certops_observe'
    ? `${plural(count, 'certificate')} your agent found`
    : `${plural(count, 'certificate')} from this setup`;
}

/** Why the alerting goal has nothing to tick. */
export const DEFAULT_ONLY_NOTE =
  'This setup does not create items that carry their own group. Alerts use the groups below as the workspace default: set the default group and make sure it reaches someone.';

/**
 * The note for a goal with no items of its own. It must not claim "no items"
 * in a workspace that already manages some, so then it only says where the
 * default group applies.
 */
export const DEFAULT_ONLY_NOTE_WITH_ITEMS =
  'Items in this workspace that have no group of their own use the workspace default group. Set the default group below and make sure it reaches someone.';

export function workspaceHasItems(summary) {
  const certs = summary?.certops?.certificates;
  return (
    (summary?.assets?.total || 0) > 0 ||
    (summary?.monitors?.items || []).length > 0 ||
    (typeof certs === 'object' && certs !== null && (certs.total || 0) > 0)
  );
}

export function defaultOnlyNote({ goal, summary }) {
  if (!isDefaultOnlyGoal(goal) || canTickGoal(goal)) return '';
  return workspaceHasItems(summary)
    ? DEFAULT_ONLY_NOTE_WITH_ITEMS
    : DEFAULT_ONLY_NOTE;
}

/**
 * Whether the recipients step should keep reading the summary: something
 * this goal manages exists or is expected, but not every item can carry a
 * group yet. A website gets its record at the first check; a certificate
 * appears when the profile is attached, an agent reports or a job finishes.
 * `ready` means the ticks were read; `itemCount` is how many are listed.
 */
export function recipientsNeedPolling({
  goal,
  plan,
  ready = false,
  itemCount = 0,
}) {
  if (goal === 'monitor_https') return (plan?.noToken || 0) > 0;
  if (!isCertificateGoal(goal)) return false;
  return ready && (itemCount === 0 || (plan?.noToken || 0) > 0);
}

export const BLOCKED_MESSAGES = {
  cap: `This guide added more than ${MAX_ITEMS} items, so groups cannot be ticked here. Change them on each asset.`,
  capObserved: `Your agent found more than ${MAX_OBSERVED} certificates, so groups cannot be ticked here. Change them on each certificate.`,
  read: 'The groups of your items could not be read, so ticking is turned off.',
};
