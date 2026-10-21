// Which items the guide created and which contact groups are attached to
// them. Pure rules for the recipients step, so they are testable without React.

import { existingAssetStepIds } from './assetRefs.js';
import { normalizeContactGroupIds } from '../../utils/contactGroupAssignment.js';

// The step reads every item once and writes one by one, so it stays bounded.
export const MAX_ITEMS = 50;

// Only these goals create items that can carry a group from this step.
const TICK_GOALS = new Set(['monitor_https', 'track_asset']);
export const canTickGoal = goal => TICK_GOALS.has(goal);

const text = v => String(v);
const unique = list => Array.from(new Set(list.map(text)));

/**
 * The tokens this guide created, split into websites and assets, plus why
 * ticks cannot be offered when the set cannot be trusted. operationRefs
 * tokenIds holds website certificates and asset-step ids together;
 * assetTokenIds (newer sessions) or the session's monitors tell them apart.
 * @returns {{ websites: string[], assets: string[], noToken: number, blocked: string|null }}
 */
export function planSessionItems({ goal, refs = {}, summary = null }) {
  if (!canTickGoal(goal)) {
    return { websites: [], assets: [], noToken: 0, blocked: null };
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
  return { websites, assets, noToken, blocked };
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
  if (!hasWebsites && !hasAssets) {
    return noToken
      ? describeNoToken(noToken)
      : 'Add something first, then choose its groups here.';
  }
  const what =
    hasWebsites && hasAssets
      ? 'the websites and assets'
      : hasWebsites
        ? 'the websites'
        : 'the assets';
  const ungrouped = items.filter(
    i => !i.groupIds.some(id => !existingIds || existingIds.has(id))
  );
  return `Ticked groups receive alerts for ${what} you added in this guide. ${
    ungrouped.length
      ? describeUngrouped({ items: ungrouped, defaultName })
      : fallback
  }`;
}

/** Note for items that carry no group, from the live default group. */
export function describeUngrouped({ items, defaultName }) {
  const count = items.length;
  if (!count) return '';
  const kinds = new Set(items.map(i => i.kind));
  const noun =
    kinds.size > 1 ? 'item' : kinds.has('website') ? 'website' : 'asset';
  const [subject, verb] =
    count === 1 ? [`1 ${noun} has`, 'uses'] : [`${count} ${noun}s have`, 'use'];
  return defaultName
    ? `${subject} no group and ${verb} the workspace default group ${quoted(defaultName)}.`
    : `${subject} no group and no default group is set, so there is no recipient until a group is set.`;
}

/** Websites that exist but have no certificate to carry a group. */
export function describeNoToken(count) {
  if (!count) return '';
  const subject =
    count === 1
      ? '1 website you added has'
      : `${count} websites you added have`;
  return `${subject} no certificate record yet, so ${count === 1 ? 'its' : 'their'} groups cannot be set here.`;
}

export const BLOCKED_MESSAGES = {
  cap: `This guide added more than ${MAX_ITEMS} items, so groups cannot be ticked here. Change them on each asset.`,
  read: 'The groups of your items could not be read, so ticking is turned off.',
};
