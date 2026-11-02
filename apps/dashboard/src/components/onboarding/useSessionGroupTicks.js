import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { onboardingActions } from '../../utils/onboardingActions.js';
import { hydrateContactGroupIds } from '../../utils/contactGroupAssignment.js';
import {
  BLOCKED_MESSAGES,
  canTickGoal,
  itemsToChange,
  nextGroupIds,
  planSessionItems,
} from './groupAttachment.js';

const READ_CONCURRENCY = 5;
const WRITE_CONCURRENCY = 3;
const NAMES_SHOWN = 5;

async function runPool(list, size, fn) {
  let next = 0;
  const worker = async () => {
    while (next < list.length) {
      const entry = list[next];
      next += 1;
      await fn(entry);
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(size, list.length) }, worker)
  );
}

async function readItems(entries) {
  const items = [];
  const failed = [];
  await runPool(entries, READ_CONCURRENCY, async entry => {
    try {
      const token = await onboardingActions.getToken(entry.id);
      items.push({
        ...entry,
        name: token?.name || `#${entry.id}`,
        groupIds: hydrateContactGroupIds(token),
        keep: { cost: token?.cost, key_size: token?.key_size },
      });
    } catch {
      failed.push({ ...entry, name: `#${entry.id}` });
    }
  });
  const order = new Map(entries.map((e, i) => [e.id, i]));
  items.sort((a, b) => order.get(a.id) - order.get(b.id));
  return { items, failed };
}

function nameList(items) {
  const names = items.map(i => i.name);
  const shown = names.slice(0, NAMES_SHOWN).join(', ');
  const rest = names.length - NAMES_SHOWN;
  return rest > 0 ? `${shown} and ${rest} more` : shown;
}

/**
 * The contact groups attached to the websites, assets and certificates this
 * guide created,
 * read from the server, and the writes that change them. Every write is
 * followed by a read, so the ticks only ever show what is saved.
 */
export function useSessionGroupTicks({ ctx, plural = true }) {
  const goal = ctx.session?.intent?.goal;
  const refs = ctx.session?.operationRefs;
  const progress = ctx.session?.progress;
  const { summary } = ctx;
  const plan = useMemo(
    () => planSessionItems({ goal, refs: refs || {}, summary, progress }),
    [goal, refs, summary, progress]
  );
  const planRef = useRef(plan);
  planRef.current = plan;
  const goalRef = useRef(goal);
  goalRef.current = goal;
  const refreshRef = useRef(ctx.refresh);
  refreshRef.current = ctx.refresh;

  const [state, setState] = useState({
    status: canTickGoal(goal) ? 'loading' : 'off',
    items: [],
    reason: null,
  });
  const [saving, setSaving] = useState(null);
  const [notice, setNotice] = useState('');
  const latest = useRef(0);

  const load = useCallback(async () => {
    const mine = (latest.current += 1);
    const { current } = planRef;
    if (!canTickGoal(goalRef.current)) {
      setState({ status: 'off', items: [], reason: null });
      return { ok: false, items: [] };
    }
    if (current.blocked) {
      setState({ status: 'blocked', items: [], reason: current.blocked });
      return { ok: false, items: [] };
    }
    const entries = [
      ...current.websites.map(id => ({ id, kind: 'website' })),
      ...current.assets.map(id => ({ id, kind: 'asset' })),
      ...current.certificates.map(id => ({ id, kind: 'certificate' })),
    ];
    if (!entries.length) {
      setState({ status: 'ready', items: [], reason: null });
      return { ok: true, items: [] };
    }
    const { items, failed } = await readItems(entries);
    if (mine !== latest.current) return { ok: false, items: [], stale: true };
    if (failed.length) {
      setState({ status: 'blocked', items: [], reason: 'read' });
      return { ok: false, items: [] };
    }
    setState({ status: 'ready', items, reason: null });
    return { ok: true, items };
  }, []);

  const key = `${plan.blocked || ''}|${plan.websites.join(',')}|${plan.assets.join(',')}|${plan.certificates.join(',')}|${goal}`;
  useEffect(() => {
    load();
  }, [key, load]);

  const toggle = useCallback(
    async (groupId, add) => {
      if (state.status !== 'ready' || saving) return;
      const id = String(groupId);
      const targets = itemsToChange(id, state.items, add);
      if (!targets.length) return;
      setSaving(id);
      setNotice('');
      const failures = [];
      try {
        await runPool(targets, WRITE_CONCURRENCY, async item => {
          try {
            await onboardingActions.setTokenContactGroups(
              item.id,
              nextGroupIds(item.groupIds, id, add, plural),
              item.keep
            );
          } catch {
            failures.push(item);
          }
        });
        const fresh = await load();
        if (fresh.stale) return;
        const failedIds = new Set(failures.map(f => f.id));
        // Written without an error, yet not what the server now holds.
        const notKept = fresh.ok
          ? fresh.items.filter(
              i =>
                !failedIds.has(i.id) &&
                targets.some(t => t.id === i.id) &&
                i.groupIds.includes(id) !== add
            )
          : [];
        const parts = [];
        if (failures.length) {
          const named = failures.map(f => ({
            ...f,
            name: fresh.items.find(i => i.id === f.id)?.name || f.name,
          }));
          parts.push(
            `${failures.length} of ${targets.length} items could not be updated: ${nameList(named)}.`
          );
        }
        if (notKept.length) {
          parts.push(
            `The server did not keep the change for ${nameList(notKept)}.`
          );
        }
        if (parts.length) {
          parts.push('The ticks show what is saved.');
          setNotice(parts.join(' '));
        }
        await refreshRef.current?.();
      } finally {
        setSaving(null);
      }
    },
    [state, saving, plural, load]
  );

  return {
    status: state.status,
    items: state.items,
    noToken: plan.noToken,
    plan,
    blockedMessage: state.reason ? BLOCKED_MESSAGES[state.reason] : '',
    saving,
    notice,
    toggle,
    reload: load,
  };
}
