// Resume-safe execution of a creating operation.
//
// The operation is recorded in the session BEFORE the backend call. If the
// browser closes after the backend succeeded but before the result was
// recorded, the next attempt finds the pending record and reconciles against
// the verified identity instead of creating again. A generic conflict is only
// treated as success when the conflicting asset is the expected one.

export class OperationConflictError extends Error {
  constructor(message, existing) {
    super(message);
    this.name = 'OperationConflictError';
    this.existing = existing;
  }
}

function newOperationId() {
  const c = typeof crypto !== 'undefined' ? crypto : null;
  if (c?.randomUUID) return c.randomUUID();
  return `op-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * @param {object}   args
 * @param {object}   args.controller  SessionController
 * @param {string}   args.kind        e.g. 'monitor', 'asset', 'contact_group'
 * @param {object}   args.identity    verified identity (small, non-secret)
 * @param {Function} args.find        async (identity) => existing | null
 * @param {Function} args.create      async (identity, operationId) => created
 *                                    may throw { conflict: existing } to report a 409
 * @param {Function} args.record      (refs, created) => refs patch to store
 */
export async function runIdempotent({
  controller,
  kind,
  identity,
  find,
  create,
  record,
}) {
  const identityKey = JSON.stringify(identity);
  let operationId;
  await controller.update(session => {
    const pending = session.progress?.pending;
    const reuse =
      pending && pending.kind === kind && pending.identityKey === identityKey;
    operationId = reuse ? pending.id : newOperationId();
    return {
      progress: {
        ...session.progress,
        pending: { id: operationId, kind, identityKey },
      },
    };
  });

  let result = await find(identity);
  let adopted = Boolean(result);

  if (!result) {
    try {
      result = await create(identity, operationId);
    } catch (e) {
      if (!e || !e.conflict) throw e;
      // The backend says something with this identity already exists. Only
      // adopt it if it is verifiably the expected one.
      const verified = await find(identity);
      if (!verified) {
        throw new OperationConflictError(
          'An item with the same name already exists but does not match what you entered.',
          e.conflict
        );
      }
      result = verified;
      adopted = true;
    }
  }

  await controller.update(session => {
    const { pending: _pending, ...rest } = session.progress || {};
    return {
      progress: rest,
      operation_refs: {
        ...session.operationRefs,
        ...record(session.operationRefs, result),
      },
    };
  });
  return { result, adopted };
}

/** Normalizes a monitor URL the way the server does (https, no trailing slash). */
export function normalizeMonitorUrl(input) {
  const raw = String(input || '').trim();
  if (!raw) return null;
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw)
    ? raw
    : `https://${raw}`;
  let url;
  try {
    url = new URL(withScheme);
  } catch (_) {
    return null;
  }
  if (url.protocol !== 'https:' || !url.hostname) return null;
  url.hash = '';
  return url.toString().replace(/\/+$/, '');
}
