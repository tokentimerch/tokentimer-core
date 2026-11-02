import { describe, expect, it, vi } from 'vitest';
import { SessionController } from '../../src/components/onboarding/sessionController.js';
import { clearGoal } from '../../src/components/onboarding/sessionTransitions.js';

function conflict(current) {
  const e = new Error('conflict');
  e.name = 'RevisionConflictError';
  e.current = current;
  return e;
}

const base = {
  revision: 0,
  intent: {},
  progress: {},
  operationRefs: {},
};

describe('SessionController', () => {
  it('loads the session and writes with the current revision', async () => {
    const api = {
      getSession: vi.fn().mockResolvedValue({ ...base, revision: 2 }),
      putSession: vi.fn().mockImplementation(async (_w, _f, body) => ({
        ...base,
        revision: body.expectedRevision + 1,
        intent: body.intent,
      })),
    };
    const controller = new SessionController({
      api,
      workspaceId: 'w1',
      flow: 'mega',
    });
    const next = await controller.update(() => ({ intent: { goal: 'a' } }));
    expect(api.putSession).toHaveBeenCalledWith('w1', 'mega', {
      intent: { goal: 'a' },
      expectedRevision: 2,
    });
    expect(next.revision).toBe(3);
  });

  it('replays a change on top of the server copy after a conflict', async () => {
    const serverCopy = {
      ...base,
      revision: 5,
      operationRefs: { monitorUrl: 'https://a.example' },
    };
    const api = {
      getSession: vi.fn().mockResolvedValue({ ...base, revision: 4 }),
      putSession: vi
        .fn()
        .mockRejectedValueOnce(conflict(serverCopy))
        .mockImplementation(async (_w, _f, body) => ({
          ...serverCopy,
          revision: body.expectedRevision + 1,
          operationRefs: body.operation_refs,
        })),
    };
    const controller = new SessionController({
      api,
      workspaceId: 'w1',
      flow: 'mega',
    });
    const seen = [];
    const result = await controller.update(current => {
      seen.push(current.revision);
      return {
        operation_refs: { ...current.operationRefs, tokenIds: [7] },
      };
    });
    expect(seen).toEqual([4, 5]);
    expect(result.operationRefs).toEqual({
      monitorUrl: 'https://a.example',
      tokenIds: [7],
    });
  });

  it('gives up after repeated conflicts instead of looping forever', async () => {
    const api = {
      getSession: vi.fn().mockResolvedValue(base),
      putSession: vi.fn().mockImplementation(async () => {
        throw conflict({ ...base, revision: 9 });
      }),
    };
    const controller = new SessionController({
      api,
      workspaceId: 'w1',
      flow: 'mega',
    });
    await expect(controller.update(() => ({}))).rejects.toThrow('conflict');
    expect(api.putSession).toHaveBeenCalledTimes(4);
  });

  it('serialises concurrent updates so revisions never race', async () => {
    let revision = 0;
    const api = {
      getSession: vi.fn().mockResolvedValue({ ...base }),
      putSession: vi.fn().mockImplementation(async (_w, _f, body) => {
        await new Promise(r => setTimeout(r, 5));
        expect(body.expectedRevision).toBe(revision);
        revision += 1;
        return { ...base, revision };
      }),
    };
    const controller = new SessionController({
      api,
      workspaceId: 'w1',
      flow: 'mega',
    });
    await Promise.all([
      controller.update(() => ({ progress: { a: 1 } })),
      controller.update(() => ({ progress: { b: 1 } })),
      controller.update(() => ({ progress: { c: 1 } })),
    ]);
    expect(revision).toBe(3);
  });

  it('does not rewrite on non-conflict errors', async () => {
    const api = {
      getSession: vi.fn().mockResolvedValue(base),
      putSession: vi.fn().mockRejectedValue(new Error('boom')),
    };
    const controller = new SessionController({
      api,
      workspaceId: 'w1',
      flow: 'mega',
    });
    await expect(controller.update(() => ({}))).rejects.toThrow('boom');
    expect(api.putSession).toHaveBeenCalledTimes(1);
  });
});

describe('SessionController goal protection', () => {
  const chosen = {
    ...base,
    revision: 3,
    intent: { goal: 'import_file', provider: '' },
  };

  function setup(serverCopy) {
    const api = {
      getSession: vi.fn().mockResolvedValue(chosen),
      putSession: vi
        .fn()
        .mockRejectedValueOnce(conflict(serverCopy))
        .mockImplementation(async (_w, _f, body) => ({
          ...base,
          revision: body.expectedRevision + 1,
          intent: body.intent ?? serverCopy.intent,
          progress: body.progress ?? serverCopy.progress,
        })),
    };
    const seen = [];
    const controller = new SessionController({
      api,
      workspaceId: 'w1',
      flow: 'mega',
      onChange: s => seen.push(s),
    });
    return { api, controller, seen };
  }

  it('keeps the chosen goal when the conflicting copy lost it', async () => {
    const { api, controller, seen } = setup({ ...base, revision: 9 });
    await controller.load();
    seen.length = 0;
    const result = await controller.update(s => ({
      progress: { ...s.progress, pending: { id: 'op' } },
    }));
    const retry = api.putSession.mock.calls[1][2];
    expect(retry.expectedRevision).toBe(9);
    expect(retry.intent.goal).toBe('import_file');
    expect(result.intent.goal).toBe('import_file');
    // The picker must not flash while the write is replayed.
    expect(seen.every(s => s.intent?.goal === 'import_file')).toBe(true);
  });

  it('keeps the goal when a copy has an empty goal that was never cleared on purpose', async () => {
    const { api, controller } = setup({
      ...base,
      revision: 7,
      intent: { goal: '' },
    });
    await controller.load();
    await controller.update(s => ({
      intent: { ...s.intent, provider: 'github' },
    }));
    const retry = api.putSession.mock.calls[1][2];
    expect(retry.intent).toMatchObject({
      goal: 'import_file',
      provider: 'github',
    });
  });

  it('respects a reset: a deleted row is not brought back with the old goal', async () => {
    const { api, controller } = setup({ ...base, exists: false, revision: 0 });
    await controller.load();
    await controller.update(s => ({ progress: { ...s.progress, x: 1 } }));
    expect(api.putSession.mock.calls[1][2].intent).toBeUndefined();
  });

  it('respects a goal another tab cleared on purpose', async () => {
    const { api, controller } = setup({
      ...base,
      revision: 7,
      intent: { goal: '', goalCleared: true },
    });
    await controller.load();
    await controller.update(s => ({ progress: { ...s.progress, x: 1 } }));
    const retry = api.putSession.mock.calls[1][2];
    expect(retry.intent).toBeUndefined();
  });

  it('lets the caller clear the goal explicitly', async () => {
    const api = {
      getSession: vi.fn().mockResolvedValue(chosen),
      putSession: vi.fn().mockImplementation(async (_w, _f, body) => ({
        ...base,
        revision: body.expectedRevision + 1,
        intent: body.intent,
      })),
    };
    const controller = new SessionController({
      api,
      workspaceId: 'w1',
      flow: 'mega',
    });
    const next = await controller.update(clearGoal);
    expect(next.intent.goal).toBe('');
    // Later writes do not bring the cleared goal back.
    await controller.update(s => ({ progress: { ...s.progress, y: 1 } }));
    expect(api.putSession.mock.calls[1][2].intent).toBeUndefined();
  });

  it('lets an explicit new goal win over a conflict that lost the old one', async () => {
    const { api, controller } = setup({ ...base, revision: 9 });
    await controller.load();
    const next = await controller.update(s => ({
      intent: { ...s.intent, goal: 'track_asset' },
    }));
    const retry = api.putSession.mock.calls[1][2];
    expect(retry.expectedRevision).toBe(9);
    expect(retry.intent.goal).toBe('track_asset');
    expect(next.intent.goal).toBe('track_asset');
  });

  it('merges a conflicting intent by field and keeps the goal', async () => {
    const { api, controller } = setup({
      ...base,
      revision: 5,
      intent: { goal: 'import_file', provider: 'gitlab' },
    });
    await controller.load();
    await controller.update(s => ({
      intent: { ...s.intent, provider: 'github' },
    }));
    expect(api.putSession.mock.calls[1][2].intent).toMatchObject({
      goal: 'import_file',
      provider: 'github',
    });
  });

  it('drops the cleared marker once a new goal is chosen', async () => {
    const api = {
      getSession: vi.fn().mockResolvedValue({
        ...base,
        revision: 2,
        intent: { goal: '', goalCleared: true },
      }),
      putSession: vi.fn().mockImplementation(async (_w, _f, body) => ({
        ...base,
        revision: body.expectedRevision + 1,
        intent: body.intent,
      })),
    };
    const controller = new SessionController({
      api,
      workspaceId: 'w1',
      flow: 'mega',
    });
    const next = await controller.update(s => ({
      intent: { ...s.intent, goal: 'track_asset' },
    }));
    expect(next.intent).toEqual({ goal: 'track_asset' });
  });
});
