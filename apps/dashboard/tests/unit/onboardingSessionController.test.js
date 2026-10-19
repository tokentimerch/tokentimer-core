import { describe, expect, it, vi } from 'vitest';
import { SessionController } from '../../src/components/onboarding/sessionController.js';

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
