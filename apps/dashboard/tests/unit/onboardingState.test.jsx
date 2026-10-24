import { act, renderHook, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const workspace = vi.hoisted(() => ({ id: 'workspace-a' }));
vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: workspace.id }),
}));
vi.mock('../../src/components/DashboardShell', () => ({
  default: ({ children }) => children,
}));
vi.mock('../../src/hooks/useDashboardShellProps', () => ({
  useDashboardShellProps: () => ({}),
}));
vi.mock('../../src/components/SEO.jsx', () => ({ default: () => null }));

import { useOnboardingState } from '../../src/components/onboarding/OnboardingPage.jsx';

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

function sessionFor(workspaceId, revision = 1) {
  return {
    workspaceId,
    revision,
    intent: {},
    progress: {},
    operationRefs: {},
  };
}

function makeApi() {
  return {
    getSession: vi.fn(async id => sessionFor(id)),
    getCapabilities: vi.fn(async id => ({ workspaceId: id, items: [] })),
    getSummary: vi.fn(async id => ({ workspaceId: id, version: 'initial' })),
    putSession: vi.fn(),
  };
}

async function mountedState(api = makeApi()) {
  const hook = renderHook(() => useOnboardingState({ api }));
  await waitFor(() => expect(hook.result.current.status).toBe('ready'));
  return { ...hook, api };
}

async function switchWorkspace(hook, id) {
  workspace.id = id;
  hook.rerender();
  await waitFor(() => {
    expect(hook.result.current.status).toBe('ready');
    expect(hook.result.current.session.workspaceId).toBe(id);
  });
}

beforeEach(() => {
  workspace.id = 'workspace-a';
});

describe('onboarding state request ownership', () => {
  it('returns and displays a current refresh, and preserves refresh failures', async () => {
    const hook = await mountedState();
    const summary = { workspaceId: 'workspace-a', version: 'updated' };
    hook.api.getSummary.mockResolvedValueOnce(summary);
    await act(async () => {
      expect(await hook.result.current.refresh()).toBe(summary);
    });
    expect(hook.result.current.summary).toBe(summary);

    const error = new Error('summary unavailable');
    hook.api.getSummary.mockRejectedValueOnce(error);
    await act(async () => {
      await expect(hook.result.current.refresh()).rejects.toBe(error);
    });
    expect(hook.result.current.summary).toBe(summary);
  });

  it('applies a write from the current workspace controller', async () => {
    const hook = await mountedState();
    const saved = {
      ...sessionFor('workspace-a', 2),
      progress: { imported: true },
    };
    hook.api.putSession.mockResolvedValueOnce(saved);
    await act(async () => {
      await hook.result.current.controller.update(() => ({
        progress: saved.progress,
      }));
    });
    expect(hook.result.current.session).toBe(saved);
  });

  it('does not replace a new workspace summary with an old in-flight refresh', async () => {
    const hook = await mountedState();
    const pending = deferred();
    hook.api.getSummary.mockReturnValueOnce(pending.promise);
    const refresh = hook.result.current.refresh();

    await switchWorkspace(hook, 'workspace-b');
    const currentSummary = hook.result.current.summary;
    const previousSummary = { workspaceId: 'workspace-a', version: 'late' };
    await act(async () => {
      pending.resolve(previousSummary);
      // Callers still receive the result of their own request.
      expect(await refresh).toBe(previousSummary);
    });
    expect(hook.result.current.summary).toBe(currentSummary);
  });

  it('keeps a newer refresh when an older request finishes last', async () => {
    const hook = await mountedState();
    const older = deferred();
    const newer = deferred();
    hook.api.getSummary
      .mockReturnValueOnce(older.promise)
      .mockReturnValueOnce(newer.promise);
    const oldRefresh = hook.result.current.refresh();
    const newRefresh = hook.result.current.refresh();
    const newestSummary = { workspaceId: 'workspace-a', version: 'newer' };
    await act(async () => {
      newer.resolve(newestSummary);
      await newRefresh;
    });
    await act(async () => {
      older.resolve({ workspaceId: 'workspace-a', version: 'older' });
      await oldRefresh;
    });
    expect(hook.result.current.summary).toBe(newestSummary);
  });

  it('invalidates an in-flight refresh when the same workspace is reloaded', async () => {
    const hook = await mountedState();
    const pending = deferred();
    hook.api.getSummary.mockReturnValueOnce(pending.promise);
    const refresh = hook.result.current.refresh();
    const reloaded = { workspaceId: 'workspace-a', version: 'reloaded' };
    hook.api.getSummary.mockResolvedValueOnce(reloaded);
    await act(async () => hook.result.current.reload());
    await act(async () => {
      pending.resolve({ workspaceId: 'workspace-a', version: 'before-reload' });
      await refresh;
    });
    expect(hook.result.current.summary).toBe(reloaded);
  });

  it('does not apply an old controller write to the new workspace session', async () => {
    const hook = await mountedState();
    const previousController = hook.result.current.controller;
    const pending = deferred();
    hook.api.putSession.mockReturnValueOnce(pending.promise);
    const update = previousController.update(() => ({
      progress: { imported: true },
    }));
    await waitFor(() => expect(hook.api.putSession).toHaveBeenCalledOnce());
    await switchWorkspace(hook, 'workspace-b');
    const currentSession = hook.result.current.session;
    await act(async () => {
      pending.resolve({
        ...sessionFor('workspace-a', 2),
        progress: { imported: true },
      });
      await update;
    });
    expect(hook.result.current.session).toBe(currentSession);
    expect(hook.result.current.controller).not.toBe(previousController);
  });

  it('does not dispatch an old workspace refresh after ownership changes', async () => {
    const hook = await mountedState();
    const oldRefresh = hook.result.current.refresh;
    await switchWorkspace(hook, 'workspace-b');
    const before = hook.api.getSummary.mock.calls.length;
    await act(async () => {
      expect(await oldRefresh()).toBeNull();
    });
    expect(hook.api.getSummary).toHaveBeenCalledTimes(before);
    expect(hook.result.current.summary.workspaceId).toBe('workspace-b');
  });

  it('invalidates callbacks when no workspace remains or the hook unmounts', async () => {
    const hook = await mountedState();
    const oldRefresh = hook.result.current.refresh;
    workspace.id = null;
    hook.rerender();
    expect(hook.result.current.status).toBe('loading');
    expect(hook.result.current.controller).toBeNull();
    expect(hook.result.current.session).toBeUndefined();
    expect(hook.result.current.summary).toBeUndefined();
    const before = hook.api.getSummary.mock.calls.length;
    await act(async () => {
      expect(await oldRefresh()).toBeNull();
      expect(await hook.result.current.refresh()).toBeNull();
    });
    expect(hook.api.getSummary).toHaveBeenCalledTimes(before);

    await switchWorkspace(hook, 'workspace-c');
    const lastRefresh = hook.result.current.refresh;
    hook.unmount();
    const atUnmount = hook.api.getSummary.mock.calls.length;
    expect(await lastRefresh()).toBeNull();
    expect(hook.api.getSummary).toHaveBeenCalledTimes(atUnmount);
  });
});
