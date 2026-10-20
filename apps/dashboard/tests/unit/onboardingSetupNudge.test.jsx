import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import SetupNudge from '../../src/components/onboarding/SetupNudge.jsx';

const empty = { assets: { total: 0 }, monitors: { total: 0 } };

function makeApi({ session, summary = empty } = {}) {
  return {
    getSession: vi
      .fn()
      .mockResolvedValue(
        session || { revision: 0, status: 'in_progress', intent: {} }
      ),
    getSummary: vi.fn().mockResolvedValue(summary),
    putSession: vi.fn().mockResolvedValue({}),
  };
}

const show = (api, props = {}) =>
  render(
    <ChakraProvider>
      <SetupNudge
        workspaceId='ws-1'
        isViewer={false}
        onStart={props.onStart}
        suppress={props.suppress}
        api={api}
      />
    </ChakraProvider>
  );

describe('SetupNudge', () => {
  beforeEach(() => {
    sessionStorage.clear();
  });

  it('opens the modal first for an empty workspace', async () => {
    show(makeApi());
    expect(await screen.findByText('Your workspace is empty')).toBeTruthy();
    expect(screen.queryByTestId('setup-banner')).toBeNull();
  });

  it('leaves a banner when the modal is closed with Esc, and does not dismiss', async () => {
    const api = makeApi();
    show(api);
    await screen.findByText('Your workspace is empty');
    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' });
    await waitFor(() =>
      expect(screen.getByTestId('setup-banner')).toBeTruthy()
    );
    expect(api.putSession).not.toHaveBeenCalled();
  });

  it('dismisses for good only with "Not now"', async () => {
    const api = makeApi();
    show(api);
    fireEvent.click(await screen.findByText('Not now'));
    await waitFor(() => expect(api.putSession).toHaveBeenCalledTimes(1));
    expect(api.putSession.mock.calls[0][2]).toMatchObject({
      status: 'dismissed',
    });
    expect(screen.queryByTestId('setup-banner')).toBeNull();
    expect(screen.queryByText('Your workspace is empty')).toBeNull();
  });

  it('shows the banner, not the modal, on a later visit in the same session', async () => {
    const first = makeApi();
    const { unmount } = show(first);
    await screen.findByText('Your workspace is empty');
    unmount();
    show(makeApi());
    expect(await screen.findByTestId('setup-banner')).toBeTruthy();
    expect(screen.queryByText('Not now')).toBeNull();
  });

  it('offers to continue when a goal was already chosen', async () => {
    show(
      makeApi({
        session: {
          revision: 3,
          status: 'in_progress',
          intent: { goal: 'alerting' },
        },
      })
    );
    expect(await screen.findByText('Continue setup')).toBeTruthy();
    expect(screen.queryByText('Your workspace is empty')).toBeNull();
  });

  it('starts the guide from the banner', async () => {
    const onStart = vi.fn();
    const api = makeApi({
      session: { revision: 1, status: 'in_progress', intent: { goal: 'x' } },
    });
    show(api, { onStart });
    fireEvent.click(await screen.findByText('Continue setup'));
    expect(onStart).toHaveBeenCalledTimes(1);
  });

  it('hides the banner permanently with "Hide"', async () => {
    const api = makeApi({
      session: { revision: 1, status: 'in_progress', intent: { goal: 'x' } },
    });
    show(api);
    fireEvent.click(await screen.findByText('Hide'));
    await waitFor(() => expect(api.putSession).toHaveBeenCalledTimes(1));
    expect(api.putSession.mock.calls[0][2]).toMatchObject({
      status: 'dismissed',
      expectedRevision: 1,
    });
    expect(screen.queryByTestId('setup-banner')).toBeNull();
  });

  it('shows nothing once there is something to watch, and asks only once', async () => {
    const api = makeApi({
      summary: { assets: { total: 3 }, monitors: { total: 0 } },
    });
    const { unmount } = show(api);
    await waitFor(() => expect(api.getSummary).toHaveBeenCalled());
    expect(screen.queryByTestId('setup-banner')).toBeNull();
    expect(screen.queryByText('Your workspace is empty')).toBeNull();
    unmount();
    const again = makeApi();
    show(again);
    await new Promise(r => setTimeout(r, 30));
    expect(again.getSession).not.toHaveBeenCalled();
  });

  it('stays hidden for viewers and while suppressed', async () => {
    const api = makeApi();
    render(
      <ChakraProvider>
        <SetupNudge workspaceId='ws-1' isViewer api={api} />
      </ChakraProvider>
    );
    await new Promise(r => setTimeout(r, 30));
    expect(api.getSession).not.toHaveBeenCalled();
    show(api, { suppress: true });
    await new Promise(r => setTimeout(r, 30));
    expect(api.getSession).not.toHaveBeenCalled();
  });
});

describe('SetupNudge when the workspace changes', () => {
  beforeEach(() => {
    sessionStorage.clear();
  });

  const goalSession = {
    revision: 1,
    status: 'in_progress',
    intent: { goal: 'alerting' },
  };

  // Answers differ per workspace: a is empty, b has content.
  const apiByWorkspace = () => ({
    getSession: vi
      .fn()
      .mockImplementation(async ws =>
        ws === 'ws-a'
          ? goalSession
          : { revision: 0, status: 'in_progress', intent: {} }
      ),
    getSummary: vi
      .fn()
      .mockImplementation(async ws =>
        ws === 'ws-a' ? empty : { assets: { total: 4 }, monitors: { total: 0 } }
      ),
    putSession: vi.fn().mockResolvedValue({}),
  });

  const tree = (workspaceId, api) => (
    <ChakraProvider>
      <SetupNudge workspaceId={workspaceId} isViewer={false} api={api} />
    </ChakraProvider>
  );

  it('drops the banner at once when the new workspace has content', async () => {
    const api = apiByWorkspace();
    const { rerender } = render(tree('ws-a', api));
    expect(await screen.findByTestId('setup-banner')).toBeTruthy();
    rerender(tree('ws-b', api));
    // Not after the fetch: the old answer must not be shown for ws-b at all.
    expect(screen.queryByTestId('setup-banner')).toBeNull();
    await waitFor(() =>
      expect(api.getSession).toHaveBeenCalledWith('ws-b', 'mega')
    );
    expect(screen.queryByTestId('setup-banner')).toBeNull();
  });

  it('drops the banner when the new workspace was already checked this session', async () => {
    const api = apiByWorkspace();
    // Nothing to show for ws-b, remembered from earlier in this session.
    sessionStorage.setItem('tt_setup_nudge_checked:ws-b', '1');
    const { rerender } = render(tree('ws-a', api));
    expect(await screen.findByTestId('setup-banner')).toBeTruthy();
    rerender(tree('ws-b', api));
    await new Promise(r => setTimeout(r, 30));
    expect(screen.queryByTestId('setup-banner')).toBeNull();
    expect(api.getSession).not.toHaveBeenCalledWith('ws-b', 'mega');
  });

  it('shows the banner again when switching back to the empty workspace', async () => {
    const api = apiByWorkspace();
    const { rerender } = render(tree('ws-a', api));
    await screen.findByTestId('setup-banner');
    rerender(tree('ws-b', api));
    await waitFor(() =>
      expect(api.getSession).toHaveBeenCalledWith('ws-b', 'mega')
    );
    rerender(tree('ws-a', api));
    expect(await screen.findByTestId('setup-banner')).toBeTruthy();
  });

  it('ignores a slow answer that arrives for the workspace we left', async () => {
    let resolveA;
    const api = apiByWorkspace();
    api.getSummary.mockImplementation(ws =>
      ws === 'ws-a'
        ? new Promise(r => {
            resolveA = () => r(empty);
          })
        : Promise.resolve({ assets: { total: 4 }, monitors: { total: 0 } })
    );
    const { rerender } = render(tree('ws-a', api));
    await waitFor(() => expect(resolveA).toBeTypeOf('function'));
    rerender(tree('ws-b', api));
    resolveA();
    await new Promise(r => setTimeout(r, 40));
    expect(screen.queryByTestId('setup-banner')).toBeNull();
  });
});
