import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import AdcsPostPinCheck from '../../src/components/onboarding/AdcsPostPinCheck.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import {
  dispatchIssuerPreflight,
  listIssuers,
} from '../../src/components/certops/certopsEnrollmentsApi.js';
import { getJob } from '../../src/components/certops/certopsJobsApi.js';

vi.mock('../../src/components/certops/certopsEnrollmentsApi.js', () => ({
  dispatchIssuerPreflight: vi.fn(),
  listIssuers: vi.fn(),
}));
vi.mock('../../src/components/certops/certopsJobsApi.js', () => ({
  getJob: vi.fn(),
}));

const issuer = {
  id: 'issuer-b',
  caConfig: 'ca\\Issuing CA',
  template: 'WebServer',
};
const agent = {
  id: 'database-agent',
  hostname: 'windows-member',
  platform: 'win32',
  livenessState: 'live',
  declaredCapabilities: ['adcs-enroll-v1'],
};
const safe = {
  ...issuer,
  lastPreflightJobId: 'fresh-job',
  revalidationRequired: false,
  lastPreflight: {
    caConfig: issuer.caConfig,
    template: issuer.template,
    caCheck: { verdict: 'safe' },
    templateCheck: { verdict: 'safe' },
  },
};
const show = (extra = {}) => {
  const onChanged = vi.fn().mockResolvedValue(undefined);
  const view = render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <AdcsPostPinCheck
          workspaceId='ws-b'
          issuer={issuer}
          agent={agent}
          onChanged={onChanged}
          {...extra}
        />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
  return { ...view, onChanged };
};
beforeEach(() => {
  vi.resetAllMocks();
  dispatchIssuerPreflight.mockResolvedValue({
    job: { id: 'fresh-job', status: 'queued' },
  });
  getJob.mockResolvedValue({ job: { id: 'fresh-job', status: 'succeeded' } });
  listIssuers.mockResolvedValue({ items: [safe] });
});

describe('inline AD CS post-pin check', () => {
  it('dispatches the existing issuer and selected database agent, then refreshes only its fresh safe result', async () => {
    const { onChanged } = show();
    fireEvent.click(screen.getByRole('button', { name: 'Run post-pin check' }));
    await waitFor(() => expect(onChanged).toHaveBeenCalledTimes(1));
    expect(dispatchIssuerPreflight).toHaveBeenCalledWith('ws-b', issuer.id, {
      agentId: agent.id,
      caConfig: issuer.caConfig,
      template: issuer.template,
    });
    expect(getJob).toHaveBeenCalledWith('ws-b', 'fresh-job');
    expect(
      await screen.findByText('Post-pin CA and template checks passed.')
    ).toBeVisible();
  });

  it('does not accept an older safe result for a different job', async () => {
    listIssuers.mockResolvedValue({
      items: [{ ...safe, lastPreflightJobId: 'old-job' }],
    });
    const { onChanged, unmount } = show();
    fireEvent.click(screen.getByRole('button', { name: 'Run post-pin check' }));
    await waitFor(() => expect(listIssuers).toHaveBeenCalled());
    expect(onChanged).not.toHaveBeenCalled();
    expect(
      screen.getByRole('button', { name: 'Run post-pin check' })
    ).toBeDisabled();
    unmount();
  });

  it.each([
    [
      'unsafe template',
      {
        ...safe,
        lastPreflight: {
          ...safe.lastPreflight,
          templateCheck: { verdict: 'unsafe' },
        },
      },
    ],
    [
      'different CA pair',
      {
        ...safe,
        lastPreflight: { ...safe.lastPreflight, caConfig: 'other\\CA' },
      },
    ],
    ['changed pin', { ...safe, revalidationRequired: true }],
  ])('blocks completion for %s', async (_label, current) => {
    listIssuers.mockResolvedValue({ items: [current] });
    const { onChanged } = show();
    fireEvent.click(screen.getByRole('button', { name: 'Run post-pin check' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'not safe for the pinned issuer'
    );
    expect(onChanged).not.toHaveBeenCalled();
  });

  it('shows agent refusal without treating it as a CA verdict', async () => {
    getJob.mockResolvedValue({
      job: { status: 'rejected', errorCode: 'issuer_not_allowlisted' },
    });
    const { onChanged } = show();
    fireEvent.click(screen.getByRole('button', { name: 'Run post-pin check' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'enrollment rule does not name this CA'
    );
    expect(onChanged).not.toHaveBeenCalled();
  });

  it('preserves pending approval and prevents duplicate dispatch', async () => {
    getJob.mockResolvedValue({ job: { status: 'pending_approval' } });
    const { onChanged, unmount } = show();
    const button = screen.getByRole('button', { name: 'Run post-pin check' });
    fireEvent.click(button);
    await waitFor(() => expect(getJob).toHaveBeenCalled());
    expect(button).toBeDisabled();
    fireEvent.click(button);
    expect(dispatchIssuerPreflight).toHaveBeenCalledTimes(1);
    expect(onChanged).not.toHaveBeenCalled();
    unmount();
  });

  it('can refresh a failed read without creating another check', async () => {
    getJob.mockRejectedValueOnce(new Error('Temporary network failure'));
    const { onChanged } = show();
    fireEvent.click(screen.getByRole('button', { name: 'Run post-pin check' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Temporary network failure'
    );
    fireEvent.click(
      screen.getByRole('button', { name: 'Refresh check result' })
    );
    await waitFor(() => expect(onChanged).toHaveBeenCalledTimes(1));
    expect(dispatchIssuerPreflight).toHaveBeenCalledTimes(1);
  });

  it.each([
    { disabledReason: 'Certificate operations are paused.' },
    { agent: { ...agent, livenessState: 'offline' } },
    { agent: { ...agent, platform: 'linux' } },
  ])('respects the workspace and selected agent blockers: %j', extra => {
    show(extra);
    const button = screen.getByRole('button', { name: 'Run post-pin check' });
    expect(button).toBeDisabled();
    fireEvent.click(button);
    expect(dispatchIssuerPreflight).not.toHaveBeenCalled();
  });

  it('does not update an abandoned workspace after unmount', async () => {
    let finish;
    getJob.mockImplementation(
      () =>
        new Promise(resolve => {
          finish = resolve;
        })
    );
    const { onChanged, unmount } = show();
    fireEvent.click(screen.getByRole('button', { name: 'Run post-pin check' }));
    await waitFor(() => expect(getJob).toHaveBeenCalled());
    unmount();
    await act(async () => finish({ job: { status: 'succeeded' } }));
    expect(onChanged).not.toHaveBeenCalled();
  });
});
