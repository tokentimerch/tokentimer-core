import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { actions } = vi.hoisted(() => ({
  actions: {
    listMonitors: vi.fn(),
    createMonitor: vi.fn(),
    discoverHostnames: vi.fn(),
    getAlertSettings: vi.fn(),
  },
}));

vi.mock('../../src/utils/onboardingActions.js', () => ({
  onboardingActions: actions,
}));

import { MonitorStep } from '../../src/components/onboarding/monitorStep.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

function makeCtx(overrides = {}, operationRefs = {}) {
  const session = { progress: {}, operationRefs, intent: {} };
  return {
    workspaceId: 'ws-1',
    docs: () => [],
    refresh: vi.fn().mockResolvedValue(undefined),
    summary: { monitors: { items: [] } },
    controller: {
      update: vi.fn(async fn => {
        const patch = fn(session);
        if (patch.progress) session.progress = patch.progress;
        if (patch.operation_refs) session.operationRefs = patch.operation_refs;
      }),
      session,
    },
    ...overrides,
  };
}

const mount = ctx =>
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MonitorStep ctx={ctx} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );

const type = (el, value) => fireEvent.change(el, { target: { value } });
const addressBox = () => screen.getByPlaceholderText('https://example.com');
const stage = value => {
  type(addressBox(), value);
  fireEvent.click(screen.getByRole('button', { name: 'Add website' }));
};

beforeEach(() => {
  actions.listMonitors.mockReset().mockResolvedValue([]);
  actions.createMonitor.mockReset().mockImplementation(async (_w, body) => ({
    id: `m-${body.url}`,
    url: body.url,
    token_id: 100,
  }));
  actions.discoverHostnames.mockReset();
  actions.getAlertSettings
    .mockReset()
    .mockResolvedValue({ contact_groups: [] });
});

describe('MonitorStep website list', () => {
  it('collects several websites before creating anything', async () => {
    mount(makeCtx());
    stage('a.example.com');
    stage('b.example.com');
    expect(
      screen.getByRole('list', { name: 'Websites to monitor' })
    ).toBeTruthy();
    expect(screen.getAllByRole('listitem')).toHaveLength(2);
    expect(actions.createMonitor).not.toHaveBeenCalled();
    expect(
      screen.getByRole('button', { name: 'Monitor 2 websites' })
    ).toBeTruthy();
  });

  it('creates every listed website with the chosen settings', async () => {
    const ctx = makeCtx();
    mount(ctx);
    stage('a.example.com');
    stage('b.example.com');
    fireEvent.change(screen.getByLabelText('Check every'), {
      target: { value: '5min' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Monitor 2 websites' }));
    await waitFor(() => expect(actions.createMonitor).toHaveBeenCalledTimes(2));
    for (const [, body] of actions.createMonitor.mock.calls) {
      expect(body).toMatchObject({
        checkInterval: '5min',
        healthCheckEnabled: true,
        alertAfterFailures: 2,
      });
    }
    expect(actions.createMonitor.mock.calls.map(c => c[1].url)).toEqual([
      'https://a.example.com',
      'https://b.example.com',
    ]);
    await waitFor(() => expect(ctx.refresh).toHaveBeenCalled());
  });

  it('sends the same defaults the wizard always used when nothing is changed', async () => {
    mount(makeCtx());
    stage('example.com');
    fireEvent.click(
      screen.getByRole('button', { name: 'Monitor this website' })
    );
    await waitFor(() => expect(actions.createMonitor).toHaveBeenCalledTimes(1));
    expect(actions.createMonitor.mock.calls[0][1]).toMatchObject({
      url: 'https://example.com',
      checkInterval: 'hourly',
      healthCheckEnabled: true,
      alertAfterFailures: 2,
    });
  });

  it('sends the workspace default group to every website', async () => {
    actions.getAlertSettings.mockResolvedValue({
      contact_groups: [
        { id: 'g1', name: 'Ops team' },
        { id: 'g2', name: 'Security' },
      ],
      default_contact_group_id: 'g1',
    });
    mount(makeCtx());
    await waitFor(() => expect(actions.getAlertSettings).toHaveBeenCalled());
    stage('a.example.com');
    stage('b.example.com');
    fireEvent.click(screen.getByRole('button', { name: 'Monitor 2 websites' }));
    await waitFor(() => expect(actions.createMonitor).toHaveBeenCalledTimes(2));
    for (const [, body] of actions.createMonitor.mock.calls) {
      expect(body.contactGroupIds).toEqual(['g1']);
    }
  });

  it('sends no group when the workspace has no default, so the server decides', async () => {
    actions.getAlertSettings.mockResolvedValue({
      contact_groups: [{ id: 'g1', name: 'Ops team' }],
      default_contact_group_id: '',
    });
    mount(makeCtx());
    await waitFor(() => expect(actions.getAlertSettings).toHaveBeenCalled());
    stage('a.example.com');
    fireEvent.click(
      screen.getByRole('button', { name: 'Monitor this website' })
    );
    await waitFor(() => expect(actions.createMonitor).toHaveBeenCalledTimes(1));
    expect(actions.createMonitor.mock.calls[0][1].contactGroupIds).toEqual([]);
  });

  it('asks who gets alerted only in the next step, not inside this one', async () => {
    actions.getAlertSettings.mockResolvedValue({
      contact_groups: [{ id: 'g1', name: 'Ops team' }],
      default_contact_group_id: 'g1',
    });
    mount(makeCtx());
    await waitFor(() => expect(actions.getAlertSettings).toHaveBeenCalled());
    expect(screen.queryByText('Who gets alerted')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Ops team' })).toBeNull();
    expect(screen.queryByTestId('alerts-go-to')).toBeNull();
    expect(screen.queryByTestId('no-group-hint')).toBeNull();
    expect(
      screen.getByText(/You choose who gets alerted in the next step\./)
    ).toBeTruthy();
  });

  it('turns down alerts off and hides the failure count', async () => {
    mount(makeCtx());
    expect(screen.getByLabelText('After failed checks in a row')).toBeTruthy();
    fireEvent.click(screen.getByLabelText('Alert me if a website is down'));
    expect(screen.queryByLabelText('After failed checks in a row')).toBeNull();
    stage('example.com');
    fireEvent.click(
      screen.getByRole('button', { name: 'Monitor this website' })
    );
    await waitFor(() => expect(actions.createMonitor).toHaveBeenCalled());
    expect(actions.createMonitor.mock.calls[0][1].healthCheckEnabled).toBe(
      false
    );
  });

  it('counts a typed address that was not added yet', async () => {
    mount(makeCtx());
    stage('a.example.com');
    type(addressBox(), 'b.example.com');
    fireEvent.click(screen.getByRole('button', { name: 'Monitor 2 websites' }));
    await waitFor(() => expect(actions.createMonitor).toHaveBeenCalledTimes(2));
  });

  it('removes a website from the list', () => {
    mount(makeCtx());
    stage('a.example.com');
    stage('b.example.com');
    fireEvent.click(
      screen.getByRole('button', { name: 'Remove https://a.example.com' })
    );
    expect(screen.getAllByRole('listitem')).toHaveLength(1);
  });

  it('does not list the same website twice', () => {
    mount(makeCtx());
    stage('a.example.com');
    stage('A.example.com/');
    expect(screen.getAllByRole('listitem')).toHaveLength(1);
  });

  it('refuses an invalid address with a message and adds nothing', () => {
    mount(makeCtx());
    stage('http://insecure.example.com');
    expect(screen.getByText(/valid HTTPS address/)).toBeTruthy();
    expect(
      screen.queryByRole('list', { name: 'Websites to monitor' })
    ).toBeNull();
  });

  it('refuses an out of range failure count and creates nothing', async () => {
    mount(makeCtx());
    stage('example.com');
    fireEvent.change(screen.getByLabelText('After failed checks in a row'), {
      target: { value: '99' },
    });
    fireEvent.click(
      screen.getByRole('button', { name: 'Monitor this website' })
    );
    await screen.findByText('Fix the highlighted settings.');
    expect(actions.createMonitor).not.toHaveBeenCalled();
  });
});

describe('MonitorStep partial failure', () => {
  it('keeps only the failed websites listed, with their reason', async () => {
    actions.createMonitor.mockImplementation(async (_w, body) => {
      if (body.url.includes('bad'))
        throw new Error('Could not reach bad.example.com');
      return { id: `m-${body.url}`, url: body.url, token_id: 100 };
    });
    const ctx = makeCtx();
    mount(ctx);
    stage('good.example.com');
    stage('bad.example.com');
    fireEvent.click(screen.getByRole('button', { name: 'Monitor 2 websites' }));
    expect(await screen.findByText(/Added 1 of 2/)).toBeTruthy();
    expect(screen.getByText('Could not reach bad.example.com')).toBeTruthy();
    const items = screen.getAllByRole('listitem');
    expect(items).toHaveLength(1);
    expect(items[0].textContent).toMatch(/bad\.example\.com/);
    // The step must not be reported finished while something failed: the
    // snapshot is refreshed, but no address is recorded as the finished one.
    expect(ctx.refresh).toHaveBeenCalledTimes(1);
    expect(ctx.controller.session.operationRefs.monitorUrl).toBeUndefined();
    expect(ctx.controller.session.operationRefs.monitorIds).toEqual([
      'm-https://good.example.com',
    ]);
  });

  it('does not refresh when nothing at all could be added', async () => {
    actions.createMonitor.mockRejectedValue(new Error('Unreachable'));
    const ctx = makeCtx();
    mount(ctx);
    stage('bad.example.com');
    fireEvent.click(
      screen.getByRole('button', { name: 'Monitor this website' })
    );
    expect(
      await screen.findByText('None of the websites could be added.')
    ).toBeTruthy();
    expect(ctx.refresh).not.toHaveBeenCalled();
  });

  it('shows what was created after a partial failure, and drops the stale discovery note', async () => {
    actions.discoverHostnames.mockResolvedValue({
      items: [{ name: 'good.example.com' }],
      partial: false,
      truncated: false,
    });
    actions.createMonitor.mockImplementation(async (_w, body) => {
      if (body.url.includes('bad')) throw new Error('Could not reach it');
      return { id: `m-${body.url}`, url: body.url, token_id: 100 };
    });
    const ctx = makeCtx();
    // The server snapshot gains the created website once refreshed.
    ctx.refresh = vi.fn(async () => {
      ctx.summary = {
        monitors: { items: [{ url: 'https://good.example.com' }] },
      };
    });
    mount(ctx);
    fireEvent.click(screen.getByText('Find the websites on my domain'));
    type(screen.getByLabelText('Domain to search'), 'example.com');
    fireEvent.click(
      screen.getByRole('button', { name: 'Find websites', hidden: true })
    );
    await screen.findByText('1 found for example.com');
    fireEvent.click(screen.getByLabelText('good.example.com'));
    fireEvent.click(
      screen.getByRole('button', { name: 'Add 1 to the list', hidden: true })
    );
    expect(screen.getByText('Added 1 to the list.')).toBeTruthy();
    stage('bad.example.com');
    expect(screen.queryByText(/Already monitoring/)).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Monitor 2 websites' }));
    expect(await screen.findByText(/Added 1 of 2/)).toBeTruthy();
    await waitFor(() => expect(ctx.refresh).toHaveBeenCalledTimes(1));
    expect(screen.queryByText('Added 1 to the list.')).toBeNull();
    expect(
      await screen.findByText('Already monitoring 1 website in this workspace.')
    ).toBeTruthy();
    expect(await screen.findByText('Already monitored')).toBeTruthy();
    expect(screen.getByLabelText('good.example.com')).toBeDisabled();
  });

  it('still advances a fully created batch that includes a website with no certificate', async () => {
    actions.createMonitor.mockImplementation(async (_w, body) =>
      body.url.includes('nocert')
        ? { id: 'm-nocert', url: body.url, token_id: null, validated: false }
        : {
            id: 'm-ok',
            url: body.url,
            token_id: 100,
            validated: true,
            ssl_valid_to: '2027-01-01T00:00:00Z',
          }
    );
    const ctx = makeCtx();
    mount(ctx);
    stage('ok.example.com');
    stage('nocert.example.com');
    fireEvent.click(screen.getByRole('button', { name: 'Monitor 2 websites' }));
    await waitFor(() => expect(ctx.refresh).toHaveBeenCalledTimes(1));
    // Both are recorded; the verify step reads their certificates from the
    // live summary, so nothing certificate-related is stored here.
    expect(ctx.controller.session.operationRefs.monitorIds).toEqual([
      'm-ok',
      'm-nocert',
    ]);
    expect(ctx.controller.session.operationRefs.tokenIds).toEqual([100]);
    expect(ctx.controller.session.operationRefs.monitorUrl).toBe(
      'https://ok.example.com'
    );
  });

  it('does not create a website that already exists', async () => {
    actions.listMonitors.mockResolvedValue([
      { id: 'old', url: 'https://a.example.com', token_id: 5 },
    ]);
    const ctx = makeCtx();
    mount(ctx);
    stage('a.example.com');
    fireEvent.click(
      screen.getByRole('button', { name: 'Monitor this website' })
    );
    await waitFor(() => expect(ctx.refresh).toHaveBeenCalled());
    expect(actions.createMonitor).not.toHaveBeenCalled();
    // The existing monitor still counts as part of what was set up.
    expect(ctx.controller.session.operationRefs.monitorUrl).toBe(
      'https://a.example.com'
    );
    expect(ctx.controller.session.operationRefs.tokenIds).toEqual([5]);
  });

  it('never marks an existing website as pending, which would end the step mid-batch', async () => {
    actions.listMonitors.mockResolvedValue([
      { id: 'old', url: 'https://a.example.com', token_id: 5 },
    ]);
    const ctx = makeCtx();
    mount(ctx);
    stage('a.example.com');
    stage('b.example.com');
    fireEvent.click(screen.getByRole('button', { name: 'Monitor 2 websites' }));
    await waitFor(() => expect(ctx.refresh).toHaveBeenCalled());
    const pendingFor = ctx.controller.update.mock.calls
      .map(([fn]) => fn({ progress: {}, operationRefs: {} }))
      .filter(p => p.progress?.pending)
      .map(p => JSON.parse(p.progress.pending.identityKey).url);
    // Only the new address ever carried the marker.
    expect(pendingFor).toEqual(['https://b.example.com']);
  });
});

describe('MonitorStep limits', () => {
  it('counts every existing website, not only the newest few in the summary', async () => {
    actions.listMonitors.mockResolvedValue(
      Array.from({ length: 52 }, (_, i) => ({
        id: `m${i}`,
        url: `https://s${i}.example.com`,
      }))
    );
    mount(
      makeCtx({
        summary: { monitors: { items: [{ url: 'https://s0.example.com' }] } },
      })
    );
    expect(
      await screen.findByText(/Already monitoring 52 websites/)
    ).toBeTruthy();
  });

  it('keeps the saved ids within what the saved progress accepts', async () => {
    const ids = Array.from({ length: 99 }, (_, i) => `old-${i}`);
    const ctx = makeCtx({}, { monitorIds: ids });
    mount(ctx);
    stage('a.example.com');
    stage('b.example.com');
    stage('c.example.com');
    fireEvent.click(screen.getByRole('button', { name: 'Monitor 3 websites' }));
    await waitFor(() => expect(ctx.refresh).toHaveBeenCalled());
    const saved = ctx.controller.session.operationRefs.monitorIds;
    expect(saved).toHaveLength(100);
    expect(saved.at(-1)).toBe('m-https://c.example.com');
  });

  it('refuses an address too long to be saved, in plain words', () => {
    mount(makeCtx());
    stage(`example.com/${'a'.repeat(600)}`);
    expect(screen.getByText(/That address is too long/)).toBeTruthy();
    expect(screen.queryAllByRole('listitem')).toHaveLength(0);
  });
});

describe('MonitorStep domain discovery', () => {
  const open = () =>
    fireEvent.click(screen.getByText('Find the websites on my domain'));

  it('lists what it finds, and adds only the selected ones to the list', async () => {
    actions.discoverHostnames.mockResolvedValue({
      items: [
        { name: 'api.example.com' },
        { name: 'www.example.com' },
        { name: 'other.org' },
        { name: '*.example.com', domains: ['*.example.com'] },
      ],
      partial: false,
      truncated: false,
    });
    mount(makeCtx());
    open();
    type(screen.getByLabelText('Domain to search'), 'https://www.Example.com/');
    fireEvent.click(
      screen.getByRole('button', { name: 'Find websites', hidden: true })
    );
    expect(await screen.findByText('2 found for example.com')).toBeTruthy();
    expect(actions.discoverHostnames).toHaveBeenCalledWith(
      'ws-1',
      'example.com',
      expect.objectContaining({ includeAllSources: false })
    );
    // Wildcards and other domains never appear.
    expect(screen.queryByText('other.org')).toBeNull();
    expect(screen.queryByText('*.example.com')).toBeNull();

    fireEvent.click(screen.getByLabelText('api.example.com'));
    fireEvent.click(
      screen.getByRole('button', { name: 'Add 1 to the list', hidden: true })
    );
    const list = screen.getByRole('list', { name: 'Websites to monitor' });
    expect(list.textContent).toMatch(/https:\/\/api\.example\.com/);
    expect(list.textContent).not.toMatch(/www\.example\.com/);
    expect(actions.createMonitor).not.toHaveBeenCalled();
  });

  it('marks websites already monitored and does not let them be selected again', async () => {
    actions.discoverHostnames.mockResolvedValue({
      items: [{ name: 'api.example.com' }],
      partial: false,
      truncated: false,
    });
    mount(
      makeCtx({
        summary: { monitors: { items: [{ url: 'https://api.example.com' }] } },
      })
    );
    open();
    type(screen.getByLabelText('Domain to search'), 'example.com');
    fireEvent.click(
      screen.getByRole('button', { name: 'Find websites', hidden: true })
    );
    expect(await screen.findByText('Already monitored')).toBeTruthy();
    expect(screen.getByLabelText('api.example.com')).toBeDisabled();
  });

  it('says so when nothing is found, and when the lookup fails', async () => {
    actions.discoverHostnames.mockResolvedValueOnce({
      items: [],
      partial: false,
      truncated: false,
    });
    mount(makeCtx());
    open();
    type(screen.getByLabelText('Domain to search'), 'example.com');
    fireEvent.click(
      screen.getByRole('button', { name: 'Find websites', hidden: true })
    );
    expect(await screen.findByText(/No websites were found/)).toBeTruthy();

    actions.discoverHostnames.mockRejectedValueOnce(
      new Error('Discovery tools are not available')
    );
    fireEvent.click(
      screen.getByRole('button', { name: 'Find websites', hidden: true })
    );
    expect(
      await screen.findByText('Discovery tools are not available')
    ).toBeTruthy();
  });

  it('rejects something that is not a domain without calling the API', async () => {
    mount(makeCtx());
    open();
    type(screen.getByLabelText('Domain to search'), 'not a domain');
    fireEvent.click(
      screen.getByRole('button', { name: 'Find websites', hidden: true })
    );
    expect(
      await screen.findByText('Enter a domain such as example.com.')
    ).toBeTruthy();
    expect(actions.discoverHostnames).not.toHaveBeenCalled();
  });
});

describe('MonitorStep discovery options', () => {
  const open = () =>
    fireEvent.click(screen.getByText('Find the websites on my domain'));
  const search = async (domain = 'example.com') => {
    type(screen.getByLabelText('Domain to search'), domain);
    fireEvent.click(
      screen.getByRole('button', { name: 'Find websites', hidden: true })
    );
  };
  const result = (names, extra = {}) => ({
    items: names.map(name => ({ name })),
    partial: false,
    truncated: false,
    cap: null,
    failedCodes: [],
    ...extra,
  });
  const hostsOf = n =>
    Array.from(
      { length: n },
      (_, i) => `h${String(i).padStart(3, '0')}.example.com`
    );

  it('asks for all sources only when the option is ticked', async () => {
    actions.discoverHostnames.mockResolvedValue(result(['a.example.com']));
    mount(makeCtx());
    open();
    expect(screen.getByText(/finds more but is slower/)).toBeTruthy();
    fireEvent.click(screen.getByLabelText('Include all sources'));
    await search();
    await screen.findByText('1 found for example.com');
    expect(actions.discoverHostnames).toHaveBeenCalledWith(
      'ws-1',
      'example.com',
      expect.objectContaining({ includeAllSources: true })
    );
  });

  it('filters the found websites and selects all the matches, across the list', async () => {
    actions.discoverHostnames.mockResolvedValue(
      result(['api.example.com', 'api2.example.com', 'www.example.com'])
    );
    mount(makeCtx());
    open();
    await search();
    await screen.findByText('3 found for example.com');
    type(screen.getByLabelText('Filter found websites'), 'API');
    expect(screen.queryByLabelText('www.example.com')).toBeNull();
    expect(screen.getByLabelText('api.example.com')).toBeTruthy();
    fireEvent.click(
      screen.getByRole('button', { name: 'Select all matching', hidden: true })
    );
    expect(screen.getByText(/^2 selected, up to 50 fit/)).toBeTruthy();
    fireEvent.click(
      screen.getByRole('button', { name: 'Add 2 to the list', hidden: true })
    );
    const list = screen.getByRole('list', { name: 'Websites to monitor' });
    expect(list.textContent).toMatch(/api\.example\.com/);
    expect(list.textContent).toMatch(/api2\.example\.com/);
    expect(list.textContent).not.toMatch(/www\.example\.com/);
  });

  it('says when the filter matches nothing', async () => {
    actions.discoverHostnames.mockResolvedValue(result(['a.example.com']));
    mount(makeCtx());
    open();
    await search();
    await screen.findByText('1 found for example.com');
    type(screen.getByLabelText('Filter found websites'), 'zzz');
    expect(screen.getByText('No websites match this filter.')).toBeTruthy();
  });

  it('shows 50 per page and moves between pages', async () => {
    actions.discoverHostnames.mockResolvedValue(result(hostsOf(120)));
    mount(makeCtx());
    open();
    await search();
    await screen.findByText('120 found for example.com');
    expect(screen.getByText('1 to 50 of 120')).toBeTruthy();
    expect(screen.getByLabelText('h000.example.com')).toBeTruthy();
    expect(screen.queryByLabelText('h050.example.com')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Next', hidden: true }));
    expect(screen.getByText('51 to 100 of 120')).toBeTruthy();
    expect(screen.getByLabelText('h050.example.com')).toBeTruthy();
    fireEvent.click(
      screen.getByRole('button', { name: 'Previous', hidden: true })
    );
    expect(screen.getByText('1 to 50 of 120')).toBeTruthy();
  });

  it('never selects more than the batch has room for', async () => {
    actions.discoverHostnames.mockResolvedValue(result(hostsOf(120)));
    mount(makeCtx());
    for (let i = 0; i < 45; i += 1) stage(`s${i}.other.com`);
    open();
    await search();
    await screen.findByText('120 found for example.com');
    fireEvent.click(
      screen.getByRole('button', { name: 'Select all', hidden: true })
    );
    expect(
      screen.getByText(/^5 selected, up to 5 fit in the list\./)
    ).toBeTruthy();
    expect(screen.getByLabelText('h010.example.com')).toBeDisabled();
  }, 30000);

  it('shows plain notices for a cut or partial result', async () => {
    actions.discoverHostnames.mockResolvedValue(
      result(['a.example.com'], {
        truncated: true,
        partial: true,
        cap: 500,
      })
    );
    mount(makeCtx());
    open();
    await search();
    expect(await screen.findByText(/cut at 500 websites/)).toBeTruthy();
    expect(screen.queryByText(/subfinder/i)).toBeNull();
  });

  it('summarises how many can still be added', async () => {
    actions.discoverHostnames.mockResolvedValue(
      result(['a.example.com', 'b.example.com'])
    );
    mount(
      makeCtx({
        summary: { monitors: { items: [{ url: 'https://a.example.com' }] } },
      })
    );
    open();
    await search();
    expect(
      await screen.findByText(/1 can be added, 1 already monitored/)
    ).toBeTruthy();
  });

  it.each([
    [
      {
        code: 'DOMAIN_CHECKER_TOOL_MISSING',
        message: 'spawn subfinder ENOENT',
      },
      'Website discovery is not available on this server. Add websites by address instead.',
    ],
    [
      { code: 'DOMAIN_CHECKER_BUSY', message: 'raw', retryAfterSeconds: 60 },
      /already running.*in about 60s/,
    ],
    [{ code: 'DOMAIN_CHECKER_TIMEOUT', message: 'raw' }, /took too long/],
    [
      {
        code: 'DOMAIN_CHECKER_RATE_LIMITED',
        message: 'raw',
        retryAfterSeconds: 30,
      },
      /Too many searches.*about 30s/,
    ],
    [{ code: 'INVALID_DOMAIN', message: 'raw' }, /Enter a domain/],
  ])('words the failure %# in plain language', async (failure, expected) => {
    actions.discoverHostnames.mockRejectedValue(
      Object.assign(new Error(failure.message), failure)
    );
    mount(makeCtx());
    open();
    await search();
    expect(await screen.findByText(expected)).toBeTruthy();
    expect(screen.queryByText(/ENOENT|subfinder|raw/)).toBeNull();
  });

  it('keeps address entry fully usable after discovery is unavailable', async () => {
    actions.discoverHostnames.mockRejectedValue(
      Object.assign(new Error('x'), { code: 'DOMAIN_CHECKER_TOOL_MISSING' })
    );
    const ctx = makeCtx();
    mount(ctx);
    open();
    await search();
    await screen.findByText(/Website discovery is not available/);
    stage('manual.example.com');
    fireEvent.click(
      screen.getByRole('button', { name: 'Monitor this website' })
    );
    await waitFor(() => expect(actions.createMonitor).toHaveBeenCalledTimes(1));
  });

  it('shows progress while searching, keeps the address list editable, and can cancel', async () => {
    let signal;
    actions.discoverHostnames.mockImplementation(
      (_w, _d, opts) =>
        new Promise((_resolve, reject) => {
          ({ signal } = opts);
          signal.addEventListener('abort', () =>
            reject(
              Object.assign(new Error('Search cancelled.'), {
                code: 'ERR_CANCELED',
              })
            )
          );
        })
    );
    mount(makeCtx());
    open();
    await search();
    expect(
      await screen.findByText(/This can take a minute or two\. You can keep/)
    ).toBeTruthy();
    expect(
      screen.getByRole('button', { name: /Searching/, hidden: true })
    ).toBeDisabled();

    // The address list stays usable while the search runs.
    stage('typed.example.com');
    expect(screen.getAllByRole('listitem')).toHaveLength(1);

    fireEvent.click(
      screen.getByRole('button', { name: 'Cancel', hidden: true })
    );
    expect(signal.aborted).toBe(true);
    expect(await screen.findByText('Search cancelled.')).toBeTruthy();
    expect(
      screen.getByRole('button', { name: 'Find websites', hidden: true })
    ).not.toBeDisabled();
    expect(screen.queryByText(/lookup failed|could not finish/i)).toBeNull();
  });

  it('abandons a running search when the step is left', async () => {
    let signal;
    actions.discoverHostnames.mockImplementation((_w, _d, opts) => {
      ({ signal } = opts);
      return new Promise(() => {});
    });
    const view = mount(makeCtx());
    open();
    await search();
    await screen.findByText(/This can take a minute or two\. You can keep/);
    view.unmount();
    expect(signal.aborted).toBe(true);
  });

  it('keeps sections out of the way and sends them with every website when given', async () => {
    mount(makeCtx());
    expect(screen.getByText('More options')).toBeTruthy();
    type(screen.getByLabelText('Sections (optional)'), 'prod, public');
    stage('a.example.com');
    stage('b.example.com');
    fireEvent.click(screen.getByRole('button', { name: 'Monitor 2 websites' }));
    await waitFor(() => expect(actions.createMonitor).toHaveBeenCalledTimes(2));
    for (const [, body] of actions.createMonitor.mock.calls) {
      expect(body.section).toEqual(['prod', 'public']);
    }
  });

  it('sends no section when none is typed', async () => {
    mount(makeCtx());
    stage('a.example.com');
    fireEvent.click(
      screen.getByRole('button', { name: 'Monitor this website' })
    );
    await waitFor(() => expect(actions.createMonitor).toHaveBeenCalledTimes(1));
    expect(actions.createMonitor.mock.calls[0][1].section).toBeUndefined();
  });
});

describe('MonitorStep remembered settings', () => {
  const stored = {
    checkInterval: '5min',
    healthCheckEnabled: true,
    alertAfterFailures: 3,
  };
  const intervalBox = () => screen.getByLabelText('Check every');
  const failuresBox = () =>
    screen.getByLabelText('After failed checks in a row');

  it('prefills the settings applied to the last batch', () => {
    mount(makeCtx({}, { monitorSettings: stored }));
    expect(intervalBox().value).toBe('5min');
    expect(failuresBox().value).toBe('3');
  });

  it('prefills alerts off when that is what was applied', () => {
    mount(
      makeCtx({}, { monitorSettings: { ...stored, healthCheckEnabled: false } })
    );
    expect(intervalBox().value).toBe('5min');
    expect(screen.queryByLabelText('After failed checks in a row')).toBeNull();
  });

  it.each([
    ['an unknown interval', { ...stored, checkInterval: 'weekly' }],
    ['an out of range count', { ...stored, alertAfterFailures: 99 }],
    ['a non-boolean switch', { ...stored, healthCheckEnabled: 'false' }],
    ['a non-numeric count', { ...stored, alertAfterFailures: '3' }],
    ['a missing field', { checkInterval: '5min' }],
    ['a non-object value', 'every 5 minutes'],
  ])('falls back to the defaults for %s', (_name, bad) => {
    mount(makeCtx({}, { monitorSettings: bad }));
    expect(intervalBox().value).toBe('hourly');
    expect(failuresBox().value).toBe('2');
  });

  it('uses the defaults when nothing was stored', () => {
    mount(makeCtx());
    expect(intervalBox().value).toBe('hourly');
    expect(failuresBox().value).toBe('2');
  });

  it('stores the chosen settings with the batch, and only those three values', async () => {
    const ctx = makeCtx();
    mount(ctx);
    stage('a.example.com');
    fireEvent.change(intervalBox(), { target: { value: '5min' } });
    fireEvent.change(failuresBox(), { target: { value: '3' } });
    fireEvent.change(screen.getByPlaceholderText('production, public sites'), {
      target: { value: 'prod' },
    });
    fireEvent.click(
      screen.getByRole('button', { name: 'Monitor this website' })
    );
    await waitFor(() => expect(ctx.refresh).toHaveBeenCalled());
    const patch = ctx.controller.update.mock.calls
      .map(([fn]) => fn({ progress: {}, operationRefs: {} }))
      .find(p => p.operation_refs?.monitorIds);
    expect(patch.operation_refs.monitorSettings).toEqual(stored);
  });

  it('stores the settings after a partial failure too', async () => {
    actions.createMonitor.mockImplementation(async (_w, body) => {
      if (body.url.includes('bad')) throw new Error('Could not reach it');
      return { id: `m-${body.url}`, url: body.url, token_id: 100 };
    });
    const ctx = makeCtx();
    mount(ctx);
    stage('good.example.com');
    stage('bad.example.com');
    fireEvent.change(intervalBox(), { target: { value: '5min' } });
    fireEvent.change(failuresBox(), { target: { value: '3' } });
    fireEvent.click(screen.getByRole('button', { name: 'Monitor 2 websites' }));
    await screen.findByText(/Added 1 of 2/);
    expect(ctx.controller.session.operationRefs.monitorSettings).toEqual(
      stored
    );
  });

  it('keeps earlier settings when a batch creates nothing new', async () => {
    actions.listMonitors.mockResolvedValue([
      { id: 'old', url: 'https://a.example.com', token_id: 5 },
    ]);
    const earlier = { ...stored, checkInterval: 'daily' };
    const ctx = makeCtx({}, { monitorSettings: earlier });
    mount(ctx);
    stage('a.example.com');
    fireEvent.change(intervalBox(), { target: { value: '1min' } });
    fireEvent.click(
      screen.getByRole('button', { name: 'Monitor this website' })
    );
    await waitFor(() => expect(ctx.refresh).toHaveBeenCalled());
    expect(actions.createMonitor).not.toHaveBeenCalled();
    expect(ctx.controller.session.operationRefs.monitorSettings).toEqual(
      earlier
    );
  });

  it('writes nothing when no website could be added', async () => {
    actions.createMonitor.mockRejectedValue(new Error('Unreachable'));
    const ctx = makeCtx();
    mount(ctx);
    stage('bad.example.com');
    fireEvent.click(
      screen.getByRole('button', { name: 'Monitor this website' })
    );
    await screen.findByText('None of the websites could be added.');
    const stored = ctx.controller.update.mock.calls
      .map(([fn]) => fn({ progress: {}, operationRefs: {} }))
      .filter(p => p.operation_refs?.monitorSettings);
    expect(stored).toHaveLength(0);
    expect(
      ctx.controller.session.operationRefs.monitorSettings
    ).toBeUndefined();
  });
});

describe('MonitorStep leave warning', () => {
  const leave = () => {
    const event = new Event('beforeunload', { cancelable: true });
    window.dispatchEvent(event);
    return event;
  };

  it('does not warn with an empty list and an empty address', () => {
    mount(makeCtx());
    expect(leave().defaultPrevented).toBe(false);
  });

  it('warns while an address is typed, and stops when it is cleared', () => {
    mount(makeCtx());
    type(addressBox(), 'a.example.com');
    expect(leave().defaultPrevented).toBe(true);
    type(addressBox(), '');
    expect(leave().defaultPrevented).toBe(false);
  });

  it('warns while websites are listed, and stops after the last is removed', () => {
    mount(makeCtx());
    stage('a.example.com');
    stage('b.example.com');
    expect(leave().defaultPrevented).toBe(true);
    fireEvent.click(
      screen.getByRole('button', { name: 'Remove https://a.example.com' })
    );
    expect(leave().defaultPrevented).toBe(true);
    fireEvent.click(
      screen.getByRole('button', { name: 'Remove https://b.example.com' })
    );
    expect(leave().defaultPrevented).toBe(false);
  });

  it('does not warn while the batch is being created, nor after it succeeded', async () => {
    let release;
    actions.createMonitor.mockImplementation(
      () =>
        new Promise(resolve => {
          release = () =>
            resolve({ id: 'm-1', url: 'https://a.example.com', token_id: 1 });
        })
    );
    const ctx = makeCtx();
    mount(ctx);
    stage('a.example.com');
    expect(leave().defaultPrevented).toBe(true);
    fireEvent.click(
      screen.getByRole('button', { name: 'Monitor this website' })
    );
    await waitFor(() => expect(actions.createMonitor).toHaveBeenCalled());
    expect(leave().defaultPrevented).toBe(false);
    release();
    await waitFor(() => expect(ctx.refresh).toHaveBeenCalled());
    await waitFor(() => expect(leave().defaultPrevented).toBe(false));
  });

  it('warns again for the websites left after a partial failure', async () => {
    actions.createMonitor.mockRejectedValue(new Error('Unreachable'));
    mount(makeCtx());
    stage('bad.example.com');
    fireEvent.click(
      screen.getByRole('button', { name: 'Monitor this website' })
    );
    await screen.findByText('None of the websites could be added.');
    expect(leave().defaultPrevented).toBe(true);
  });

  it('removes the handler when the step is left', () => {
    const { unmount } = mount(makeCtx());
    stage('a.example.com');
    expect(leave().defaultPrevented).toBe(true);
    unmount();
    expect(leave().defaultPrevented).toBe(false);
  });
});

describe('MonitorStep disabled button', () => {
  it('says what is missing until an address is entered', () => {
    mount(makeCtx());
    expect(
      screen.getByRole('button', { name: 'Monitor this website' })
    ).toBeDisabled();
    expect(screen.getByTestId('continue-hint').textContent).toMatch(
      /^To continue: enter a website address/
    );
    stage('a.example.com');
    expect(screen.queryByTestId('continue-hint')).toBeNull();
  });
});
