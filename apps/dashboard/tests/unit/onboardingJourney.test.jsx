import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

// The wizard talks to the server only through these three modules, so a
// stateful fake server here exercises the real page, planner and steps.
const server = vi.hoisted(() => ({ state: null }));

vi.mock('../../src/components/DashboardShell', () => ({
  default: ({ children }) => <div>{children}</div>,
}));
vi.mock('../../src/hooks/useDashboardShellProps', () => ({
  useDashboardShellProps: () => ({}),
}));
vi.mock('../../src/components/SEO.jsx', () => ({ default: () => null }));
vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: 'ws-1' }),
}));

vi.mock('../../src/utils/onboardingApi.js', () => {
  const clone = v => JSON.parse(JSON.stringify(v));
  class RevisionConflictError extends Error {
    constructor(current) {
      super('conflict');
      this.name = 'RevisionConflictError';
      this.current = current;
    }
  }
  return {
    RevisionConflictError,
    onboardingAPI: {
      getCapabilities: async () => ({
        docsBaseUrl: 'https://tokentimer.ch/docs/self-hosted',
        items: [
          { id: 'monitoring.endpoint', state: 'ready', blockers: [] },
          { id: 'assets.manual', state: 'ready', blockers: [] },
          { id: 'alerts.contact_groups', state: 'ready', blockers: [] },
        ],
      }),
      getSession: async () => clone(server.state.session),
      putSession: async (_w, _f, body) => {
        const s = server.state.session;
        if (body.expectedRevision !== s.revision) {
          throw new RevisionConflictError(clone(s));
        }
        if (body.intent) s.intent = body.intent;
        if (body.progress) s.progress = body.progress;
        if (body.operation_refs) s.operationRefs = body.operation_refs;
        if (body.status) s.status = body.status;
        s.revision += 1;
        return clone(s);
      },
      getSummary: async () => clone(server.summary()),
    },
  };
});

vi.mock('../../src/utils/onboardingActions.js', async () => {
  const real = await vi.importActual('../../src/utils/onboardingActions.js');
  const clone = v => JSON.parse(JSON.stringify(v));
  return {
    ...real,
    onboardingActions: {
      listMonitors: async () => clone(server.state.monitors),
      createMonitor: async (_w, { url }) => {
        server.state.calls.createMonitor += 1;
        const monitor = {
          id: `m${server.state.monitors.length + 1}`,
          url,
          token_id: 41,
          ssl_valid_to: '2027-03-01T00:00:00Z',
        };
        server.state.monitors.push(monitor);
        return clone(monitor);
      },
      getAlertSettings: async () => clone(server.state.alert),
      putAlertSettings: async (_w, body) => {
        server.state.calls.putAlertSettings += 1;
        Object.assign(server.state.alert, body);
        return clone(server.state.alert);
      },
      listContacts: async () => clone(server.state.contacts),
      createContact: async (_w, body) => {
        server.state.calls.createContact += 1;
        const contact = { id: `c${server.state.contacts.length + 1}`, ...body };
        server.state.contacts.push(contact);
        return clone(contact);
      },
      getToken: async () => ({
        id: 41,
        alert_state: { eligibility: { eligible_channels: ['email'] } },
      }),
    },
  };
});

import OnboardingPage from '../../src/components/onboarding/OnboardingPage.jsx';

// Minimal stand-ins for user-event, built on fireEvent.
const user = {
  click: async el => {
    fireEvent.click(el);
  },
  type: async (el, value) => {
    fireEvent.change(el, { target: { value } });
  },
};

function freshServer() {
  const state = {
    session: {
      exists: false,
      revision: 0,
      intent: {},
      progress: {},
      operationRefs: {},
    },
    monitors: [],
    contacts: [],
    alert: { contact_groups: [], default_contact_group_id: null },
    calls: { createMonitor: 0, putAlertSettings: 0, createContact: 0 },
  };
  server.state = state;
  server.summary = () => {
    const contactsWithEmail = new Set(
      state.contacts.filter(c => c.details?.email).map(c => c.id)
    );
    const def = state.alert.contact_groups.find(
      g => g.id === state.alert.default_contact_group_id
    );
    return {
      assets: { total: state.monitors.length },
      monitors: {
        total: state.monitors.length,
        items: state.monitors.map(m => ({
          id: m.id,
          url: m.url,
          tokenId: m.token_id,
          certificateExpiresAt: m.ssl_valid_to,
        })),
      },
      alerts: {
        smtpConfigured: true,
        contactGroups: {
          defaultHasEmailRecipient: Boolean(
            def?.email_contact_ids?.some(id => contactsWithEmail.has(id))
          ),
        },
      },
      references: {
        tokenIds: { existing: [], missing: [] },
        monitorIds: { existing: [], missing: [] },
      },
    };
  };
  return state;
}

function mount() {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter>
          <OnboardingPage
            session={{ email: 'ana@example.com', name: 'Ana Lopez' }}
            onLogout={() => {}}
            onAccountClick={() => {}}
          />
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

describe('first-value onboarding journey', () => {
  beforeEach(() => {
    freshServer();
  });

  it('takes a new user from a goal to a verified monitor', async () => {
    mount();

    await user.click(
      await screen.findByLabelText(/Monitor a website certificate/i)
    );
    await user.click(screen.getByRole('button', { name: 'Continue' }));

    await user.type(
      await screen.findByPlaceholderText('https://example.com'),
      'example.com'
    );
    await user.click(screen.getByRole('button', { name: 'Add website' }));

    // The recipient step defaults to the signed-in user's own email.
    const email = await screen.findByLabelText(/Email/);
    expect(email).toHaveValue('ana@example.com');
    await user.click(screen.getByRole('button', { name: 'Save recipient' }));

    expect(await screen.findByText('Alerts have a recipient')).toBeVisible();
    expect(screen.getByText(/Will notify through: email/)).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Finish setup' }));

    expect(await screen.findByText('You are set up')).toBeVisible();
    expect(server.state.session.status).toBe('completed');
    expect(server.state.calls.createMonitor).toBe(1);
    expect(server.state.alert.default_contact_group_id).toMatch(/^onboarding-/);
  });

  it('resumes on another device without creating anything twice', async () => {
    const first = mount();
    await user.click(
      await screen.findByLabelText(/Monitor a website certificate/i)
    );
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    await user.type(
      await screen.findByPlaceholderText('https://example.com'),
      'example.com'
    );
    await user.click(screen.getByRole('button', { name: 'Add website' }));
    await screen.findByLabelText(/Email/);
    first.unmount();

    // New device: same server state, fresh page. It lands on the next step.
    mount();
    expect(await screen.findByLabelText(/Email/)).toBeVisible();
    expect(screen.queryByPlaceholderText('https://example.com')).toBeNull();
    expect(server.state.calls.createMonitor).toBe(1);
  });

  it('adopts a monitor created before the session recorded it', async () => {
    // Backend succeeded, browser closed before the result was saved: the
    // session has the pending marker and the goal, but no recorded URL.
    server.state.monitors.push({
      id: 'm1',
      url: 'https://example.com',
      token_id: 41,
      ssl_valid_to: '2027-03-01T00:00:00Z',
    });
    server.state.session = {
      exists: true,
      revision: 3,
      intent: { goal: 'monitor_https' },
      progress: {
        pending: {
          id: 'op-1',
          kind: 'monitor',
          identityKey: JSON.stringify({ url: 'https://example.com' }),
        },
      },
      operationRefs: {},
    };
    mount();
    // It must not ask for the URL again nor create a second monitor.
    expect(await screen.findByLabelText(/Email/)).toBeVisible();
    expect(screen.queryByPlaceholderText('https://example.com')).toBeNull();
    expect(server.state.calls.createMonitor).toBe(0);
    // The result is now recorded and the pending marker cleared.
    await waitFor(() =>
      expect(server.state.session.operationRefs.monitorUrl).toBe(
        'https://example.com'
      )
    );
    expect(server.state.session.progress.pending).toBeUndefined();
  });
  it('reopens the monitor step if the monitor is deleted', async () => {
    server.state.session = {
      exists: true,
      revision: 2,
      intent: { goal: 'monitor_https' },
      progress: {},
      operationRefs: { monitorUrl: 'https://gone.example' },
    };
    mount();
    expect(
      await screen.findByPlaceholderText('https://example.com')
    ).toBeVisible();
  });

  it('does not offer a goal the user cannot use', async () => {
    // Re-mock capabilities for this case only.
    const mod = await import('../../src/utils/onboardingApi.js');
    const spy = vi
      .spyOn(mod.onboardingAPI, 'getCapabilities')
      .mockResolvedValue({
        docsBaseUrl: 'https://tokentimer.ch/docs/self-hosted',
        items: [
          {
            id: 'monitoring.endpoint',
            state: 'role_handoff',
            blockers: [
              {
                code: 'ROLE_REQUIRED',
                remediation: 'Ask a workspace manager.',
              },
            ],
          },
          { id: 'assets.manual', state: 'ready', blockers: [] },
          { id: 'alerts.contact_groups', state: 'ready', blockers: [] },
        ],
      });
    mount();
    const radio = await screen.findByLabelText(
      /Monitor a website certificate/i
    );
    expect(radio).toBeDisabled();
    expect(screen.getByText('Ask a workspace manager.')).toBeVisible();
    spy.mockRestore();
  });
});
