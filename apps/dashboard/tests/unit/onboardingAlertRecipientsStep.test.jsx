import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { actions, store } = vi.hoisted(() => ({
  actions: {
    getAlertSettings: vi.fn(),
    putAlertSettings: vi.fn(),
    listContacts: vi.fn(),
    getToken: vi.fn(),
  },
  store: { settings: null, tokens: {} },
}));

vi.mock('../../src/utils/onboardingActions.js', () => ({
  onboardingActions: actions,
}));

import { RecipientsStep } from '../../src/components/onboarding/alertRecipientsStep.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const clone = v => JSON.parse(JSON.stringify(v));
const group = (id, name, emails = ['c1']) => ({
  id,
  name,
  email_contact_ids: emails,
  whatsapp_contact_ids: [],
  webhook_names: [],
});

function makeCtx({ goal = 'monitor_https', assetIds = [] } = {}) {
  return {
    workspaceId: 'ws-1',
    docs: () => [],
    refresh: vi.fn().mockResolvedValue(undefined),
    skip: vi.fn().mockResolvedValue(undefined),
    userEmail: 'ana@example.com',
    userName: 'Ana',
    summary: { references: { assetTokenIds: { existing: assetIds } } },
    session: {
      intent: { goal },
      progress: {},
      operationRefs: { assetTokenIds: assetIds },
    },
    controller: { update: vi.fn() },
  };
}

const mount = ctx =>
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <RecipientsStep ctx={ctx} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );

const row = id => screen.getByTestId(`group-${id}`);

beforeEach(() => {
  store.settings = {
    alert_thresholds: [30, 14, 7],
    webhook_urls: [],
    contact_groups: [group('ops', 'Ops'), group('billing', 'Billing', ['c2'])],
    default_contact_group_id: 'ops',
  };
  store.tokens = {};
  actions.getAlertSettings
    .mockReset()
    .mockImplementation(() => Promise.resolve(clone(store.settings)));
  actions.putAlertSettings.mockReset().mockImplementation((_w, body) => {
    Object.assign(store.settings, clone(body));
    return Promise.resolve(clone(store.settings));
  });
  actions.listContacts.mockReset().mockResolvedValue([
    { id: 'c1', details: { email: 'ana@example.com' } },
    { id: 'c2', details: { email: 'bill@example.com' } },
  ]);
  actions.getToken
    .mockReset()
    .mockImplementation(id => Promise.resolve(clone(store.tokens[id])));
});

describe('RecipientsStep layout', () => {
  it('separates what this setup uses from the groups that exist', async () => {
    mount(makeCtx());
    expect(
      await screen.findByRole('heading', { name: 'Used for this setup' })
    ).toBeVisible();
    expect(
      screen.getByRole('heading', { name: 'Groups in this workspace' })
    ).toBeVisible();
    expect(
      screen.getByRole('button', { name: 'Create a new group' })
    ).toBeVisible();
    expect(
      screen.getByText(
        'Creating a group does not send alerts to it until it is the default or is selected on an asset.'
      )
    ).toBeVisible();
  });

  it('names the default group for the website goal', async () => {
    mount(makeCtx({ goal: 'monitor_https' }));
    const block = await screen.findByTestId('used-for-setup');
    expect(block.textContent).toMatch(
      /Websites you add here use the default group "Ops"/
    );
    expect(block.textContent).toMatch(/attaches no group to a website/);
  });

  it('marks the default group as both Default and Used for this setup', async () => {
    mount(makeCtx());
    await screen.findByTestId('used-for-setup');
    const ops = within(row('ops'));
    expect(ops.getByText('Default')).toBeVisible();
    expect(ops.getByText('Used for this setup')).toBeVisible();
    const billing = within(row('billing'));
    expect(billing.queryByText('Default')).toBeNull();
    expect(billing.queryByText('Used for this setup')).toBeNull();
  });

  it('keeps a new group unused until it becomes the default', async () => {
    mount(makeCtx());
    await screen.findByTestId('used-for-setup');
    // Billing exists but receives nothing for this setup yet.
    expect(
      within(row('billing')).queryByText('Used for this setup')
    ).toBeNull();

    fireEvent.click(
      within(row('billing')).getByRole('button', {
        name: 'Use for this setup',
      })
    );
    await waitFor(() =>
      expect(within(row('billing')).getByText('Default')).toBeVisible()
    );
    expect(actions.putAlertSettings).toHaveBeenCalledWith('ws-1', {
      default_contact_group_id: 'billing',
    });
    expect(
      within(row('billing')).getByText('Used for this setup')
    ).toBeVisible();
    expect(within(row('ops')).queryByText('Default')).toBeNull();
    expect(within(row('ops')).queryByText('Used for this setup')).toBeNull();
    expect(screen.getByTestId('used-for-setup').textContent).toMatch(
      /default group "Billing"/
    );
  });

  it('describes the default group for goals that attach no group', async () => {
    mount(makeCtx({ goal: 'certops_observe' }));
    const block = await screen.findByTestId('used-for-setup');
    expect(block.textContent).toMatch(/agents and their certificates/);
    expect(block.textContent).toMatch(/default group "Ops"/);
  });

  it('warns inside the block when the default reaches nobody', async () => {
    store.settings.contact_groups = [
      group('ops', 'Ops', []),
      group('billing', 'Billing', ['c2']),
    ];
    mount(makeCtx());
    const block = await screen.findByTestId('used-for-setup');
    expect(block.textContent).toMatch(/"Ops" reaches nobody yet/);
  });

  it('says when no default group is set', async () => {
    store.settings.default_contact_group_id = null;
    mount(makeCtx());
    const block = await screen.findByTestId('used-for-setup');
    expect(block.textContent).toMatch(/none is set/);
    expect(block.textContent).toMatch(
      /Make one of the groups below the default/
    );
  });

  it('opens the editor from Create a new group with the creation note', async () => {
    mount(makeCtx());
    fireEvent.click(
      await screen.findByRole('button', { name: 'Create a new group' })
    );
    expect(await screen.findByTestId('group-editor')).toBeVisible();
    expect(
      screen.getByText(/Creating a group does not send alerts to it/)
    ).toBeVisible();
    expect(screen.getByLabelText(/^Email$/)).toHaveValue('ana@example.com');
  });

  it('still lets the person skip', async () => {
    const ctx = makeCtx();
    mount(ctx);
    fireEvent.click(
      await screen.findByRole('button', { name: 'Skip for now' })
    );
    await waitFor(() => expect(ctx.skip).toHaveBeenCalledWith('recipients'));
  });
});

describe.each(['track_asset', 'import_file', 'import_integration'])(
  'RecipientsStep %s goal',
  goal => {
    it('states no per-asset rule, no counts and no green badge', async () => {
      store.tokens = {
        1: { id: 1, contact_group_ids: ['billing'] },
        2: { id: 2, contact_group_ids: [] },
      };
      mount(makeCtx({ goal, assetIds: [1, 2] }));
      expect(
        await screen.findByRole('heading', { name: 'Groups in this workspace' })
      ).toBeVisible();
      expect(screen.queryByTestId('used-for-setup')).toBeNull();
      expect(
        screen.queryByRole('heading', { name: 'Used for this setup' })
      ).toBeNull();
      expect(screen.queryByText(/ticked/)).toBeNull();
      expect(screen.queryByText(/Groups on the/)).toBeNull();
      expect(screen.queryByText('Used for this setup')).toBeNull();
      // Assets are no longer read, since nothing would show them.
      expect(actions.getToken).not.toHaveBeenCalled();
    });

    it('keeps Default, Make default, Reaches nobody and creation', async () => {
      store.settings.contact_groups = [
        group('ops', 'Ops'),
        group('billing', 'Billing', []),
      ];
      mount(makeCtx({ goal }));
      expect(
        await within(await screen.findByTestId('group-ops')).findByText(
          'Default'
        )
      ).toBeVisible();
      expect(within(row('billing')).getByText('Reaches nobody')).toBeVisible();
      expect(
        screen.queryByRole('button', { name: 'Use for this setup' })
      ).toBeNull();
      expect(
        screen.getByText(/Creating a group does not send alerts to it/)
      ).toBeVisible();
      expect(
        screen.getByRole('button', { name: 'Create a new group' })
      ).toBeVisible();

      fireEvent.click(
        within(row('billing')).getByRole('button', { name: 'Make default' })
      );
      await waitFor(() =>
        expect(within(row('billing')).getByText('Default')).toBeVisible()
      );
      expect(actions.putAlertSettings).toHaveBeenCalledWith('ws-1', {
        default_contact_group_id: 'billing',
      });
      expect(screen.queryByText('Used for this setup')).toBeNull();
    });

    it('still deletes a non-default group', async () => {
      mount(makeCtx({ goal }));
      fireEvent.click(
        await screen.findByRole('button', { name: 'Delete Billing' })
      );
      fireEvent.click(
        await screen.findByRole('button', { name: 'Delete group' })
      );
      await waitFor(() =>
        expect(screen.queryByTestId('group-billing')).toBeNull()
      );
      expect(screen.queryByTestId('used-for-setup')).toBeNull();
    });
  }
);

describe('RecipientsStep delete', () => {
  it('asks for confirmation naming the group before changing anything', async () => {
    mount(makeCtx());
    fireEvent.click(
      await screen.findByRole('button', { name: 'Delete Billing' })
    );
    expect(
      await screen.findByText('Delete the group "Billing"?')
    ).toBeInTheDocument();
    expect(
      screen.getByText(/will use the default group "Ops" instead/)
    ).toBeInTheDocument();
    expect(screen.getByText('This cannot be undone.')).toBeInTheDocument();
    expect(actions.putAlertSettings).not.toHaveBeenCalled();
  });

  it('does nothing when the confirmation is cancelled', async () => {
    mount(makeCtx());
    fireEvent.click(
      await screen.findByRole('button', { name: 'Delete Billing' })
    );
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }));
    await waitFor(() =>
      expect(screen.queryByText('Delete the group "Billing"?')).toBeNull()
    );
    expect(actions.putAlertSettings).not.toHaveBeenCalled();
    expect(row('billing')).toBeVisible();
  });

  it('removes only that group, reads settings back and refreshes the wizard', async () => {
    const ctx = makeCtx();
    mount(ctx);
    fireEvent.click(
      await screen.findByRole('button', { name: 'Delete Billing' })
    );
    fireEvent.click(
      await screen.findByRole('button', { name: 'Delete group' })
    );

    await waitFor(() =>
      expect(screen.queryByTestId('group-billing')).toBeNull()
    );
    expect(actions.putAlertSettings).toHaveBeenCalledTimes(1);
    const [, body] = actions.putAlertSettings.mock.calls[0];
    expect(body.contact_groups.map(g => g.id)).toEqual(['ops']);
    // The default group is left alone.
    expect(body).not.toHaveProperty('default_contact_group_id');
    expect(store.settings.default_contact_group_id).toBe('ops');
    // Fresh read before, read-back after, and a reload for the list.
    expect(actions.getAlertSettings.mock.calls.length).toBeGreaterThanOrEqual(
      3
    );
    expect(ctx.refresh).toHaveBeenCalled();
    expect(within(row('ops')).getByText('Default')).toBeVisible();
  });

  it('blocks deleting the default group and explains why', async () => {
    mount(makeCtx());
    const button = await screen.findByRole('button', { name: 'Delete Ops' });
    expect(button).toBeDisabled();
    const why = within(row('ops')).getByText(
      /You cannot delete this group yet\. It is the default group\. Make another group the default first\./
    );
    expect(button).toHaveAttribute('aria-describedby', why.id);
    expect(
      screen.getByRole('button', { name: 'Delete Billing' })
    ).toBeEnabled();
  });

  it('blocks deleting the only group, which leaves nobody to alert', async () => {
    store.settings.contact_groups = [group('ops', 'Ops')];
    mount(makeCtx());
    const button = await screen.findByRole('button', { name: 'Delete Ops' });
    expect(button).toBeDisabled();
    expect(
      screen.getByText(/default and only group\. Create another group/)
    ).toBeVisible();
  });

  it('shows the error and keeps the group when the write fails', async () => {
    actions.putAlertSettings.mockRejectedValueOnce(new Error('Server said no'));
    const ctx = makeCtx();
    mount(ctx);
    fireEvent.click(
      await screen.findByRole('button', { name: 'Delete Billing' })
    );
    fireEvent.click(
      await screen.findByRole('button', { name: 'Delete group' })
    );
    expect(await screen.findByText('Server said no')).toBeVisible();
    expect(row('billing')).toBeVisible();
    expect(ctx.refresh).not.toHaveBeenCalled();
  });

  it('reports a delete that the server did not keep', async () => {
    // The read-back still lists the group, as if the write had been trimmed.
    actions.putAlertSettings.mockImplementation(() => Promise.resolve({}));
    const ctx = makeCtx();
    mount(ctx);
    fireEvent.click(
      await screen.findByRole('button', { name: 'Delete Billing' })
    );
    fireEvent.click(
      await screen.findByRole('button', { name: 'Delete group' })
    );
    expect(
      await screen.findByText('The group could not be deleted.')
    ).toBeVisible();
    expect(row('billing')).toBeVisible();
  });

  it('refuses to delete a group that became the default meanwhile', async () => {
    mount(makeCtx());
    fireEvent.click(
      await screen.findByRole('button', { name: 'Delete Billing' })
    );
    // Another tab made Billing the default after this page was drawn.
    store.settings.default_contact_group_id = 'billing';
    fireEvent.click(
      await screen.findByRole('button', { name: 'Delete group' })
    );
    expect(await screen.findByRole('alert')).toHaveTextContent(
      /It is the default group\. Make another group/
    );
    expect(actions.putAlertSettings).not.toHaveBeenCalled();
  });

  it('does not claim a recipient when the default reaches nobody after a delete', async () => {
    store.settings.contact_groups = [
      group('ops', 'Ops', []),
      group('billing', 'Billing', ['c2']),
    ];
    mount(makeCtx());
    fireEvent.click(
      await screen.findByRole('button', { name: 'Delete Billing' })
    );
    fireEvent.click(
      await screen.findByRole('button', { name: 'Delete group' })
    );
    await waitFor(() =>
      expect(screen.queryByTestId('group-billing')).toBeNull()
    );
    const block = screen.getByTestId('used-for-setup');
    expect(block.textContent).toMatch(/"Ops" reaches nobody yet/);
    expect(within(row('ops')).getByText('Reaches nobody')).toBeVisible();
  });

  it('treats a group that is already gone as deleted without writing', async () => {
    mount(makeCtx());
    fireEvent.click(
      await screen.findByRole('button', { name: 'Delete Billing' })
    );
    store.settings.contact_groups = [group('ops', 'Ops')];
    fireEvent.click(
      await screen.findByRole('button', { name: 'Delete group' })
    );
    await waitFor(() =>
      expect(screen.queryByTestId('group-billing')).toBeNull()
    );
    expect(actions.putAlertSettings).not.toHaveBeenCalled();
  });
});
