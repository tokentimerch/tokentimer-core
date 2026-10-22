import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { actions, store, editor } = vi.hoisted(() => ({
  actions: {
    getAlertSettings: vi.fn(),
    putAlertSettings: vi.fn(),
    listContacts: vi.fn(),
    getToken: vi.fn(),
    setTokenContactGroups: vi.fn(),
  },
  store: { settings: null, tokens: {}, plural: true },
  editor: { props: null },
}));

vi.mock('../../src/utils/onboardingActions.js', () => ({
  onboardingActions: actions,
}));

// The test setup forces plural writes on; this suite also needs them off.
vi.mock('../../src/utils/contactGroupPluralWrites.jsx', () => ({
  useContactGroupPluralWrites: () => store.plural,
}));

// The editor is the shared Alert Preferences dialog (needs a router and the
// full page). The journey test covers it for real; here it is a marker with
// one button that saves a new group the way the dialog does.
vi.mock('../../src/components/onboarding/alertGroupEditor.jsx', () => ({
  default: props => {
    editor.props = props;
    return (
      <div data-testid='group-editor'>
        <button
          type='button'
          onClick={() => {
            store.settings.contact_groups.push({
              id: 'legal',
              name: 'Legal',
              email_contact_ids: ['c1'],
              whatsapp_contact_ids: [],
              webhook_names: [],
            });
            props.onSaved();
          }}
        >
          Save new group
        </button>
      </div>
    );
  },
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
const token = (id, groups = [], name = `site-${id}.example.com`) => ({
  id,
  name,
  contact_group_ids: groups,
});

// Websites are tokens 11 and 12; assets are 21 and 22.
function makeCtx({
  goal = 'monitor_https',
  websiteIds = [11, 12],
  assetIds = [],
} = {}) {
  const tokenIds = [...websiteIds, ...assetIds];
  const monitorIds = websiteIds.map(id => `m${id}`);
  return {
    workspaceId: 'ws-1',
    docs: () => [],
    refresh: vi.fn().mockResolvedValue(undefined),
    skip: vi.fn().mockResolvedValue(undefined),
    hold: vi.fn(),
    release: vi.fn(),
    userEmail: 'ana@example.com',
    userName: 'Ana',
    summary: {
      monitors: { items: [] },
      references: {
        tokenIds: { existing: tokenIds },
        assetTokenIds: { existing: assetIds },
        monitorIds: { existing: monitorIds },
      },
    },
    session: {
      intent: { goal },
      progress: {},
      operationRefs: { tokenIds, assetTokenIds: assetIds, monitorIds },
    },
    controller: { update: vi.fn() },
  };
}

const mount = (ctx, props = {}) =>
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <RecipientsStep ctx={ctx} {...props} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );

const row = id => screen.getByTestId(`group-${id}`);
const box = name => screen.findByRole('checkbox', { name });
const GOALS = [
  'monitor_https',
  'track_asset',
  'import_file',
  'import_integration',
  'alerting',
  'certops_observe',
];

beforeEach(() => {
  editor.props = null;
  store.plural = true;
  store.settings = {
    alert_thresholds: [30, 14, 7],
    webhook_urls: [],
    contact_groups: [group('ops', 'Ops'), group('billing', 'Billing', ['c2'])],
    default_contact_group_id: 'ops',
  };
  store.tokens = {
    11: token(11, ['ops']),
    12: token(12, ['ops', 'billing']),
    21: token(21, [], 'Asset one'),
    22: token(22, [], 'Asset two'),
  };
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
  actions.getToken.mockReset().mockImplementation(id => {
    const found = store.tokens[id];
    return found
      ? Promise.resolve(clone(found))
      : Promise.reject(new Error('Token not found'));
  });
  actions.setTokenContactGroups.mockReset().mockImplementation((id, ids) => {
    store.tokens[id].contact_group_ids = clone(ids);
    return Promise.resolve(clone(store.tokens[id]));
  });
});

describe('RecipientsStep layout', () => {
  it('lists the groups with creation and no used-for-setup block', async () => {
    mount(makeCtx());
    expect(
      await screen.findByRole('heading', { name: 'Groups in this workspace' })
    ).toBeVisible();
    expect(
      screen.getByRole('button', { name: 'Create a new group' })
    ).toBeVisible();
    expect(
      screen.getByText(
        'Creating a group does not send alerts to it until it is the default or is selected on an asset.'
      )
    ).toBeVisible();
    expect(screen.queryByTestId('used-for-setup')).toBeNull();
    expect(
      screen.queryByRole('heading', { name: 'Used for this setup' })
    ).toBeNull();
    expect(screen.queryByText('Used for this setup')).toBeNull();
  });

  it('hides Skip for now while a finished step is reviewed', async () => {
    mount(makeCtx(), { reviewing: true });
    await screen.findByRole('button', { name: 'Create a new group' });
    expect(screen.queryByRole('button', { name: 'Skip for now' })).toBeNull();
  });

  it('keeps Skip for now on the live step', async () => {
    mount(makeCtx());
    expect(
      await screen.findByRole('button', { name: 'Skip for now' })
    ).toBeVisible();
  });

  it('makes Create a new group an outline button', async () => {
    mount(makeCtx());
    const button = await screen.findByRole('button', {
      name: 'Create a new group',
    });
    const skip = screen.getByRole('button', { name: 'Skip for now' });
    // Both are outline buttons, so neither carries the solid primary fill.
    expect(getComputedStyle(button).backgroundColor).toBe(
      getComputedStyle(skip).backgroundColor
    );
  });
  it('keeps the Default and Reaches nobody badges', async () => {
    store.settings.contact_groups = [
      group('ops', 'Ops'),
      group('billing', 'Billing', []),
    ];
    mount(makeCtx());
    await box('Ops');
    expect(within(row('ops')).getByText('Default')).toBeVisible();
    expect(within(row('billing')).queryByText('Default')).toBeNull();
    expect(within(row('billing')).getByText('Reaches nobody')).toBeVisible();
    expect(within(row('ops')).queryByText('Reaches nobody')).toBeNull();
  });

  it.each(GOALS)(
    'has no Make default or Use for this setup (%s)',
    async goal => {
      mount(makeCtx({ goal, websiteIds: [], assetIds: [21] }));
      await screen.findByRole('heading', { name: 'Groups in this workspace' });
      expect(screen.queryByRole('button', { name: /Make default/ })).toBeNull();
      expect(
        screen.queryByRole('button', { name: /Use for this setup/ })
      ).toBeNull();
      expect(screen.queryByText('Make default')).toBeNull();
    }
  );

  it('opens the editor from Create a new group with the creation note', async () => {
    mount(makeCtx());
    fireEvent.click(
      await screen.findByRole('button', { name: 'Create a new group' })
    );
    expect(await screen.findByTestId('group-editor')).toBeVisible();
    expect(
      screen.getByText(/Creating a group does not send alerts to it/)
    ).toBeVisible();
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

describe('RecipientsStep ticks', () => {
  beforeEach(() => {
    store.settings.contact_groups.push(group('legal', 'Legal'));
  });

  it('derives all, some and none from the real groups of the items', async () => {
    mount(makeCtx());
    const ops = await box('Ops');
    const billing = await box('Billing');
    const legal = await box('Legal');
    expect(ops).toHaveAttribute('aria-checked', 'true');
    expect(billing).toHaveAttribute('aria-checked', 'mixed');
    expect(legal).toHaveAttribute('aria-checked', 'false');
    expect(row('ops')).toHaveAttribute('data-selected', 'all');
    expect(row('billing')).toHaveAttribute('data-selected', 'some');
    expect(row('legal')).toHaveAttribute('data-selected', 'none');
    expect(actions.getToken).toHaveBeenCalledWith('11');
    expect(actions.getToken).toHaveBeenCalledWith('12');
  });

  it('highlights the selected row and a tick keeps a visible check', async () => {
    mount(makeCtx());
    await box('Ops');
    const selected = within(row('ops')).getByRole('checkbox');
    expect(selected.querySelector('svg')).not.toBeNull();
    expect(
      within(row('legal')).getByRole('checkbox').querySelector('svg')
    ).toBeNull();
  });

  it('ticking writes only the items that lack the group, then reads back', async () => {
    const ctx = makeCtx();
    mount(ctx);
    fireEvent.click(await box('Billing'));
    await waitFor(() =>
      expect(screen.getByRole('checkbox', { name: 'Billing' })).toHaveAttribute(
        'aria-checked',
        'true'
      )
    );
    expect(actions.setTokenContactGroups).toHaveBeenCalledTimes(1);
    expect(actions.setTokenContactGroups).toHaveBeenCalledWith(
      '11',
      ['billing', 'ops'],
      {}
    );
    expect(store.tokens[11].contact_group_ids).toEqual(['billing', 'ops']);
    // Two reads at the start, two more after the write.
    expect(actions.getToken).toHaveBeenCalledTimes(4);
    expect(ctx.refresh).toHaveBeenCalled();
    expect(actions.putAlertSettings).not.toHaveBeenCalled();
  });

  it('sends cost and key size back so the update does not clear them', async () => {
    store.tokens[11].cost = 12.5;
    store.tokens[11].key_size = 2048;
    mount(makeCtx({ websiteIds: [11] }));
    fireEvent.click(await box('Billing'));
    await waitFor(() =>
      expect(actions.setTokenContactGroups).toHaveBeenCalledWith(
        '11',
        ['billing', 'ops'],
        { cost: 12.5, key_size: 2048 }
      )
    );
  });
  it('unticking removes the group from every item and says who falls back', async () => {
    const ctx = makeCtx();
    mount(ctx);
    fireEvent.click(await box('Ops'));
    await waitFor(() =>
      expect(screen.getByRole('checkbox', { name: 'Ops' })).toHaveAttribute(
        'aria-checked',
        'false'
      )
    );
    expect(actions.setTokenContactGroups).toHaveBeenCalledTimes(2);
    expect(actions.setTokenContactGroups).toHaveBeenCalledWith('11', [], {});
    expect(actions.setTokenContactGroups).toHaveBeenCalledWith(
      '12',
      ['billing'],
      {}
    );
    expect(screen.getByTestId('tick-sentence').textContent).toBe(
      'Ticked groups receive alerts for the websites you added in this guide. 1 website has no group and uses the workspace default group "Ops".'
    );
    expect(ctx.refresh).toHaveBeenCalled();
  });

  it('says there is no recipient when untick leaves items without any default', async () => {
    store.settings.default_contact_group_id = null;
    mount(makeCtx());
    fireEvent.click(await box('Ops'));
    await waitFor(() =>
      expect(screen.getByTestId('tick-sentence')).toHaveTextContent(
        /1 website has no group and no default group is set, so there is no recipient until a group is set/
      )
    );
  });

  it('shows which items failed, keeps the ticks true and re-reads', async () => {
    actions.setTokenContactGroups.mockImplementation((id, ids) => {
      if (id === '11') return Promise.reject(new Error('Forbidden'));
      store.tokens[id].contact_group_ids = clone(ids);
      return Promise.resolve({});
    });
    mount(makeCtx());
    // Legal is on neither item, so ticking it writes to both.
    fireEvent.click(await box('Legal'));
    expect(
      await screen.findByText(
        /1 of 2 items could not be updated: site-11\.example\.com\. The ticks show what is saved\./
      )
    ).toBeVisible();
    expect(screen.getByRole('checkbox', { name: 'Legal' })).toHaveAttribute(
      'aria-checked',
      'mixed'
    );
    expect(store.tokens[12].contact_group_ids).toContain('legal');
    expect(store.tokens[11].contact_group_ids).not.toContain('legal');
    expect(actions.getToken).toHaveBeenCalledTimes(4);
  });

  it('reports a write the server did not keep', async () => {
    actions.setTokenContactGroups.mockResolvedValue({});
    mount(makeCtx());
    fireEvent.click(await box('Legal'));
    expect(
      await screen.findByText(/The server did not keep the change for/)
    ).toBeVisible();
    expect(screen.getByRole('checkbox', { name: 'Legal' })).toHaveAttribute(
      'aria-checked',
      'false'
    );
  });

  it('turns ticks off when an item cannot be read', async () => {
    delete store.tokens[12];
    mount(makeCtx());
    expect(
      await screen.findByText(
        'The groups of your items could not be read, so ticking is turned off.'
      )
    ).toBeVisible();
    expect(screen.queryAllByRole('checkbox')).toHaveLength(0);
    expect(
      screen.getByRole('button', { name: 'Create a new group' })
    ).toBeVisible();
  });

  it('turns ticks off past the cap without reading anything', async () => {
    const ids = Array.from({ length: 51 }, (_, i) => 100 + i);
    mount(makeCtx({ goal: 'track_asset', websiteIds: [], assetIds: ids }));
    expect(
      await screen.findByText(/more than 50 items, so groups cannot be ticked/)
    ).toBeVisible();
    expect(screen.queryAllByRole('checkbox')).toHaveLength(0);
    expect(actions.getToken).not.toHaveBeenCalled();
  });

  it('ticks the rest and says which websites have no certificate record', async () => {
    const ctx = makeCtx();
    ctx.session.operationRefs.monitorIds.push('m99');
    ctx.summary.monitors.items.push({ id: 'm99', tokenId: null });
    mount(ctx);
    expect(await screen.findByTestId('no-token-note')).toHaveTextContent(
      '1 website you added has no certificate record yet, so its groups cannot be set here.'
    );
    expect(await box('Ops')).toHaveAttribute('aria-checked', 'true');
    expect(actions.getToken).not.toHaveBeenCalledWith('m99');
  });
  it('shows a new group unticked and attaches nothing to it', async () => {
    mount(makeCtx());
    await box('Ops');
    fireEvent.click(
      await screen.findByRole('button', { name: 'Create a new group' })
    );
    store.settings.contact_groups = store.settings.contact_groups.filter(
      g => g.id !== 'legal'
    );
    fireEvent.click(await screen.findByText('Save new group'));
    const legal = await box('Legal');
    expect(legal).toHaveAttribute('aria-checked', 'false');
    expect(row('legal')).toHaveAttribute('data-selected', 'none');
    expect(actions.setTokenContactGroups).not.toHaveBeenCalled();
  });

  it('toggles with the Space key', async () => {
    mount(makeCtx());
    const legal = await box('Legal');
    legal.focus();
    fireEvent.keyDown(legal, { key: ' ' });
    await waitFor(() =>
      expect(screen.getByRole('checkbox', { name: 'Legal' })).toHaveAttribute(
        'aria-checked',
        'true'
      )
    );
    expect(actions.setTokenContactGroups).toHaveBeenCalledTimes(2);
  });

  it('is busy per group while saving and blocks other ticks', async () => {
    let release;
    actions.setTokenContactGroups.mockImplementation(
      (id, ids) =>
        new Promise(resolve => {
          release = () => {
            store.tokens[id].contact_group_ids = clone(ids);
            resolve({});
          };
        })
    );
    mount(makeCtx({ websiteIds: [11] }));
    fireEvent.click(await box('Legal'));
    await waitFor(() =>
      expect(screen.getByRole('checkbox', { name: 'Legal' })).toHaveAttribute(
        'aria-busy',
        'true'
      )
    );
    expect(screen.getByRole('checkbox', { name: 'Ops' })).toHaveAttribute(
      'aria-disabled',
      'true'
    );
    release();
    await waitFor(() =>
      expect(screen.getByRole('checkbox', { name: 'Legal' })).toHaveAttribute(
        'aria-checked',
        'true'
      )
    );
    expect(screen.getByRole('checkbox', { name: 'Legal' })).not.toHaveAttribute(
      'aria-busy'
    );
  });

  it('replaces the group when the workspace allows one group per item', async () => {
    store.plural = false;
    mount(makeCtx({ websiteIds: [11] }));
    fireEvent.click(await box('Billing'));
    await waitFor(() =>
      expect(store.tokens[11].contact_group_ids).toEqual(['billing'])
    );
    expect(actions.setTokenContactGroups).toHaveBeenCalledWith(
      '11',
      ['billing'],
      {}
    );
  });

  it('ticks websites and assets together when the session has both', async () => {
    mount(
      makeCtx({
        goal: 'track_asset',
        websiteIds: [11],
        assetIds: [21],
      })
    );
    fireEvent.click(await box('Billing'));
    await waitFor(() =>
      expect(screen.getByRole('checkbox', { name: 'Billing' })).toHaveAttribute(
        'aria-checked',
        'true'
      )
    );
    expect(actions.setTokenContactGroups).toHaveBeenCalledWith(
      '11',
      ['billing', 'ops'],
      {}
    );
    expect(actions.setTokenContactGroups).toHaveBeenCalledWith(
      '21',
      ['billing'],
      {}
    );
  });
});

describe('RecipientsStep sentence', () => {
  const sentence = () => screen.findByTestId('tick-sentence');

  it('names the websites and the default group', async () => {
    mount(makeCtx());
    expect((await sentence()).textContent).toBe(
      'Ticked groups receive alerts for the websites you added in this guide. Anything without a group uses the workspace default group "Ops".'
    );
  });

  it('names the assets for the asset goal', async () => {
    mount(makeCtx({ goal: 'track_asset', websiteIds: [], assetIds: [21] }));
    expect((await sentence()).textContent).toMatch(
      /receive alerts for the assets you added in this guide\./
    );
  });

  it('says "assets" and never "websites" for the asset goal when assets have no group', async () => {
    store.tokens[21].contact_group_ids = [];
    mount(makeCtx({ goal: 'track_asset', websiteIds: [], assetIds: [21] }));
    const text = (await sentence()).textContent;
    expect(text).toBe(
      'Ticked groups receive alerts for the assets you added in this guide. 1 asset has no group and uses the workspace default group "Ops".'
    );
    expect(text).not.toMatch(/website/);
  });

  it('names both when the session has both', async () => {
    mount(makeCtx({ goal: 'track_asset', websiteIds: [11], assetIds: [21] }));
    expect((await sentence()).textContent).toMatch(
      /for the websites and assets you added in this guide\./
    );
  });

  it('says so when there is no default group', async () => {
    store.settings.default_contact_group_id = null;
    mount(makeCtx());
    expect((await sentence()).textContent).toMatch(
      /No default group is set, so anything without a group has no recipient\./
    );
  });

  it('asks to add something first when the session has no items', async () => {
    mount(makeCtx({ websiteIds: [] }));
    expect((await sentence()).textContent).toBe(
      'Add something first, then choose its groups here.'
    );
    expect(screen.queryAllByRole('checkbox')).toHaveLength(0);
  });

  it.each(['alerting', 'certops_observe'])(
    'shows no ticks and points at the default for %s',
    async goal => {
      mount(makeCtx({ goal, websiteIds: [11], assetIds: [21] }));
      expect((await sentence()).textContent).toBe(
        'Alerts for this setup use the group chosen elsewhere, or the workspace default group "Ops".'
      );
      expect(screen.queryAllByRole('checkbox')).toHaveLength(0);
      expect(actions.getToken).not.toHaveBeenCalled();
    }
  );

  it.each([
    [
      'import_file',
      'Imported rows use the groups named in your file (contact_group_ids), or the workspace default group "Ops".',
    ],
    [
      'import_integration',
      'Imported assets use the groups chosen in the import dialog, or the workspace default group "Ops".',
    ],
  ])('says where imports get their groups for %s', async (goal, expected) => {
    mount(makeCtx({ goal, websiteIds: [], assetIds: [21] }));
    expect((await sentence()).textContent).toBe(expected);
    expect(screen.queryAllByRole('checkbox')).toHaveLength(0);
    expect(actions.getToken).not.toHaveBeenCalled();
  });
});

describe.each(['track_asset', 'import_file', 'import_integration'])(
  'RecipientsStep %s goal',
  goal => {
    it('still deletes a non-default group', async () => {
      mount(makeCtx({ goal, websiteIds: [], assetIds: [21] }));
      fireEvent.click(
        await screen.findByRole('button', { name: 'Delete Billing' })
      );
      fireEvent.click(
        await screen.findByRole('button', { name: 'Delete group' })
      );
      await waitFor(() =>
        expect(screen.queryByTestId('group-billing')).toBeNull()
      );
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
      /You cannot delete this group yet\. It is the default group\. Make another group the default in Alert Preferences first\./
    );
    expect(button).toHaveAttribute('aria-describedby', why.id);
    // The default is managed elsewhere, so the explanation links there.
    const link = within(why).getByRole('link', {
      name: 'Open Alert Preferences',
    });
    expect(link).toHaveAttribute('href', '/workspace-preferences');
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
      screen.getByText(
        /default and only group\. Create another group, then make it the default in Alert Preferences\./
      )
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
      /It is the default group\. Make another group the default in Alert Preferences first/
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

describe('RecipientsStep confirmation for goals without ticks', () => {
  const confirmButton = () =>
    screen.findByRole('button', { name: 'Use these groups' });

  it.each(['import_file', 'import_integration', 'alerting', 'certops_observe'])(
    'records the confirmation for %s',
    async goal => {
      const ctx = makeCtx({ goal, websiteIds: [], assetIds: [] });
      mount(ctx);
      fireEvent.click(await confirmButton());
      await waitFor(() => expect(ctx.controller.update).toHaveBeenCalled());
      const patch = ctx.controller.update.mock.calls[0][0]({
        progress: { skipped: [] },
      });
      expect(patch.progress).toEqual({
        skipped: [],
        recipientsConfirmedFor: goal,
      });
      await waitFor(() => expect(ctx.refresh).toHaveBeenCalled());
    }
  );

  it.each(['monitor_https', 'track_asset'])(
    'offers no confirmation for %s, ticks decide',
    async goal => {
      mount(makeCtx({ goal, websiteIds: [11], assetIds: [] }));
      await screen.findByRole('button', { name: 'Skip for now' });
      expect(
        screen.queryByRole('button', { name: 'Use these groups' })
      ).toBeNull();
    }
  );

  it('keeps the button off while the default group reaches nobody', async () => {
    store.settings.contact_groups = [group('ops', 'Ops', [])];
    mount(makeCtx({ goal: 'certops_observe', websiteIds: [] }));
    expect(await confirmButton()).toBeDisabled();
    expect(screen.getByTestId('continue-hint')).toHaveTextContent(
      'set a default group that has a recipient'
    );
  });

  it('shows no confirmation while a finished step is reviewed', async () => {
    mount(makeCtx({ goal: 'import_file', websiteIds: [] }), {
      reviewing: true,
    });
    await screen.findByRole('button', { name: 'Create a new group' });
    expect(
      screen.queryByRole('button', { name: 'Use these groups' })
    ).toBeNull();
  });
});

describe('RecipientsStep Continue for goals with ticks', () => {
  const doneGroups = { 11: ['ops'], 12: ['ops', 'billing'] };
  const withGroups = (ctx, groups) => {
    ctx.summary.references.tokenGroups = groups;
    return ctx;
  };
  const continueButton = () =>
    screen.findByRole('button', { name: 'Continue' });

  beforeEach(() => {
    store.settings.contact_groups.push(group('legal', 'Legal'));
  });

  it.each(['monitor_https', 'track_asset'])(
    'asks the guide to keep the step open for %s',
    async goal => {
      const ctx = makeCtx({ goal, websiteIds: [11], assetIds: [21] });
      mount(ctx);
      await continueButton();
      expect(ctx.hold).toHaveBeenCalledWith('recipients');
    }
  );

  it('keeps Continue off until every item carries a group', async () => {
    mount(makeCtx());
    expect(await continueButton()).toBeDisabled();
    expect(screen.getByTestId('continue-hint')).toHaveTextContent(
      'tick a group'
    );
  });

  it('enables Continue when the step is done and Continue leaves the step', async () => {
    const ctx = withGroups(makeCtx(), doneGroups);
    mount(ctx);
    const button = await continueButton();
    await waitFor(() => expect(button).toBeEnabled());
    expect(ctx.release).not.toHaveBeenCalled();
    fireEvent.click(button);
    expect(ctx.release).toHaveBeenCalledTimes(1);
  });

  it('never leaves the step when groups are ticked one after the other', async () => {
    const ctx = withGroups(makeCtx(), doneGroups);
    mount(ctx);
    fireEvent.click(await box('Billing'));
    await waitFor(() =>
      expect(screen.getByRole('checkbox', { name: 'Billing' })).toHaveAttribute(
        'aria-checked',
        'true'
      )
    );
    fireEvent.click(await box('Legal'));
    await waitFor(() =>
      expect(screen.getByRole('checkbox', { name: 'Legal' })).toHaveAttribute(
        'aria-checked',
        'true'
      )
    );
    expect(actions.setTokenContactGroups).toHaveBeenCalledTimes(3);
    expect(ctx.release).not.toHaveBeenCalled();
    expect(ctx.skip).not.toHaveBeenCalled();
    fireEvent.click(await box('Legal'));
    await waitFor(() =>
      expect(screen.getByRole('checkbox', { name: 'Legal' })).toHaveAttribute(
        'aria-checked',
        'false'
      )
    );
    expect(actions.setTokenContactGroups).toHaveBeenCalledTimes(5);
    expect(ctx.release).not.toHaveBeenCalled();
  });

  it('shows no Continue and no hold while a finished step is reviewed', async () => {
    const ctx = withGroups(makeCtx(), doneGroups);
    mount(ctx, { reviewing: true });
    await box('Ops');
    expect(screen.queryByRole('button', { name: 'Continue' })).toBeNull();
    expect(ctx.hold).not.toHaveBeenCalled();
  });

  it.each(['import_file', 'certops_observe'])(
    'does not hold or add Continue for %s',
    async goal => {
      const ctx = makeCtx({ goal, websiteIds: [], assetIds: [] });
      mount(ctx);
      await screen.findByRole('button', { name: 'Use these groups' });
      expect(screen.queryByRole('button', { name: 'Continue' })).toBeNull();
      expect(ctx.hold).not.toHaveBeenCalled();
    }
  );
});
