import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { actions } = vi.hoisted(() => ({
  actions: {
    getAlertSettings: vi.fn(),
    findTokens: vi.fn(),
    createToken: vi.fn(),
  },
}));

vi.mock('../../src/utils/onboardingActions.js', () => ({
  onboardingActions: actions,
}));

import { AssetStep } from '../../src/components/onboarding/assetStep.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

function makeCtx() {
  const session = { progress: {}, operationRefs: {}, intent: {} };
  return {
    workspaceId: 'ws-1',
    docs: () => [],
    refresh: vi.fn().mockResolvedValue(undefined),
    onDone: vi.fn(),
    controller: {
      update: vi.fn(async fn => {
        const patch = fn(session);
        if (patch.progress) session.progress = patch.progress;
        if (patch.operation_refs) session.operationRefs = patch.operation_refs;
      }),
      session,
    },
  };
}

const mount = ctx =>
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <AssetStep ctx={ctx} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );

const nameBox = () => screen.getByPlaceholderText('Payments API key');
const setName = value => fireEvent.change(nameBox(), { target: { value } });
const addToList = () =>
  fireEvent.click(screen.getByRole('button', { name: 'Add to the list' }));
const stageNamed = value => {
  setName(value);
  addToList();
};

let nextId;
beforeEach(() => {
  nextId = 1;
  actions.getAlertSettings.mockReset().mockResolvedValue({
    contact_groups: [],
    default_contact_group_id: '',
  });
  actions.findTokens.mockReset().mockResolvedValue([]);
  actions.createToken.mockReset().mockImplementation(async body => ({
    id: nextId++,
    name: body.name,
  }));
});

describe('AssetStep list', () => {
  it('collects several assets and clears the form between them', () => {
    mount(makeCtx());
    stageNamed('Payments API key');
    expect(nameBox()).toHaveValue('');
    stageNamed('Billing API key');
    const list = screen.getByRole('list', { name: 'Assets to create' });
    expect(list.textContent).toMatch(/Payments API key/);
    expect(list.textContent).toMatch(/Billing API key/);
    expect(screen.getAllByRole('listitem')).toHaveLength(2);
    expect(actions.createToken).not.toHaveBeenCalled();
    expect(
      screen.getByRole('button', { name: 'Create 2 assets' })
    ).toBeTruthy();
  });

  it('keeps the chosen kind for the next asset', () => {
    mount(makeCtx());
    const license = () => screen.getByRole('radio', { name: /License/ });
    fireEvent.click(license());
    stageNamed('Editor license');
    expect(license()).toBeChecked();
  });

  it('describes each listed asset in words', () => {
    mount(makeCtx());
    stageNamed('Payments API key');
    expect(
      screen.getByRole('list', { name: 'Assets to create' }).textContent
    ).toMatch(/Key\/Secret/);
  });

  it('refuses the same asset twice', () => {
    mount(makeCtx());
    stageNamed('Payments API key');
    stageNamed('payments api key');
    expect(screen.getByText('This asset is already in the list.')).toBeTruthy();
    expect(screen.getAllByRole('listitem')).toHaveLength(1);
  });

  it('refuses a draft that fails the product rules and lists nothing', () => {
    mount(makeCtx());
    fireEvent.click(screen.getByLabelText(/Certificate/));
    // A certificate needs at least one domain once any domain text exists,
    // and a past expiry date is never valid.
    setName('Old cert');
    fireEvent.change(screen.getByLabelText('Expires on'), {
      target: { value: '2001-01-01' },
    });
    addToList();
    expect(screen.getByText('Fix the highlighted fields.')).toBeTruthy();
    expect(screen.queryByRole('list', { name: 'Assets to create' })).toBeNull();
  });

  it('removes an asset from the list', () => {
    mount(makeCtx());
    stageNamed('A');
    stageNamed('B');
    fireEvent.click(screen.getByRole('button', { name: 'Remove A' }));
    expect(screen.getAllByRole('listitem')).toHaveLength(1);
  });
});

describe('AssetStep creation', () => {
  it('creates every listed asset and finishes the step', async () => {
    const ctx = makeCtx();
    mount(ctx);
    stageNamed('Payments API key');
    stageNamed('Billing API key');
    fireEvent.click(screen.getByRole('button', { name: 'Create 2 assets' }));
    await waitFor(() => expect(actions.createToken).toHaveBeenCalledTimes(2));
    expect(actions.createToken.mock.calls.map(c => c[0].name)).toEqual([
      'Payments API key',
      'Billing API key',
    ]);
    await waitFor(() => expect(ctx.onDone).toHaveBeenCalled());
    expect(screen.getByTestId('added-assets').textContent).toMatch(
      /Payments API key, Billing API key/
    );
    expect(screen.queryByRole('list', { name: 'Assets to create' })).toBeNull();
    expect(ctx.controller.session.operationRefs.tokenIds).toEqual([1, 2]);
    expect(ctx.controller.session.operationRefs.assetTokenIds).toEqual([1, 2]);
  });

  it('records asset-step tokens apart from website certificates', async () => {
    const ctx = makeCtx();
    // A website monitor already added certificate 50 in this workspace.
    ctx.controller.session.operationRefs = {
      monitorIds: ['m1'],
      tokenIds: [50],
    };
    mount(ctx);
    stageNamed('Payments API key');
    stageNamed('Billing API key');
    fireEvent.click(screen.getByRole('button', { name: 'Create 2 assets' }));
    await waitFor(() => expect(ctx.onDone).toHaveBeenCalled());
    const refs = ctx.controller.session.operationRefs;
    expect(refs.tokenIds).toEqual([50, 1, 2]);
    expect(refs.assetTokenIds).toEqual([1, 2]);
    expect(refs.monitorIds).toEqual(['m1']);
  });

  it('carries over asset ids from a session saved before assetTokenIds', async () => {
    const ctx = makeCtx();
    ctx.controller.session.operationRefs = { tokenIds: [40] };
    mount(ctx);
    setName('Another key');
    fireEvent.click(screen.getByRole('button', { name: 'Create asset' }));
    await waitFor(() => expect(ctx.onDone).toHaveBeenCalled());
    expect(ctx.controller.session.operationRefs.assetTokenIds).toEqual([40, 1]);
  });

  it('counts a filled-in form that was not added to the list', async () => {
    mount(makeCtx());
    stageNamed('First');
    setName('Second');
    fireEvent.click(screen.getByRole('button', { name: 'Create 2 assets' }));
    await waitFor(() => expect(actions.createToken).toHaveBeenCalledTimes(2));
  });

  it('creates a single asset exactly as before', async () => {
    const ctx = makeCtx();
    mount(ctx);
    setName('Only one');
    fireEvent.click(screen.getByRole('button', { name: 'Create asset' }));
    await waitFor(() => expect(actions.createToken).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(ctx.onDone).toHaveBeenCalled());
  });

  it('keeps only the failed assets, with the reason, and does not finish', async () => {
    actions.createToken.mockImplementation(async body => {
      if (body.name === 'Bad') throw new Error('Name already taken');
      return { id: 9, name: body.name };
    });
    const ctx = makeCtx();
    mount(ctx);
    stageNamed('Good');
    stageNamed('Bad');
    fireEvent.click(screen.getByRole('button', { name: 'Create 2 assets' }));
    expect(await screen.findByText(/Created 1 of 2/)).toBeTruthy();
    expect(screen.getByText('Name already taken')).toBeTruthy();
    const items = screen.getAllByRole('listitem');
    expect(items).toHaveLength(1);
    expect(items[0].textContent).toMatch(/Bad/);
    expect(ctx.onDone).not.toHaveBeenCalled();
  });

  it('does not create an asset that already exists', async () => {
    actions.findTokens.mockResolvedValue([
      {
        name: 'Existing',
        location: '',
        category: 'key_secret',
        type: 'api_key',
        expiresAt: '2099-12-31',
      },
    ]);
    mount(makeCtx());
    setName('Existing');
    fireEvent.click(screen.getByRole('button', { name: 'Create asset' }));
    await waitFor(() => expect(actions.findTokens).toHaveBeenCalled());
    await new Promise(r => setTimeout(r, 30));
    expect(actions.createToken).not.toHaveBeenCalled();
  });

  it('lists a failed asset once and clears the form so the count is right', async () => {
    actions.createToken.mockImplementation(async body => {
      if (body.name === 'Bad') throw new Error('Name already taken');
      return { id: 9, name: body.name };
    });
    const ctx = makeCtx();
    mount(ctx);
    stageNamed('Good');
    // Typed, never added to the list: submit() includes it in the batch.
    setName('Bad');
    fireEvent.click(screen.getByRole('button', { name: 'Create 2 assets' }));
    expect(await screen.findByText('Name already taken')).toBeTruthy();
    const items = screen.getAllByRole('listitem');
    expect(items).toHaveLength(1);
    expect(items[0].textContent).toMatch(/Bad/);
    expect(nameBox()).toHaveValue('');
    expect(screen.getByRole('button', { name: 'Create asset' })).toBeEnabled();
    expect(
      screen.queryByRole('button', { name: 'Create 2 assets' })
    ).toBeNull();
    expect(ctx.onDone).not.toHaveBeenCalled();

    // A retry sends only the failed asset, never the one that worked.
    actions.createToken.mockClear();
    actions.createToken.mockImplementation(async body => ({
      id: 10,
      name: body.name,
    }));
    fireEvent.click(screen.getByRole('button', { name: 'Create asset' }));
    await waitFor(() => expect(ctx.onDone).toHaveBeenCalled());
    expect(actions.createToken.mock.calls.map(c => c[0].name)).toEqual(['Bad']);
  });

  it('asks for a name instead of doing nothing on an empty form', () => {
    mount(makeCtx());
    const button = screen.getByRole('button', { name: 'Create asset' });
    expect(button).toBeDisabled();
  });
});

describe('AssetStep banner', () => {
  const existingMatch = name => ({
    name,
    location: '',
    category: 'key_secret',
    type: 'api_key',
    expiresAt: '2099-12-31',
  });

  it('says Created for new assets only', async () => {
    mount(makeCtx());
    setName('Fresh');
    fireEvent.click(screen.getByRole('button', { name: 'Create asset' }));
    const line = await screen.findByTestId('added-assets');
    expect(line.textContent).toMatch(/^Created: Fresh\./);
    expect(screen.queryByTestId('existing-assets')).toBeNull();
  });

  it('separates new assets from ones that already existed', async () => {
    actions.findTokens.mockImplementation(async (_ws, query) =>
      query === 'Old one' ? [existingMatch('Old one')] : []
    );
    mount(makeCtx());
    stageNamed('Old one');
    stageNamed('Fresh');
    fireEvent.click(screen.getByRole('button', { name: 'Create 2 assets' }));
    const line = await screen.findByTestId('added-assets');
    expect(line.textContent).toMatch(/^Created: Fresh\./);
    expect(line.textContent).not.toMatch(/Old one/);
    expect(screen.getByTestId('existing-assets').textContent).toMatch(
      /^Already existed: Old one\./
    );
    expect(actions.createToken).toHaveBeenCalledTimes(1);
  });

  it('claims nothing was created when everything already existed', async () => {
    actions.findTokens.mockResolvedValue([existingMatch('Old one')]);
    const ctx = makeCtx();
    mount(ctx);
    setName('Old one');
    fireEvent.click(screen.getByRole('button', { name: 'Create asset' }));
    await waitFor(() => expect(ctx.onDone).toHaveBeenCalled());
    expect(screen.queryByTestId('added-assets')).toBeNull();
    expect(screen.getByTestId('existing-assets').textContent).toMatch(
      /Already existed: Old one/
    );
    expect(actions.createToken).not.toHaveBeenCalled();
  });
});

describe('AssetStep contact group hint', () => {
  const settings = defaultId => ({
    contact_groups: [
      { id: 'g1', name: 'Ops team' },
      { id: 'g2', name: 'Security' },
    ],
    default_contact_group_id: defaultId,
  });

  it('names the default group when no group is checked', async () => {
    actions.getAlertSettings.mockResolvedValue(settings('g1'));
    mount(makeCtx());
    await screen.findByText('Ops team');
    const ops = screen.getByLabelText('Ops team');
    await waitFor(() => expect(ops).toBeChecked());
    expect(screen.queryByTestId('no-group-hint')).toBeNull();
    fireEvent.click(ops);
    expect(screen.getByTestId('no-group-hint').textContent).toBe(
      'No group selected: alerts go to the default group (Ops team).'
    );
    fireEvent.click(screen.getByLabelText('Security'));
    expect(screen.queryByTestId('no-group-hint')).toBeNull();
  });

  it('says alerts have no recipient when there is no default group', async () => {
    actions.getAlertSettings.mockResolvedValue(settings(''));
    mount(makeCtx());
    await screen.findByText('Ops team');
    expect(screen.getByTestId('no-group-hint').textContent).toBe(
      'No group selected: alerts have no recipient until a contact group is set.'
    );
  });
});
