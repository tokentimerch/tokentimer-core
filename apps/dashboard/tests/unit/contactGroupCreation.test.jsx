import { useState } from 'react';
import {
  ChakraProvider,
  Input,
  Modal,
  ModalBody,
  ModalContent,
  ModalOverlay,
} from '@chakra-ui/react';
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router';
import GroupEditor from '../../src/components/onboarding/alertGroupEditor.jsx';
import ContactGroupCheckboxGroup from '../../src/components/ContactGroupCheckboxGroup.jsx';
import EndpointSslMonitorModal from '../../src/components/EndpointSslMonitorModal.jsx';
import { ContactGroupCreationProvider } from '../../src/utils/ContactGroupCreationContext.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import apiClient, { workspaceAPI } from '../../src/utils/apiClient';
import { showError } from '../../src/utils/toast.js';

vi.mock('../../src/components/SEO.jsx', () => ({ default: () => null }));
vi.mock('../../src/components/DashboardShell', () => ({
  default: ({ children }) => children,
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: 'workspace-1' }),
}));
vi.mock('../../src/utils/apiClient', () => ({
  workspaceAPI: {
    get: vi.fn(),
    list: vi.fn(),
    getAlertSettings: vi.fn(),
    updateAlertSettings: vi.fn(),
  },
  alertAPI: {},
  showSuccessMessage: vi.fn(),
  default: { get: vi.fn(), post: vi.fn() },
}));
vi.mock('../../src/utils/toast.js', () => ({
  showSuccess: vi.fn(),
  showError: vi.fn(),
  showWarning: vi.fn(),
}));

let settings;
let AlertPreferences;
beforeAll(async () => {
  ({ default: AlertPreferences } =
    await import('../../src/pages/AlertPreferences.jsx'));
}, 30000);
const changed = vi.fn();
const parentClosed = vi.fn();
function Harness({
  multiple = true,
  disabled = false,
  groups = [{ id: 'ops', name: 'Operations' }],
}) {
  const [value, setValue] = useState(['ops']);
  return (
    <Modal isOpen onClose={parentClosed}>
      <ModalOverlay />
      <ModalContent>
        <ModalBody>
          <Input
            aria-label='Asset name'
            defaultValue='Do not lose this asset'
          />
          <ContactGroupCheckboxGroup
            contactGroups={groups}
            value={value}
            allowMultiple={multiple}
            isDisabled={disabled}
            onChange={next => {
              setValue(next);
              changed(next);
            }}
          />
        </ModalBody>
      </ModalContent>
    </Modal>
  );
}
function setup(props) {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter>
          <ContactGroupCreationProvider>
            <Harness {...props} />
          </ContactGroupCreationProvider>
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}
async function openEditor() {
  await waitFor(() => expect(workspaceAPI.get).toHaveBeenCalled());
  fireEvent.click(screen.getByRole('button', { name: 'Contact groups' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Add new group' }));
  await screen.findByText('New contact group', {}, { timeout: 5000 });
  fireEvent.change(
    screen.getByPlaceholderText('Group name (e.g., On-call, Security, Legal)'),
    {
      target: { value: 'Security' },
    }
  );
  await waitFor(() =>
    expect(
      screen.getByRole('checkbox', { name: 'Email', exact: true })
    ).toBeEnabled()
  );
  fireEvent.click(screen.getByRole('checkbox', { name: 'Email', exact: true }));
}

beforeEach(() => {
  window.matchMedia = vi.fn(query => ({
    matches: false,
    media: query,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }));
  vi.clearAllMocks();
  settings = {
    contact_groups: [{ id: 'ops', name: 'Operations' }],
    default_contact_group_id: 'ops',
    alert_thresholds: [7],
  };
  workspaceAPI.get.mockResolvedValue({ role: 'workspace_manager' });
  workspaceAPI.list.mockResolvedValue({
    items: [{ id: 'workspace-1', role: 'workspace_manager' }],
  });
  workspaceAPI.getAlertSettings.mockImplementation(async () =>
    structuredClone(settings)
  );
  apiClient.get.mockResolvedValue({
    data: { items: [{ id: 'person', details: { email: 'ops@example.com' } }] },
  });
  workspaceAPI.updateAlertSettings.mockImplementation(
    async (_workspace, patch) => {
      settings = { ...settings, ...patch };
    }
  );
});

describe('Inline contact group creation', () => {
  it('creates and assigns the first group from the endpoint form without losing its draft', async () => {
    settings.contact_groups = [];
    settings.default_contact_group_id = null;
    apiClient.get.mockImplementation(async url => ({
      data: {
        items: url.endsWith('/contacts')
          ? [{ id: 'person', details: { email: 'ops@example.com' } }]
          : [],
      },
    }));
    apiClient.post.mockResolvedValue({ data: {} });
    render(
      <ChakraProvider>
        <DashboardThemeProvider>
          <MemoryRouter>
            <ContactGroupCreationProvider>
              <EndpointSslMonitorModal
                isOpen
                onClose={parentClosed}
                contactGroups={[]}
                TOKEN_CATEGORIES={[]}
              />
            </ContactGroupCreationProvider>
          </MemoryRouter>
        </DashboardThemeProvider>
      </ChakraProvider>
    );
    fireEvent.change(screen.getByPlaceholderText('https://example.com'), {
      target: { value: 'https://keep.example.com' },
    });
    fireEvent.change(screen.getByPlaceholderText('Optional, comma-separated'), {
      target: { value: 'Production' },
    });
    await openEditor();
    fireEvent.click(screen.getByRole('button', { name: 'Save group' }));
    await waitFor(() =>
      expect(
        screen.queryByRole('dialog', { name: /New contact group/ })
      ).not.toBeInTheDocument()
    );
    expect(
      screen.getByDisplayValue('https://keep.example.com')
    ).toBeInTheDocument();
    expect(screen.getByDisplayValue('Production')).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Contact groups' })
    ).toHaveTextContent('Security');
    fireEvent.click(screen.getByRole('button', { name: 'Add', exact: true }));
    await waitFor(() =>
      expect(apiClient.post).toHaveBeenCalledWith(
        '/api/v1/workspaces/workspace-1/domains',
        expect.objectContaining({
          url: 'https://keep.example.com',
          section: 'Production',
          contact_group_ids: [settings.contact_groups[0].id],
        })
      )
    );
  });
  it('allows wheel and touch scrolling inside the group above a locked parent form', async () => {
    setup();
    await openEditor();
    const dialog = screen.getByRole('dialog', { name: /New contact group/ });
    const body = dialog.querySelector('.chakra-modal__body');
    // jsdom has no layout; give the real modal body overflowing dimensions.
    Object.defineProperties(body, {
      clientHeight: { configurable: true, value: 200 },
      scrollHeight: { configurable: true, value: 1000 },
    });
    expect(fireEvent.wheel(body, { deltaY: 100, cancelable: true })).toBe(true);
    fireEvent.touchStart(body, {
      changedTouches: [{ clientX: 300, clientY: 400 }],
    });
    expect(
      fireEvent.touchMove(body, {
        changedTouches: [{ clientX: 300, clientY: 300 }],
        touches: [{}],
        cancelable: true,
      })
    ).toBe(true);
  });

  it('does not expose contact creation inside the workspace-preferences group modal', async () => {
    render(
      <ChakraProvider>
        <DashboardThemeProvider>
          <MemoryRouter>
            <AlertPreferences />
          </MemoryRouter>
        </DashboardThemeProvider>
      </ChakraProvider>
    );
    const edit = await screen.findByRole('button', {
      name: 'Edit group',
      exact: true,
    });
    await waitFor(() => expect(edit).toBeEnabled());
    fireEvent.click(edit);
    const dialog = await screen.findByRole('dialog', {
      name: /Edit contact group/,
    });
    expect(
      within(dialog).queryByRole('button', { name: 'Add contact', exact: true })
    ).not.toBeInTheDocument();
  });

  it('creates a contact from the embedded editor and includes their email without losing either draft', async () => {
    apiClient.post.mockResolvedValueOnce({
      data: {
        id: 'new-person',
        first_name: 'Ada',
        last_name: 'Lovelace',
        details: { email: 'ada@example.com' },
      },
    });
    setup();
    await openEditor();
    fireEvent.click(
      screen.getByRole('button', { name: 'Add contact', exact: true })
    );
    fireEvent.change(screen.getByPlaceholderText('First name'), {
      target: { value: 'Ada' },
    });
    fireEvent.change(screen.getByPlaceholderText('Last name'), {
      target: { value: 'Lovelace' },
    });
    fireEvent.change(screen.getByPlaceholderText('name@example.com'), {
      target: { value: 'ada@example.com' },
    });
    fireEvent.click(
      screen.getAllByRole('button', { name: 'Add contact', exact: true }).at(-1)
    );
    await waitFor(() =>
      expect(
        screen.queryByPlaceholderText('First name')
      ).not.toBeInTheDocument()
    );
    expect(screen.getByDisplayValue('Security')).toBeInTheDocument();
    expect(changed).not.toHaveBeenCalled();
    expect(apiClient.post).toHaveBeenCalledWith(
      '/api/v1/workspaces/workspace-1/contacts',
      expect.objectContaining({ first_name: 'Ada', last_name: 'Lovelace' })
    );
    fireEvent.click(screen.getByRole('button', { name: 'Save group' }));
    await waitFor(() => expect(changed).toHaveBeenCalledTimes(1));
    expect(settings.contact_groups.at(-1).email_contact_ids).toEqual([
      'person',
      'new-person',
    ]);
    expect(
      screen.getByDisplayValue('Do not lose this asset')
    ).toBeInTheDocument();
  });

  it('retains the group draft and selection when contact creation fails or is cancelled', async () => {
    apiClient.post.mockRejectedValueOnce(new Error('Contact limit reached'));
    setup();
    await openEditor();
    fireEvent.click(
      screen.getByRole('button', { name: 'Add contact', exact: true })
    );
    fireEvent.change(screen.getByPlaceholderText('First name'), {
      target: { value: 'Ada' },
    });
    fireEvent.change(screen.getByPlaceholderText('Last name'), {
      target: { value: 'Lovelace' },
    });
    fireEvent.change(screen.getByPlaceholderText('name@example.com'), {
      target: { value: 'ada@example.com' },
    });
    fireEvent.click(
      screen.getAllByRole('button', { name: 'Add contact', exact: true }).at(-1)
    );
    await screen.findByText('Contact limit reached');
    expect(changed).not.toHaveBeenCalled();
    fireEvent.click(
      screen.getAllByRole('button', { name: 'Cancel', exact: true }).at(-1)
    );
    await waitFor(() =>
      expect(
        screen.queryByPlaceholderText('First name')
      ).not.toBeInTheDocument()
    );
    expect(screen.getByDisplayValue('Security')).toBeInTheDocument();
    expect(changed).not.toHaveBeenCalled();
  });

  it('checks the selected workspace directly even when it is absent from the first list page', async () => {
    workspaceAPI.list.mockResolvedValue({
      items: [{ id: 'other-workspace', role: 'viewer' }],
    });
    setup();
    await openEditor();
    expect(workspaceAPI.list).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Save group' }));
    await waitFor(() => expect(changed).toHaveBeenCalledTimes(1));
  });

  it('retries a failed permission check without losing the group draft', async () => {
    workspaceAPI.get
      .mockResolvedValueOnce({ role: 'workspace_manager' })
      .mockRejectedValueOnce(new Error('Temporary network failure'));
    setup();
    await waitFor(() => expect(workspaceAPI.get).toHaveBeenCalled());
    fireEvent.click(screen.getByRole('button', { name: 'Contact groups' }));
    fireEvent.click(
      await screen.findByRole('button', { name: 'Add new group' })
    );
    await screen.findByText('Unable to check workspace permissions.');
    fireEvent.change(
      screen.getByPlaceholderText(
        'Group name (e.g., On-call, Security, Legal)'
      ),
      {
        target: { value: 'Keep this draft' },
      }
    );
    expect(screen.getByRole('button', { name: 'Save group' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    await waitFor(() =>
      expect(
        screen.queryByText('Unable to check workspace permissions.')
      ).not.toBeInTheDocument()
    );
    await waitFor(() =>
      expect(
        screen.getByRole('checkbox', { name: 'Email', exact: true })
      ).toBeEnabled()
    );
    expect(screen.getByDisplayValue('Keep this draft')).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole('checkbox', { name: 'Email', exact: true })
    );
    fireEvent.click(screen.getByRole('button', { name: 'Save group' }));
    await waitFor(() => expect(changed).toHaveBeenCalledTimes(1));
  });

  it('does not select a group if its recipients were trimmed by the server', async () => {
    workspaceAPI.updateAlertSettings.mockImplementation(
      async (_workspace, patch) => {
        settings = {
          ...settings,
          ...patch,
          contact_groups: patch.contact_groups.map(group =>
            group.name === 'Security'
              ? { ...group, email_contact_ids: [] }
              : group
          ),
        };
      }
    );
    setup();
    await openEditor();
    fireEvent.click(screen.getByRole('button', { name: 'Save group' }));
    await screen.findByText(/fewer recipients in a group/);
    expect(changed).not.toHaveBeenCalled();
    expect(screen.getByDisplayValue('Security')).toBeInTheDocument();
  });
  it.each([true, false])(
    'selects the verified group and retains parent form data (multiple=%s)',
    async multiple => {
      setup({ multiple });
      await openEditor();
      fireEvent.click(screen.getByRole('button', { name: 'Save group' }));
      await waitFor(() => expect(changed).toHaveBeenCalledTimes(1));
      const id = settings.contact_groups.find(
        group => group.name === 'Security'
      ).id;
      expect(changed).toHaveBeenLastCalledWith(multiple ? ['ops', id] : [id]);
      expect(screen.getByRole('textbox', { name: 'Asset name' })).toHaveValue(
        'Do not lose this asset'
      );
      expect(settings.default_contact_group_id).toBe('ops');
      expect(
        screen.getByRole('button', { name: 'Contact groups' })
      ).toHaveTextContent('Security');
    }
  );

  it('keeps selection and form data on cancellation', async () => {
    setup();
    await openEditor();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    await waitFor(() =>
      expect(screen.queryByText('New contact group')).not.toBeInTheDocument()
    );
    expect(changed).not.toHaveBeenCalled();
    expect(workspaceAPI.updateAlertSettings).not.toHaveBeenCalled();
    expect(screen.getByRole('textbox', { name: 'Asset name' })).toHaveValue(
      'Do not lose this asset'
    );
  });

  it('keeps original selection when the server refuses a save, then permits retry', async () => {
    workspaceAPI.updateAlertSettings.mockRejectedValueOnce(
      new Error('Permission changed. Ask a workspace manager.')
    );
    setup();
    await openEditor();
    fireEvent.click(screen.getByRole('button', { name: 'Save group' }));
    await waitFor(() => expect(showError).toHaveBeenCalled());
    expect(changed).not.toHaveBeenCalled();
    expect(screen.getByDisplayValue('Security')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Save group' }));
    await waitFor(() => expect(changed).toHaveBeenCalledTimes(1));
  });

  it('does not select a group silently dropped by a server group limit', async () => {
    workspaceAPI.updateAlertSettings.mockResolvedValue({});
    setup();
    await openEditor();
    fireEvent.click(screen.getByRole('button', { name: 'Save group' }));
    await waitFor(() => expect(showError).toHaveBeenCalled());
    expect(changed).not.toHaveBeenCalled();
  });

  it('hides creation from viewers', async () => {
    workspaceAPI.get.mockResolvedValue({ role: 'viewer' });
    setup();
    await waitFor(() => expect(workspaceAPI.get).toHaveBeenCalled());
    fireEvent.click(screen.getByRole('button', { name: 'Contact groups' }));
    expect(
      screen.queryByRole('button', { name: 'Add new group' })
    ).not.toBeInTheDocument();
  });

  it('offers creation with no existing groups', async () => {
    settings.contact_groups = [];
    setup({ groups: [] });
    await openEditor();
    fireEvent.click(screen.getByRole('button', { name: 'Save group' }));
    await waitFor(() => expect(changed).toHaveBeenCalledTimes(1));
  });

  it('preserves a same-name group created while the editor is open', async () => {
    setup();
    await openEditor();
    const concurrent = {
      id: 'onboarding-security',
      name: 'Security',
      email_contact_ids: ['other'],
    };
    settings.contact_groups.push(concurrent);
    fireEvent.click(screen.getByRole('button', { name: 'Save group' }));
    await waitFor(() => expect(changed).toHaveBeenCalledTimes(1));
    expect(settings.contact_groups).toContainEqual(concurrent);
    expect(settings.contact_groups).toHaveLength(3);
  });

  it('closes only the creation modal with Escape and restores focus', async () => {
    setup();
    await openEditor();
    fireEvent.keyDown(screen.getByDisplayValue('Security'), {
      key: 'Escape',
      code: 'Escape',
    });
    await waitFor(() =>
      expect(screen.queryByText('New contact group')).not.toBeInTheDocument()
    );
    expect(parentClosed).not.toHaveBeenCalled();
    expect(changed).not.toHaveBeenCalled();
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: 'Contact groups' })
      ).toHaveFocus()
    );
  });

  it('keeps a disabled picker disabled', async () => {
    setup({ disabled: true });
    await waitFor(() => expect(workspaceAPI.get).toHaveBeenCalled());
    expect(
      screen.getByRole('button', { name: 'Contact groups' })
    ).toBeDisabled();
  });
});

describe('onboarding shared group editor', () => {
  function mountEditor(props = {}) {
    const update = vi.fn(async updater => updater({ operationRefs: {} }));
    const saved = vi.fn();
    const cancelled = vi.fn();
    render(
      <ChakraProvider>
        <DashboardThemeProvider>
          <MemoryRouter>
            <GroupEditor
              ctx={{ controller: { update } }}
              onSaved={saved}
              onCancel={cancelled}
              {...props}
            />
          </MemoryRouter>
        </DashboardThemeProvider>
      </ChakraProvider>
    );
    return { update, saved, cancelled };
  }
  it('opens directly from the onboarding create action and cancels without writes', async () => {
    const { update, cancelled } = mountEditor({ autoOpen: true });
    const dialog = await screen.findByRole('dialog', {
      name: /New contact group/,
    });
    expect(
      within(dialog).getByRole('button', { name: 'Add contact' })
    ).toBeVisible();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(cancelled).toHaveBeenCalledOnce());
    expect(update).not.toHaveBeenCalled();
    expect(workspaceAPI.updateAlertSettings).not.toHaveBeenCalled();
  });
  it('edits an onboarding group in the shared modal and records the existing id', async () => {
    const group = {
      id: 'ops',
      name: 'Operations',
      email_contact_ids: ['person'],
      whatsapp_contact_ids: [],
      webhook_names: [],
      weekly_digest_email: true,
    };
    settings.contact_groups = [group];
    const { update, saved } = mountEditor({ group, makeDefault: true });
    const dialog = await screen.findByRole('dialog', {
      name: /Edit contact group/,
    });
    expect(
      within(dialog).getByPlaceholderText(
        'Group name (e.g., On-call, Security, Legal)'
      )
    ).toHaveValue('Operations');
    await waitFor(() =>
      expect(
        within(dialog).getByRole('button', { name: 'Save group' })
      ).toBeEnabled()
    );
    fireEvent.change(
      within(dialog).getByPlaceholderText(
        'Group name (e.g., On-call, Security, Legal)'
      ),
      { target: { value: 'Operations updated' } }
    );
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save group' }));
    await waitFor(() => expect(saved).toHaveBeenCalledOnce());
    expect(update).toHaveBeenCalledOnce();
    expect(settings.contact_groups).toHaveLength(1);
    expect(settings.contact_groups[0]).toMatchObject({
      id: 'ops',
      name: 'Operations updated',
      email_contact_ids: ['person'],
      weekly_digest_email: true,
    });
    expect(settings.default_contact_group_id).toBe('ops');
  });
});
