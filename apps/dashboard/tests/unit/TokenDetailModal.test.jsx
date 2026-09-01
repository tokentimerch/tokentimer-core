import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import TokenDetailModal from '../../src/components/TokenDetailModal.jsx';
import { TOKEN_CATEGORIES } from '../../src/constants/tokenCategories.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const { updateTokenMock } = vi.hoisted(() => ({
  updateTokenMock: vi.fn(),
}));

vi.mock('../../src/utils/apiClient', async importOriginal => {
  const actual = await importOriginal();
  return {
    ...actual,
    tokenAPI: { ...actual.tokenAPI, updateToken: updateTokenMock },
  };
});

vi.mock('../../src/components/certops/TokenCertOpsPanel.jsx', () => ({
  default: () => null,
}));

const baseToken = {
  id: 'token-1',
  name: 'Production credential',
  category: 'general',
  type: 'other',
  section: ['Production'],
  contact_group_id: 'group-1',
  expiresAt: '2027-09-01',
  location: '/srv/app/config',
  used_by: 'Payments API',
  renewal_url: 'https://provider.example.com/renew',
  contacts: 'Platform On-Call',
  notes: 'Rotate during the maintenance window.',
  created_at: '2026-01-01T00:00:00.000Z',
  updated_at: '2026-02-01T00:00:00.000Z',
};

function renderModal(token = baseToken, overrides = {}) {
  const props = {
    token,
    isOpen: true,
    onClose: vi.fn(),
    TOKEN_CATEGORIES,
    onTokenUpdated: vi.fn(),
    isViewer: false,
    contactGroups: [{ id: 'group-1', name: 'Platform On-Call' }],
    workspaceContacts: [],
    ...overrides,
  };

  return {
    props,
    ...render(
      <ChakraProvider>
        <DashboardThemeProvider>
          <MemoryRouter>
            <TokenDetailModal {...props} />
          </MemoryRouter>
        </DashboardThemeProvider>
      </ChakraProvider>
    ),
  };
}

describe('TokenDetailModal', () => {
  beforeEach(() => {
    updateTokenMock.mockReset();
  });

  it('uses compact label/value rows without removing dashboard asset data', () => {
    renderModal();

    expect(
      screen.getByRole('heading', { name: 'Production credential' })
    ).toBeInTheDocument();
    expect(screen.getByText('General · Other')).toBeInTheDocument();
    expect(screen.getByText('Basic information')).toBeInTheDocument();
    expect(screen.getByText('General details')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Notes' })).toBeInTheDocument();
    expect(
      document.querySelectorAll('[data-dashboard-detail-row]').length
    ).toBeGreaterThan(10);
  });

  it('preserves editing and saving for every general-asset field', async () => {
    const updated = { ...baseToken, name: 'Updated credential' };
    const onTokenUpdated = vi.fn();
    updateTokenMock.mockResolvedValue(updated);
    renderModal(baseToken, {
      onTokenUpdated,
      contactGroups: [
        { id: 'group-1', name: 'Platform On-Call' },
        { id: 'group-2', name: 'Security On-Call' },
      ],
    });

    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
    fireEvent.change(screen.getByDisplayValue('Production credential'), {
      target: { value: 'Updated credential' },
    });
    fireEvent.change(screen.getByDisplayValue('Production'), {
      target: { value: 'Production, Edge' },
    });
    const contactGroupSelect = screen
      .getAllByRole('combobox')
      .find(control => control.tagName === 'SELECT');
    fireEvent.change(contactGroupSelect, { target: { value: 'group-2' } });
    fireEvent.change(screen.getByDisplayValue('2027-09-01'), {
      target: { value: '2028-09-01' },
    });
    fireEvent.change(screen.getByDisplayValue('/srv/app/config'), {
      target: { value: '/srv/app/next-config' },
    });
    fireEvent.change(screen.getByDisplayValue('Payments API'), {
      target: { value: 'Billing API' },
    });
    fireEvent.change(
      screen.getByDisplayValue('https://provider.example.com/renew'),
      { target: { value: 'https://provider.example.com/new-renewal' } }
    );
    fireEvent.change(screen.getByPlaceholderText('Who manages this item?'), {
      target: { value: 'Security On-Call' },
    });
    fireEvent.change(
      screen.getByDisplayValue('Rotate during the maintenance window.'),
      { target: { value: 'Rotate during the security window.' } }
    );
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => {
      expect(updateTokenMock).toHaveBeenCalledWith(
        baseToken.id,
        expect.objectContaining({
          name: 'Updated credential',
          section: ['Production', 'Edge'],
          contact_group_id: 'group-2',
          expiresAt: '2028-09-01',
          location: '/srv/app/next-config',
          used_by: 'Billing API',
          renewal_url: 'https://provider.example.com/new-renewal',
          contacts: 'Security On-Call',
          notes: 'Rotate during the security window.',
        })
      );
      expect(onTokenUpdated).toHaveBeenCalledWith(updated);
      expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument();
    });
  });

  it.each([
    {
      category: 'key_secret',
      type: 'ssh_key',
      fields: {
        location: '/home/service/.ssh/id_ed25519',
        used_by: 'Deployment service',
        privileges: 'read:deploy',
        description: 'Deployment key',
        algorithm: 'Ed25519',
        key_size: 256,
      },
      expectedValues: [
        '/home/service/.ssh/id_ed25519',
        'Deployment service',
        'read:deploy',
        'Deployment key',
        'Ed25519',
        '256',
      ],
    },
    {
      category: 'license',
      type: 'software_license',
      fields: {
        vendor: 'Acme Software',
        license_type: 'Subscription',
        cost: 1250,
        renewal_date: '2027-08-15',
      },
      expectedValues: ['Acme Software', 'Subscription', '1250', '2027-08-15'],
    },
  ])(
    'keeps $category category-specific fields editable',
    ({ category, type, fields, expectedValues }) => {
      renderModal({ ...baseToken, category, type, ...fields });
      fireEvent.click(screen.getByRole('button', { name: 'Edit' }));

      expectedValues.forEach(value => {
        expect(screen.getByDisplayValue(value)).toBeInTheDocument();
      });
    }
  );

  it('preserves read-only viewer behavior', () => {
    renderModal(baseToken, { isViewer: true });

    expect(
      screen.queryByRole('button', { name: 'Edit' })
    ).not.toBeInTheDocument();
    expect(
      screen.getByText('You have read-only access to this asset.')
    ).toBeInTheDocument();
  });

  it('omits unavailable rows and sections in read mode without hiding edit fields', () => {
    renderModal({
      id: 'sparse-token',
      name: 'Sparse asset',
      category: 'general',
      type: 'other',
    });

    expect(
      screen.queryByRole('region', { name: 'Important summary' })
    ).not.toBeInTheDocument();
    expect(screen.queryByText('General details')).not.toBeInTheDocument();
    expect(screen.queryByText('Section')).not.toBeInTheDocument();
    expect(screen.queryByText('Contact group')).not.toBeInTheDocument();
    expect(screen.queryByText('Asset expiration')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('heading', { name: 'Notes' })
    ).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));

    expect(screen.getByText('General details')).toBeInTheDocument();
    expect(screen.getByText('Section :')).toBeInTheDocument();
    expect(screen.getByText('Contact group :')).toBeInTheDocument();
    expect(screen.getByText('Asset expiration :')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Notes' })).toBeInTheDocument();
  });

  it('shows only populated license data and a content-aware expiry summary', () => {
    renderModal({
      id: 'license-token',
      name: 'Design suite',
      category: 'license',
      type: 'software_license',
      expiresAt: '2027-08-15',
      vendor: 'Acme Software',
      cost: 0,
    });

    expect(
      screen.getByRole('region', { name: 'Important summary' })
    ).toBeInTheDocument();
    expect(screen.getByText('License details')).toBeInTheDocument();
    expect(screen.getByText('Vendor :')).toBeInTheDocument();
    expect(screen.getByText('Acme Software')).toBeInTheDocument();
    expect(screen.getByText('Cost :')).toBeInTheDocument();
    expect(screen.getByText('0')).toBeInTheDocument();
    expect(screen.queryByText('License type')).not.toBeInTheDocument();
    expect(screen.queryByText('Renewal information')).not.toBeInTheDocument();
  });
});
