import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';

import CertificateDetailsModal from '../../src/components/certops/CertificateDetailsModal.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const { updateTokenMock } = vi.hoisted(() => ({
  updateTokenMock: vi.fn(),
}));

vi.mock('../../src/utils/apiClient', () => ({
  tokenAPI: { updateToken: updateTokenMock },
}));

vi.mock('../../src/components/certops/CertificateInstances.jsx', () => ({
  default: props => (
    <div
      data-testid='certificate-instances'
      data-compact={String(Boolean(props.compact))}
    />
  ),
}));

vi.mock('../../src/components/certops/CertificateTimeline.jsx', () => ({
  default: props => {
    const content = (
      <div
        data-testid='certificate-timeline'
        data-compact={String(Boolean(props.compact))}
        data-default-latest-expanded={String(
          Boolean(props.defaultLatestExpanded)
        )}
      />
    );

    return props.renderContainer ? props.renderContainer(content) : content;
  },
}));

const token = {
  id: 'token-1',
  name: 'SSL cert - acme-corp.com',
  category: 'cert',
  type: 'ssl_cert',
  section: ['Production'],
  contact_group_id: 'group-1',
  expiresAt: '2027-09-02',
  domains: ['acme-corp.com', 'www.acme-corp.com'],
  issuer: "Let's Encrypt",
  serial_number: 'token-serial',
  subject: 'CN=acme-corp.com, O=Acme Corp',
  contacts: 'Platform On-Call',
  renewal_url: 'https://acme.example/renew',
  notes: 'Rotation is managed by the platform team.',
  created_at: '2025-09-01T00:00:00.000Z',
  imported_at: '2025-09-02T00:00:00.000Z',
  updated_at: '2025-09-20T00:00:00.000Z',
  last_used: '2025-12-21T00:00:00.000Z',
};

const certificate = {
  id: 'managed-cert-1',
  status: 'active',
  source: 'agent_filesystem',
  sourceRef: 'agent-1:/etc/ssl/acme.pem',
  serialNumber: 'managed-serial',
  fingerprintSha256: 'a'.repeat(64),
  publicKeyAlgorithm: 'RSA',
  publicKeySize: 2048,
  signatureAlgorithm: 'sha256WithRSAEncryption',
  subjectAltNames: ['acme-corp.com', 'www.acme-corp.com'],
  notBefore: '2026-02-17T00:00:00.000Z',
  notAfter: '2027-09-02T00:00:00.000Z',
  keyMode: 'agent-local',
  keyReference: 'file:///etc/ssl/private/acme.key',
  renewal: {
    state: 'auto',
    renewBeforeDays: 21,
    renewsFrom: '2027-08-12T00:00:00.000Z',
  },
};

function renderModal(overrides = {}) {
  const props = {
    token,
    certificate,
    isOpen: true,
    onClose: vi.fn(),
    isViewer: false,
    contactGroups: [{ id: 'group-1', name: 'Platform On-Call' }],
    workspaceContacts: [],
    onTokenUpdated: vi.fn(),
    certOps: {
      certificate,
      certificateCount: 1,
      instances: [{ id: 'instance-1' }],
      instancesAvailable: true,
      instancesError: '',
      loading: false,
      error: '',
    },
    compactTableSections: true,
    ...overrides,
  };

  return {
    props,
    ...render(
      <ChakraProvider>
        <DashboardThemeProvider>
          <MemoryRouter>
            <CertificateDetailsModal {...props} />
          </MemoryRouter>
        </DashboardThemeProvider>
      </ChakraProvider>
    ),
  };
}

describe('CertificateDetailsModal', () => {
  beforeEach(() => {
    updateTokenMock.mockReset();
  });

  it('presents certificate identity, lifecycle summary, and compact vertical content', () => {
    renderModal();

    expect(
      screen.getByRole('heading', { name: 'SSL cert - acme-corp.com' })
    ).toBeInTheDocument();
    expect(
      screen.getByText('Certificate · SSL Certificate')
    ).toBeInTheDocument();
    expect(screen.getByText('CERTIFICATE')).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Certificate actions' })
    ).not.toBeInTheDocument();
    expect(screen.getByText('Enabled')).toBeInTheDocument();
    expect(screen.getAllByText('Agent-local').length).toBeGreaterThan(0);
    expect(
      screen.getByRole('heading', { name: 'Basic information' })
    ).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'Certificate details' })
    ).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'Certificate operations' })
    ).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'Observed locations' })
    ).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'Job history' })
    ).toBeInTheDocument();
    expect(screen.getByTestId('certificate-instances')).toHaveAttribute(
      'data-compact',
      'false'
    );
    expect(screen.getByTestId('certificate-timeline')).toHaveAttribute(
      'data-default-latest-expanded',
      'false'
    );
  });

  it('uses at most two columns inside the three certificate information sections', () => {
    renderModal();

    [
      'Basic information',
      'Certificate details',
      'Certificate operations',
    ].forEach(name => {
      const section = screen.getByRole('heading', { name }).closest('section');
      const detailsGrid = section.querySelector('[data-detail-columns="2"]');
      expect(section).toHaveAttribute('data-compact-section', 'true');
      expect(
        section.querySelector('[data-compact-section-heading]')
      ).toBeInTheDocument();
      expect(detailsGrid).toBeInTheDocument();
      expect(detailsGrid).toHaveAttribute('data-section-enclosed', 'true');
      expect(detailsGrid.querySelector('[data-detail-row]')).toHaveAttribute(
        'data-table-style',
        'true'
      );
    });

    const notesSection = screen
      .getByRole('heading', { name: 'Notes' })
      .closest('section');
    expect(
      notesSection.querySelector('[data-detail-columns="1"]')
    ).toBeInTheDocument();
  });

  it('keeps long values single-line with full-value access in the compact table', () => {
    renderModal();

    const subjectRow = screen.getByText('Subject').closest('[data-detail-row]');
    expect(subjectRow).toHaveAttribute('data-compact-value', 'true');
    expect(screen.getByTitle(token.subject)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));

    expect(
      screen.getByDisplayValue(token.subject).closest('[data-detail-row]')
    ).toHaveAttribute('data-compact-value', 'false');
  });

  it('supports borderless property-value rows for the CertOps modal', () => {
    renderModal({ propertyValueRows: true });

    const subjectRow = screen
      .getByText('Subject :')
      .closest('[data-detail-row]');
    expect(subjectRow).toHaveAttribute('data-property-value-style', 'true');
    expect(screen.getByTitle(token.subject)).toBeInTheDocument();
  });

  it('keeps certificate and operational fields visible without a technical-details section', () => {
    renderModal();

    expect(screen.getByText('Serial number')).toBeInTheDocument();
    expect(screen.getByText('Certificate state')).toBeInTheDocument();
    expect(screen.getAllByText('Key locality').length).toBeGreaterThan(0);
    expect(screen.getByText('Managed certificate ID')).toBeInTheDocument();
    expect(screen.getByText('SHA-256 fingerprint')).toBeInTheDocument();
    expect(screen.queryByText('Technical details')).not.toBeInTheDocument();
  });

  it('uses managed X.509 validity for expiry badges instead of the asset date', () => {
    const now = Date.now();
    const expiringCertificate = {
      ...certificate,
      status: 'expiring',
      notAfter: new Date(now + 2 * 24 * 60 * 60 * 1000).toISOString(),
    };

    renderModal({
      token: {
        ...token,
        expiresAt: new Date(now - 31 * 24 * 60 * 60 * 1000).toISOString(),
      },
      certOps: {
        certificate: expiringCertificate,
        certificateCount: 1,
        instances: [],
        instancesAvailable: true,
        instancesError: '',
        loading: false,
        error: '',
      },
    });

    expect(screen.getAllByText('Expiring').length).toBeGreaterThan(0);
    expect(screen.getAllByText('2d left').length).toBeGreaterThan(0);
    expect(screen.queryByText('Expired 31d ago')).not.toBeInTheDocument();

    const expiryBadges = Array.from(
      document.querySelectorAll('.chakra-badge')
    ).filter(node => node.textContent === '2d left');
    const statusBadges = Array.from(
      document.querySelectorAll('.chakra-badge')
    ).filter(node => node.textContent === 'Expiring');

    expect(expiryBadges).toHaveLength(2);
    expect(expiryBadges[0].className).toBe(expiryBadges[1].className);
    expect(statusBadges).toHaveLength(2);
    expect(statusBadges[0].className).toBe(statusBadges[1].className);
  });

  it('edits and saves every certificate field supported by the previous details modal', async () => {
    const updated = { ...token, name: 'Renamed certificate' };
    const onTokenUpdated = vi.fn();
    updateTokenMock.mockResolvedValue(updated);
    renderModal({
      onTokenUpdated,
      contactGroups: [
        { id: 'group-1', name: 'Platform On-Call' },
        { id: 'group-2', name: 'Security On-Call' },
      ],
    });

    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
    fireEvent.change(screen.getByDisplayValue(token.name), {
      target: { value: 'Renamed certificate' },
    });
    fireEvent.change(screen.getByDisplayValue('Production'), {
      target: { value: 'Production, Edge' },
    });
    const contactGroupSelect = screen
      .getAllByRole('combobox')
      .find(control => control.tagName === 'SELECT');
    fireEvent.change(contactGroupSelect, { target: { value: 'group-2' } });
    fireEvent.change(screen.getByDisplayValue('2027-09-02'), {
      target: { value: '2028-10-03' },
    });
    fireEvent.change(
      screen.getByDisplayValue('acme-corp.com, www.acme-corp.com'),
      { target: { value: 'new.example.com, www.new.example.com' } }
    );
    fireEvent.change(screen.getByDisplayValue("Let's Encrypt"), {
      target: { value: 'DigiCert' },
    });
    fireEvent.change(screen.getByDisplayValue('token-serial'), {
      target: { value: 'new-serial' },
    });
    fireEvent.change(
      screen.getByDisplayValue('CN=acme-corp.com, O=Acme Corp'),
      { target: { value: 'CN=new.example.com, O=Acme Corp' } }
    );
    fireEvent.change(
      screen.getByPlaceholderText('Who manages this certificate?'),
      { target: { value: 'Security On-Call' } }
    );
    fireEvent.change(screen.getByDisplayValue('https://acme.example/renew'), {
      target: { value: 'https://new.example.com/renew' },
    });
    fireEvent.change(
      screen.getByDisplayValue('Rotation is managed by the platform team.'),
      { target: { value: 'Rotation is managed by security.' } }
    );
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => {
      expect(updateTokenMock).toHaveBeenCalledWith(
        token.id,
        expect.objectContaining({
          name: 'Renamed certificate',
          section: ['Production', 'Edge'],
          contact_group_id: 'group-2',
          expiresAt: '2028-10-03',
          domains: ['new.example.com', 'www.new.example.com'],
          issuer: 'DigiCert',
          serial_number: 'new-serial',
          subject: 'CN=new.example.com, O=Acme Corp',
          contacts: 'Security On-Call',
          renewal_url: 'https://new.example.com/renew',
          notes: 'Rotation is managed by security.',
        })
      );
      expect(onTokenUpdated).toHaveBeenCalledWith(updated);
    });
  });

  it('preserves the read-only viewer state', () => {
    renderModal({ isViewer: true });

    expect(
      screen.queryByRole('button', { name: 'Edit' })
    ).not.toBeInTheDocument();
    expect(
      screen.getByText('You have read-only access to this asset.')
    ).toBeInTheDocument();
  });

  it('omits empty summary items, rows, and data-only sections in read mode', () => {
    renderModal({
      token: {
        id: 'sparse-certificate',
        name: 'Sparse certificate',
        category: 'cert',
        type: 'ssl_cert',
        expiresAt: '2027-09-02',
      },
      certificate: null,
      certOps: {
        certificate: null,
        certificateCount: 0,
        instances: [],
        instancesAvailable: true,
        instancesError: '',
        loading: false,
        error: '',
      },
    });

    expect(
      screen.getByRole('region', { name: 'Important summary' })
    ).toBeInTheDocument();
    expect(screen.getByText('Expires')).toBeInTheDocument();
    expect(screen.queryByText('Valid from')).not.toBeInTheDocument();
    expect(screen.queryByText('Valid to')).not.toBeInTheDocument();
    expect(screen.queryByText('Auto-renewal')).not.toBeInTheDocument();
    expect(screen.queryByText('Key locality')).not.toBeInTheDocument();
    expect(screen.queryByText('Section')).not.toBeInTheDocument();
    expect(screen.queryByText('Contact group')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('heading', { name: 'Certificate details' })
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('heading', { name: 'Certificate operations' })
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('heading', { name: 'Observed locations' })
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('heading', { name: 'Job history' })
    ).not.toBeInTheDocument();
  });

  it('keeps empty editable asset fields available after entering edit mode', () => {
    renderModal({
      token: {
        id: 'empty-certificate',
        name: 'Empty certificate',
        category: 'cert',
        type: 'ssl_cert',
      },
      certificate: null,
      certOps: {
        certificate: null,
        certificateCount: 0,
        instances: [],
        instancesAvailable: true,
        instancesError: '',
        loading: false,
        error: '',
      },
    });

    expect(
      screen.queryByRole('region', { name: 'Important summary' })
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('heading', { name: 'Certificate details' })
    ).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));

    expect(screen.getByText('Section')).toBeInTheDocument();
    expect(screen.getByText('Contact group')).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'Certificate details' })
    ).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Notes' })).toBeInTheDocument();
    expect(
      screen.queryByRole('heading', { name: 'Certificate operations' })
    ).not.toBeInTheDocument();
  });
});
