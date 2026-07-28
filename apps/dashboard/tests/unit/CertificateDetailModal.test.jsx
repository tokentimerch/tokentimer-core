import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { ChakraProvider } from '@chakra-ui/react';

import CertificateDetailModal from '../../src/components/certops/CertificateDetailModal.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const { useWorkspaceMock, getCertificateInstancesMock } = vi.hoisted(() => ({
  useWorkspaceMock: vi.fn(),
  getCertificateInstancesMock: vi.fn(),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: useWorkspaceMock,
}));

vi.mock('../../src/components/certops/certopsApi.js', async () => {
  const actual = await vi.importActual(
    '../../src/components/certops/certopsApi.js'
  );
  return {
    ...actual,
    getCertificateInstances: getCertificateInstancesMock,
  };
});

vi.mock('../../src/components/certops/CertificateTimeline.jsx', () => ({
  default: () => <div data-testid='certificate-timeline' />,
}));

function renderModal(certificate, props = {}) {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter>
          <CertificateDetailModal
            isOpen
            onClose={vi.fn()}
            certificate={certificate}
            {...props}
          />
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

function cert(overrides = {}) {
  return {
    id: 'cert-1',
    status: 'active',
    notAfter: '2099-01-01T00:00:00.000Z',
    subjectAltNames: [],
    ...overrides,
  };
}

describe('CertificateDetailModal', () => {
  beforeEach(() => {
    useWorkspaceMock.mockReset();
    getCertificateInstancesMock.mockReset();
    useWorkspaceMock.mockReturnValue({ workspaceId: 'ws-1' });
    getCertificateInstancesMock.mockResolvedValue({ items: [] });
  });

  it('renders nothing when there is no target certificate', () => {
    const { container } = renderModal(null);

    expect(container.textContent).toBe('');
  });

  it('opens for a certificate with no tokenId at all (the whole point of this modal)', () => {
    renderModal(cert({ tokenId: null }));

    expect(screen.getByText('Certificate details')).toBeInTheDocument();
  });

  it('labels a missing cert-manager fingerprint as a valid status-only observation', () => {
    renderModal(cert({ source: 'cert_manager', fingerprintSha256: null }));

    expect(
      screen.getByText('Not reported (status-only observation)')
    ).toBeInTheDocument();
  });

  it('shows a public fingerprint when one is present', () => {
    const fingerprintSha256 = 'a'.repeat(64);
    renderModal(cert({ source: 'cert_manager', fingerprintSha256 }));

    expect(screen.getByText(fingerprintSha256)).toBeInTheDocument();
  });

  it('shows the subject alternative names', () => {
    renderModal(cert({ subjectAltNames: ['example.com', 'www.example.com'] }));

    expect(screen.getByText('example.com')).toBeInTheDocument();
    expect(screen.getByText('www.example.com')).toBeInTheDocument();
  });

  it('fetches observation history scoped to this certificate id', () => {
    renderModal(cert({ id: 'cert-abc' }));

    expect(getCertificateInstancesMock).toHaveBeenCalledWith(
      'ws-1',
      'cert-abc',
      expect.objectContaining({ signal: expect.anything() })
    );
  });
});
