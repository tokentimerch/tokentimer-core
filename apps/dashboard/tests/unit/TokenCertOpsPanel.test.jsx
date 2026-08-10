import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { ChakraProvider, Grid } from '@chakra-ui/react';

import TokenCertOpsPanel from '../../src/components/certops/TokenCertOpsPanel.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const { useCertOpsForTokenMock } = vi.hoisted(() => ({
  useCertOpsForTokenMock: vi.fn(),
}));

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsForToken: useCertOpsForTokenMock,
}));

vi.mock('../../src/components/certops/CertificateTimeline.jsx', () => ({
  default: () => <div data-testid='certificate-timeline' />,
}));

vi.mock('../../src/components/certops/CertificateInstances.jsx', () => ({
  default: () => <div data-testid='certificate-instances' />,
}));

function renderPanel(token) {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter>
          <Grid>
            <TokenCertOpsPanel token={token} tokenId={token.id} />
          </Grid>
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

const certToken = { id: 42, category: 'cert', type: 'ssl_cert' };

function cert(overrides = {}) {
  return {
    id: 'cert-1',
    status: 'active',
    notAfter: '2027-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

function hookState(overrides = {}) {
  const certificates = overrides.certificates || [cert()];
  return {
    enabled: true,
    certificate: certificates[0],
    certificates,
    certificateCount: certificates.length,
    instances: [],
    instancesAvailable: true,
    loading: false,
    error: '',
    ...overrides,
  };
}

describe('TokenCertOpsPanel', () => {
  beforeEach(() => {
    useCertOpsForTokenMock.mockReset();
  });

  it('does not show the notice when a single certificate references the token', () => {
    useCertOpsForTokenMock.mockReturnValue(hookState());

    renderPanel(certToken);

    expect(
      screen.queryByText(/certificates reference this token/)
    ).not.toBeInTheDocument();
  });

  it('shows "N certificates reference this token" when several certs reference it', () => {
    const primary = cert({ id: 'cert-active' });
    const other = cert({ id: 'cert-observed' });
    useCertOpsForTokenMock.mockReturnValue(
      hookState({
        certificates: [primary, other],
        certificate: primary,
        certificateCount: 2,
      })
    );

    renderPanel(certToken);

    expect(
      screen.getByText(/2 certificates reference this token/)
    ).toBeInTheDocument();
  });

  it('labels a missing cert-manager fingerprint as a valid status-only observation', () => {
    useCertOpsForTokenMock.mockReturnValue(
      hookState({
        certificates: [
          cert({ source: 'cert_manager', fingerprintSha256: null }),
        ],
      })
    );

    renderPanel(certToken);

    expect(
      screen.getByText('Not reported (status-only observation)')
    ).toBeInTheDocument();
  });

  it('shows a public fingerprint when Secret fallback supplied one', () => {
    const fingerprintSha256 = 'a'.repeat(64);
    useCertOpsForTokenMock.mockReturnValue(
      hookState({
        certificates: [cert({ source: 'cert_manager', fingerprintSha256 })],
      })
    );

    renderPanel(certToken);

    expect(screen.getByText(fingerprintSha256)).toBeInTheDocument();
    expect(
      screen.queryByText('Not reported (status-only observation)')
    ).not.toBeInTheDocument();
  });

  it('shows the renewal-path badge and summary when the path is not healthy', () => {
    useCertOpsForTokenMock.mockReturnValue(
      hookState({
        certificates: [
          cert({
            renewalPathState: 'unavailable',
            renewalPathSummary:
              'The only agent able to renew this certificate is offline.',
          }),
        ],
      })
    );

    renderPanel(certToken);

    expect(screen.getByText('Renewal path unavailable')).toBeInTheDocument();
    expect(
      screen.getByText(
        'The only agent able to renew this certificate is offline.'
      )
    ).toBeInTheDocument();
  });

  it('shows a Healthy renewal-path badge without a warning summary line', () => {
    useCertOpsForTokenMock.mockReturnValue(
      hookState({
        certificates: [cert({ renewalPathState: 'healthy' })],
      })
    );

    renderPanel(certToken);

    expect(screen.getByText('Healthy')).toBeInTheDocument();
    expect(
      screen.queryByText(/renewal execution agents are online/)
    ).not.toBeInTheDocument();
  });

  it('renders no renewal-path badge when the certificate never has a renewal path to evaluate', () => {
    useCertOpsForTokenMock.mockReturnValue(
      hookState({
        certificates: [cert({ renewalPathState: null })],
      })
    );

    renderPanel(certToken);

    expect(screen.queryByText('Healthy')).not.toBeInTheDocument();
    expect(screen.queryByText('Degraded')).not.toBeInTheDocument();
    expect(screen.queryByText('Renewal path unavailable')).not.toBeInTheDocument();
  });
});
