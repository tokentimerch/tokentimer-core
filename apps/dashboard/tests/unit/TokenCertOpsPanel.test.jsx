import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
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

describe('TokenCertOpsPanel multi-cert notice', () => {
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
});
