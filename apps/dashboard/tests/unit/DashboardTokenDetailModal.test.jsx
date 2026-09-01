import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import DashboardTokenDetailModal from '../../src/components/DashboardTokenDetailModal.jsx';

vi.mock('../../src/components/TokenDetailModal.jsx', () => ({
  default: () => <div>Generic dashboard details</div>,
}));

vi.mock('../../src/components/certops/CertificateDetailsModal.jsx', () => ({
  default: props => (
    <div
      data-testid='dashboard-certificate-details'
      data-compact-table-sections={String(Boolean(props.compactTableSections))}
      data-property-value-rows={String(Boolean(props.propertyValueRows))}
    >
      Certificate inspection details
    </div>
  ),
}));

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsForToken: vi.fn(() => ({})),
}));

describe('DashboardTokenDetailModal', () => {
  it('uses the certificate inspection modal for certificate assets', () => {
    render(
      <DashboardTokenDetailModal
        token={{ id: 'cert-1', category: 'cert', type: 'ssl_cert' }}
        isOpen
      />
    );

    expect(
      screen.getByText('Certificate inspection details')
    ).toBeInTheDocument();
    expect(
      screen.queryByText('Generic dashboard details')
    ).not.toBeInTheDocument();
    expect(screen.getByTestId('dashboard-certificate-details')).toHaveAttribute(
      'data-compact-table-sections',
      'true'
    );
    expect(screen.getByTestId('dashboard-certificate-details')).toHaveAttribute(
      'data-property-value-rows',
      'true'
    );
  });

  it('uses the compact generic details modal for other assets', () => {
    render(
      <DashboardTokenDetailModal
        token={{ id: 'token-1', category: 'general', type: 'api_token' }}
        isOpen
        TOKEN_CATEGORIES={[]}
      />
    );

    expect(screen.getByText('Generic dashboard details')).toBeInTheDocument();
    expect(
      screen.queryByText('Certificate inspection details')
    ).not.toBeInTheDocument();
  });
});
