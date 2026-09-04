import { ChakraProvider } from '@chakra-ui/react';
import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import CertificateTokenDetailModal from '../../src/components/certops/CertificateTokenDetailModal.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const {
  getTokenMock,
  getAlertSettingsMock,
  getContactsMock,
  certificateDetailsModalMock,
} = vi.hoisted(() => ({
  getTokenMock: vi.fn(),
  getAlertSettingsMock: vi.fn(),
  getContactsMock: vi.fn(),
  certificateDetailsModalMock: vi.fn(),
}));

vi.mock('../../src/utils/apiClient', () => ({
  default: { get: getContactsMock },
  tokenAPI: { getToken: getTokenMock },
  workspaceAPI: { getAlertSettings: getAlertSettingsMock },
}));

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsForToken: () => ({
    certificate: null,
    instances: [],
    instancesAvailable: true,
  }),
}));

vi.mock('../../src/components/certops/CertificateDetailsModal.jsx', () => ({
  default: props => {
    certificateDetailsModalMock(props);
    return <div data-testid='loaded-certificate-details' />;
  },
}));

function renderModal(overrides = {}) {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <CertificateTokenDetailModal
          isOpen
          onClose={vi.fn()}
          workspaceId='workspace-1'
          tokenId='token-1'
          canManage
          {...overrides}
        />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

describe('CertificateTokenDetailModal', () => {
  beforeEach(() => {
    getTokenMock.mockReset();
    getAlertSettingsMock.mockReset();
    getContactsMock.mockReset();
    certificateDetailsModalMock.mockReset();
    getAlertSettingsMock.mockResolvedValue({ contact_groups: [] });
    getContactsMock.mockResolvedValue({ data: { items: [] } });
  });

  it('uses the standard details shell while certificate data is loading', async () => {
    getTokenMock.mockReturnValue(new Promise(() => {}));

    renderModal();

    expect(
      await screen.findByText('Loading token details…')
    ).toBeInTheDocument();
    expect(
      document.querySelector('[data-dashboard-details-modal]')
    ).toBeInTheDocument();
    expect(screen.getByText('CERTIFICATE')).toBeInTheDocument();
    expect(screen.getByText('Loading asset details…')).toBeInTheDocument();
    expect(
      screen.getByText('Close', { selector: 'button' })
    ).toBeInTheDocument();
  });

  it('delegates loaded CertOps certificate details to the shared certificate modal', async () => {
    const token = {
      id: 'token-1',
      name: 'Certificate asset',
      category: 'cert',
      type: 'ssl_cert',
    };
    getTokenMock.mockResolvedValue(token);

    renderModal();

    expect(
      await screen.findByTestId('loaded-certificate-details')
    ).toBeInTheDocument();
    expect(certificateDetailsModalMock).toHaveBeenCalledWith(
      expect.objectContaining({
        token,
        isViewer: false,
        compactTableSections: true,
        propertyValueRows: true,
      })
    );
  });
});
