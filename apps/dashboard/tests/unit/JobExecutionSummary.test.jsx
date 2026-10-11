import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { ChakraProvider } from '@chakra-ui/react';

import { JobExecutionSummary } from '../../src/components/certops/JobDetailsButton.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const {
  useCertOpsIsWorkspaceAdminMock,
  useCertOpsCanManageMock,
  getCertificateMock,
  listTrustAnchorsMock,
} = vi.hoisted(() => ({
  useCertOpsIsWorkspaceAdminMock: vi.fn(),
  useCertOpsCanManageMock: vi.fn(),
  getCertificateMock: vi.fn(),
  listTrustAnchorsMock: vi.fn(),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: 'ws-1' }),
}));

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsIsWorkspaceAdmin: useCertOpsIsWorkspaceAdminMock,
  useCertOpsCanManage: useCertOpsCanManageMock,
}));

vi.mock('../../src/components/certops/certopsApi.js', () => ({
  getCertificate: getCertificateMock,
}));

vi.mock('../../src/components/certops/certopsTrustAnchorsApi.js', () => ({
  listTrustAnchors: listTrustAnchorsMock,
}));

const ANCHOR_ID = '11111111-1111-4111-8111-111111111111';

function renderSummary(job) {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter>
          <JobExecutionSummary job={job} agentsById={new Map()} />
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

beforeEach(() => {
  useCertOpsIsWorkspaceAdminMock.mockReset();
  useCertOpsCanManageMock.mockReset();
  getCertificateMock.mockReset();
  listTrustAnchorsMock.mockReset();
  useCertOpsIsWorkspaceAdminMock.mockReturnValue(false);
  useCertOpsCanManageMock.mockReturnValue(true);
  listTrustAnchorsMock.mockResolvedValue({ items: [] });
});

describe('JobExecutionSummary trust-anchor links', () => {
  const trustJob = {
    subjectType: 'trust_anchor',
    subjectId: ANCHOR_ID,
    source: 'api',
    createdAt: '2026-10-10T00:00:00.000Z',
  };

  it('links the trust anchor for workspace admins', async () => {
    useCertOpsIsWorkspaceAdminMock.mockReturnValue(true);
    listTrustAnchorsMock.mockResolvedValue({
      items: [{ id: ANCHOR_ID, name: 'Corp Root CA' }],
    });

    renderSummary(trustJob);

    const link = await screen.findByRole('link', { name: 'Corp Root CA' });
    expect(link).toHaveAttribute(
      'href',
      `/certops/agents?trustAnchorId=${ANCHOR_ID}`
    );
    expect(
      screen.queryByTestId('trust-anchor-access-denied')
    ).not.toBeInTheDocument();
  });

  it('shows an access explanation for managers instead of a link', () => {
    useCertOpsIsWorkspaceAdminMock.mockReturnValue(false);

    renderSummary(trustJob);

    // Synchronous denial: no first-paint link, no trust-anchor fetch.
    expect(screen.getByTestId('trust-anchor-access-denied')).toHaveTextContent(
      /Only workspace admins can open trust anchors/
    );
    expect(listTrustAnchorsMock).not.toHaveBeenCalled();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });

  it('shows an access explanation for viewers instead of a link', () => {
    useCertOpsIsWorkspaceAdminMock.mockReturnValue(false);

    renderSummary(trustJob);

    expect(screen.getByTestId('trust-anchor-access-denied')).toHaveTextContent(
      /Only workspace admins can open trust anchors/
    );
    expect(screen.queryByRole('link', { name: /trust anchor/i })).toBeNull();
  });
});
