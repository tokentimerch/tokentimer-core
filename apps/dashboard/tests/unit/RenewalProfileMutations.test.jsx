import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, render, renderHook, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';

import { useUpdateRenewalProfile } from '../../src/components/certops/useCertOpsRenewals.js';
import { listAllIssuers } from '../../src/components/certops/certopsFormat.js';
import RenewalProfileDetailsModal, {
  useBoundCertificates,
} from '../../src/components/certops/RenewalProfileDetailsModal.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const { updateRenewalProfileMock, listCertificatesMock } = vi.hoisted(() => ({
  updateRenewalProfileMock: vi.fn(),
  listCertificatesMock: vi.fn(),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: 'ws-1' }),
}));

vi.mock('../../src/components/certops/certopsRenewalApi.js', () => ({
  listRenewalProfiles: vi.fn(),
  listUpcomingRenewals: vi.fn(),
  updateRenewalProfile: updateRenewalProfileMock,
}));

vi.mock('../../src/components/certops/certopsApi.js', () => ({
  listCertificates: listCertificatesMock,
}));

beforeEach(() => {
  updateRenewalProfileMock.mockReset();
  listCertificatesMock.mockReset();
});

describe('renewal profile row saves', () => {
  it('keeps one row failed when a later row succeeds', async () => {
    let rejectFirst;
    const first = new Promise((_resolve, reject) => {
      rejectFirst = reject;
    });
    updateRenewalProfileMock.mockImplementation(
      async (_workspaceId, profileId) => {
        if (profileId === 'profile-a') return first;
        return { id: profileId };
      }
    );
    const { result } = renderHook(() => useUpdateRenewalProfile());
    let firstSave;
    let secondSave;
    act(() => {
      firstSave = result.current.save('profile-a', { renewBeforeDays: 10 });
      secondSave = result.current.save('profile-b', { renewBeforeDays: 12 });
    });
    await act(async () => {
      await secondSave;
    });
    await act(async () => {
      rejectFirst(
        Object.assign(new Error('no'), {
          response: { data: { error: 'Row A refused' } },
        })
      );
      await firstSave;
    });
    expect(result.current.errors['profile-a']).toMatch(/Row A refused/);
    expect(result.current.errors['profile-b']).toBeUndefined();
  });
});

describe('issuer catalog past the first page', () => {
  it('returns an issuer that sorts after the first 100', async () => {
    const items = await listAllIssuers(async (_workspaceId, options) => {
      if (!options.offset) {
        return {
          items: Array.from({ length: 100 }, (_, index) => ({
            id: `issuer-${index}`,
            kind: 'adcs',
            name: `CA ${index}`,
            currentVersion: 1,
          })),
        };
      }
      return {
        items: [
          {
            id: 'issuer-late',
            kind: 'adcs',
            name: 'Late CA',
            currentVersion: 1,
          },
        ],
      };
    }, 'ws-1');
    expect(items.some(item => item.id === 'issuer-late')).toBe(true);
  });
});

describe('bound certificate inventory', () => {
  it('keeps the pages already loaded when a later page fails', async () => {
    listCertificatesMock
      .mockResolvedValueOnce({
        items: Array.from({ length: 100 }, (_, index) => ({
          id: `cert-${index}`,
          profileId: 'profile-1',
          commonName: `name-${index}.example`,
        })),
      })
      .mockRejectedValueOnce(new Error('page two failed'));
    const { result } = renderHook(() => useBoundCertificates('ws-1'));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.certificates).toHaveLength(100);
    expect(result.current.incomplete).toBe(true);
  });

  it('says the certificate list is partial after a failed page', async () => {
    render(
      <MemoryRouter>
        <ChakraProvider>
          <DashboardThemeProvider>
            <RenewalProfileDetailsModal
              isOpen
              onClose={() => {}}
              profile={{
                id: 'profile-1',
                name: 'Web',
                certificateCount: 2,
                renewalProfile: {},
              }}
              boundCertificates={[
                {
                  id: 'cert-1',
                  profileId: 'profile-1',
                  commonName: 'one.example',
                },
              ]}
              inventoryIncomplete
            />
          </DashboardThemeProvider>
        </ChakraProvider>
      </MemoryRouter>
    );
    expect(
      await screen.findByText(/Loaded 1 certificates. A later page failed/)
    ).toBeInTheDocument();
  });
});
