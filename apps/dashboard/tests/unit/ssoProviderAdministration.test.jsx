import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';

import { theme } from '../../src/styles/theme.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import SsoProviderWizard from '../../src/pages/SsoProviderWizard.jsx';
import SsoProviderEdit from '../../src/pages/SsoProviderEdit.jsx';
import SsoProviders from '../../src/pages/SsoProviders.jsx';
import { showWarning } from '../../src/utils/toast.js';

const { api, navigate } = vi.hoisted(() => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() },
  navigate: vi.fn(),
}));

vi.mock('../../src/utils/apiClient', () => ({
  default: api,
  API_BASE_URL: 'https://api.example.test',
}));
vi.mock('../../src/utils/toast.js', () => ({
  showSuccess: vi.fn(),
  showWarning: vi.fn(),
}));
vi.mock('react-router', async importOriginal => ({
  ...(await importOriginal()),
  useNavigate: () => navigate,
  useParams: () => ({ slug: 'office' }),
}));
vi.mock('../../src/components/SsoAdminPageShell.jsx', () => ({
  default: ({ title, actions, children }) => (
    <>
      <h1>{title}</h1>
      {actions}
      {children}
    </>
  ),
}));

const metadataXml = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.test/entity">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>MIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBCwUA</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
    <KeyDescriptor><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>TG9jYWwgcm9sbG92ZXIgZml4dHVyZQ==</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`;

function mount(page) {
  return render(
    <ChakraProvider theme={theme}>
      <DashboardThemeProvider>
        <MemoryRouter>{page}</MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

function click(name) {
  fireEvent.click(screen.getByRole('button', { name }));
}

function enter(label, value) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

describe('Core provider administration', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    window.matchMedia = query => ({
      matches: false,
      media: query,
      addEventListener() {},
      removeEventListener() {},
      addListener() {},
      removeListener() {},
    });
  });

  it.each([true, false])(
    'saves the Okta groups scope when the role mapping option is %s',
    async includeGroups => {
      api.post.mockResolvedValueOnce({ data: { slug: 'okta-office' } });
      api.post.mockResolvedValueOnce({ data: { ok: true, checks: [] } });
      mount(<SsoProviderWizard session={{}} />);
      await screen.findByRole('heading', { name: 'Choose protocol' });
      click('Continue');
      await screen.findByRole('heading', { name: 'IdP template' });
      enter(/^Template$/, 'okta');
      click('Continue');
      await screen.findByRole('heading', { name: 'Provider details' });
      enter(/^Display name/, 'Office');
      enter(/^Issuer URL/, 'https://example.okta.com');
      enter(/^Client ID/, 'test-client');
      enter(/^Client secret/, 'synthetic-fixture');
      const option = screen.getByRole('checkbox', {
        name: 'Request groups for role mapping',
      });
      expect(option.checked).toBe(true);
      if (!includeGroups) fireEvent.click(option);
      click('Continue');
      await screen.findByRole('heading', { name: 'Register URLs in your IdP' });
      click('Continue');
      await screen.findByRole('heading', { name: 'Verification' });
      click('Save and run test');
      await screen.findByRole('heading', { name: 'Enable sign-in' });
      expect(api.post).toHaveBeenCalledWith(
        '/api/admin/sso/providers',
        expect.objectContaining({
          config: expect.objectContaining({
            scopes: includeGroups
              ? 'openid profile email groups'
              : 'openid profile email',
          }),
        })
      );
    }
  );

  it.each(['oidc', 'saml'])(
    'saves %s disabled before testing and then activates the named provider',
    async protocol => {
      api.post.mockResolvedValueOnce({ data: { slug: 'office' } });
      api.post.mockResolvedValueOnce({ data: { ok: true, checks: [] } });
      api.put.mockResolvedValue({ data: { enabled: true } });
      mount(<SsoProviderWizard session={{}} />);
      await screen.findByRole('heading', { name: 'Choose protocol' });
      enter(/^Protocol$/, protocol);
      click('Continue');
      await screen.findByRole('heading', { name: 'IdP template' });
      click('Continue');
      await screen.findByRole('heading', { name: 'Provider details' });
      enter(/^Display name/, 'Office');
      if (protocol === 'oidc') {
        enter(/^Issuer URL/, 'https://idp.example.test/realms/work');
        enter(/^Client ID/, 'core-browser-test');
        enter(/^Client secret/, 'synthetic-fixture');
      } else {
        enter(/^Or paste metadata XML/, metadataXml);
      }
      click('Continue');
      await screen.findByRole('heading', { name: 'Register URLs in your IdP' });
      click('Continue');
      await screen.findByRole('heading', { name: 'Verification' });
      click('Save and run test');
      await screen.findByRole('heading', { name: 'Enable sign-in' });
      expect(api.post).toHaveBeenNthCalledWith(
        1,
        '/api/admin/sso/providers',
        expect.objectContaining({
          slug: 'office',
          type: protocol,
          enabled: false,
        })
      );
      if (protocol === 'saml') {
        expect(api.post.mock.calls[0][1].config.authn_request_binding).toBe(
          'HTTP-POST'
        );
        expect(api.post.mock.calls[0][1].config.secondary_cert).toContain(
          'TG9jYWwgcm9sbG92ZXIgZml4dHVyZQ=='
        );
      }
      expect(api.post).toHaveBeenNthCalledWith(
        2,
        '/api/admin/sso/providers/office/test'
      );
      expect(api.put).not.toHaveBeenCalled();
      expect(api.get).not.toHaveBeenCalled();

      click('Enable provider');
      await waitFor(() =>
        expect(api.put).toHaveBeenCalledWith(
          '/api/admin/sso/providers/office',
          { enabled: true }
        )
      );
      expect(navigate).toHaveBeenCalledWith(
        '/system-settings?section=sso-group-mappings&provider=office',
        { replace: true }
      );
    }
  );

  it('offers every enabled provider during a cross-protocol conflict', async () => {
    const providers = [
      { slug: 'openid', displayName: 'OpenID', type: 'oidc', enabled: true },
      { slug: 'backup', displayName: 'Backup', type: 'saml', enabled: false },
      {
        slug: 'assertion',
        displayName: 'Assertion',
        type: 'saml',
        enabled: true,
      },
    ];
    const reloadWarning =
      'The provider change was saved. Runtime status could not be confirmed on this API instance.';
    api.get.mockResolvedValueOnce({ data: { providers } });
    api.put.mockResolvedValue({
      data: {
        enabled: true,
        sso_reload_warnings: [
          { code: 'reload_failed', message: reloadWarning },
        ],
      },
    });
    api.get.mockResolvedValueOnce({
      data: {
        providers: [
          { ...providers[0], enabled: false },
          providers[1],
          providers[2],
        ],
      },
    });
    mount(<SsoProviders session={{}} />);
    expect(
      await screen.findByText(/Multiple SSO providers are enabled/)
    ).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Select OpenID' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Select Backup' })).toBeNull();
    click('Select Assertion');
    await waitFor(() =>
      expect(showWarning).toHaveBeenCalledWith(reloadWarning)
    );
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledExactlyOnceWith(
        '/api/admin/sso/providers/assertion',
        { enabled: true, selectForSignIn: true }
      )
    );
    await waitFor(() =>
      expect(
        screen.queryByText(/Multiple SSO providers are enabled/)
      ).toBeNull()
    );
  });

  it.each([true, false])(
    'saves a newly entered client secret before testing when save succeeds: %s',
    async saveSucceeds => {
      const existing = {
        slug: 'office',
        type: 'oidc',
        enabled: false,
        displayName: 'Office',
        config: {
          issuer: 'https://idp.example.test',
          client_id: 'test-client',
        },
      };
      api.get.mockResolvedValue({ data: existing });
      api.post.mockResolvedValue({ data: { ok: true, checks: [] } });
      let resolveSave;
      let rejectSave;
      api.put.mockImplementationOnce(
        () =>
          new Promise((resolve, reject) => {
            resolveSave = resolve;
            rejectSave = reject;
          })
      );
      mount(<SsoProviderEdit session={{}} />);
      await screen.findByLabelText(/^Client secret/);
      enter(/^Display name/, 'New office');
      enter(/^Client secret/, 'synthetic-secret');
      const test = screen.getByRole('button', {
        name: /^(Test|Save and run test)$/,
      });
      fireEvent.click(test);
      expect(api.put).toHaveBeenCalledExactlyOnceWith(
        '/api/admin/sso/providers/office',
        expect.objectContaining({
          displayName: 'New office',
          secrets: { client_secret: 'synthetic-secret' },
        })
      );
      expect(api.put.mock.calls[0][1]).not.toHaveProperty('enabled');
      expect(api.post).not.toHaveBeenCalled();
      if (!saveSucceeds) {
        rejectSave(new Error('Unavailable'));
        await waitFor(() =>
          expect(showWarning).toHaveBeenCalledWith('Save failed')
        );
        expect(api.post).not.toHaveBeenCalled();
        expect(screen.getByLabelText(/^Client secret/)).toHaveValue(
          'synthetic-secret'
        );
        return;
      }
      resolveSave({ data: { ...existing, displayName: 'New office' } });
      await screen.findByText('Last test result');
      expect(api.post).toHaveBeenCalledExactlyOnceWith(
        '/api/admin/sso/providers/office/test'
      );
      expect(screen.getByLabelText(/^Client secret/)).toHaveValue('');
      fireEvent.click(screen.getByRole('button', { name: 'Test' }));
      expect(api.put).toHaveBeenCalledTimes(1);
      expect(api.post).toHaveBeenCalledTimes(2);
    }
  );

  it('previews dependencies and requires explicit retirement choices', async () => {
    api.get.mockResolvedValue({
      data: {
        slug: 'office',
        type: 'oidc',
        enabled: false,
        displayName: 'Office',
      },
    });
    api.post.mockResolvedValue({
      data: {
        linked_identities_count: 2,
        affected_users: 2,
        requires_local_admin: true,
        has_usable_local_admin: true,
        dependency_counts: {
          identities_count: 2,
          memberships_count: 3,
          group_mappings_count: 1,
          admin_grants_count: 1,
        },
      },
    });
    api.delete.mockResolvedValue({ data: { ok: true } });
    mount(<SsoProviderEdit session={{}} />);
    fireEvent.click(
      await screen.findByRole('button', { name: 'Delete provider' })
    );

    const retire = await screen.findByRole('button', {
      name: 'Retire provider',
    });
    expect(screen.getByText('Group mappings: 1')).toBeInTheDocument();
    expect(
      screen.getByText('Provider-managed administrator grants: 1')
    ).toBeInTheDocument();
    expect(retire).toBeDisabled();
    enter(/Linked identity cleanup/, 'archive');
    expect(retire).toBeDisabled();
    enter(/Workspace membership cleanup/, 'convert-to-manual');
    expect(retire).toBeEnabled();
    fireEvent.click(retire);

    await waitFor(() =>
      expect(api.delete).toHaveBeenCalledExactlyOnceWith(
        '/api/admin/sso/providers/office',
        {
          params: {
            confirmRetirement: true,
            identityPolicy: 'archive',
            membershipPolicy: 'convert-to-manual',
          },
        }
      )
    );
  });
});
