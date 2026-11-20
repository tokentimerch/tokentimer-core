import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';

import { theme } from '../../src/styles/theme.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import SsoProviderWizard from '../../src/pages/SsoProviderWizard.jsx';
import SsoProviders from '../../src/pages/SsoProviders.jsx';
import { showWarning } from '../../src/utils/toast.js';

const { api, navigate } = vi.hoisted(() => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn() },
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
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/sso"/>
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
        '/sso-providers',
        expect.any(Object)
      );
    }
  );

  it('requires a named selection for previously enabled providers', async () => {
    const providers = [
      { slug: 'openid', displayName: 'OpenID', type: 'oidc', enabled: true },
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
      data: { providers: [{ ...providers[0], enabled: false }, providers[1]] },
    });
    mount(<SsoProviders session={{}} />);
    expect(
      await screen.findByText(/Multiple providers were previously enabled/)
    ).toBeTruthy();
    click('Select Assertion');
    await waitFor(() =>
      expect(showWarning).toHaveBeenCalledWith(reloadWarning)
    );
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledExactlyOnceWith(
        '/api/admin/sso/providers/assertion',
        { enabled: true }
      )
    );
    await waitFor(() =>
      expect(
        screen.queryByText(/Multiple providers were previously enabled/)
      ).toBeNull()
    );
  });
});
