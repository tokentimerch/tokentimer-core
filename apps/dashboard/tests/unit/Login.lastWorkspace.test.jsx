import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { ChakraProvider } from '@chakra-ui/react';

import Login from '../../src/pages/Login.jsx';
import { loginNextPath } from '../../src/lib/sso-ui-shared.js';
import {
  LAST_WORKSPACE_LEGACY_KEY,
  writeLastWorkspaceId,
} from '../../src/utils/lastWorkspacePreference.js';

const { loginMock, postMock } = vi.hoisted(() => ({
  loginMock: vi.fn(),
  postMock: vi.fn(),
}));

vi.mock('../../src/components/SEO.jsx', () => ({
  default: () => null,
}));

vi.mock('../../src/utils/logoUtils.js', () => ({
  getLogoPath: () => '/logo.png',
}));

vi.mock('../../src/utils/analytics.js', () => ({
  trackEvent: vi.fn(),
}));

vi.mock('../../src/components/WelcomeModal', () => ({
  default: () => null,
}));

vi.mock('../../src/utils/apiClient', () => ({
  API_BASE_URL: '',
  default: {
    post: postMock,
  },
  authAPI: {
    login: loginMock,
  },
}));

function renderLogin({ search = '', session } = {}) {
  window.history.replaceState({}, '', `/login${search}`);
  return render(
    <ChakraProvider>
      <MemoryRouter initialEntries={[`/login${search}`]}>
        <Login session={session} />
      </MemoryRouter>
    </ChakraProvider>
  );
}

describe('Login keeps the last workspace for restore', () => {
  beforeEach(() => {
    localStorage.clear();
    loginMock.mockReset();
    postMock.mockReset();
    writeLastWorkspaceId('user-a', 'ws-ops');
    vi.stubGlobal('location', {
      ...window.location,
      href: 'http://localhost/login',
      search: '',
      pathname: '/login',
      assign: vi.fn(),
      replace: vi.fn(),
    });
  });

  it('does not clear last workspace after email login', async () => {
    loginMock.mockResolvedValue({ user: { id: 'user-a' } });
    renderLogin();

    fireEvent.change(screen.getByPlaceholderText('Enter your email'), {
      target: { value: 'a@example.com' },
    });
    fireEvent.change(screen.getByPlaceholderText('Enter your password'), {
      target: { value: 'password-value' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Sign In' }));

    await waitFor(() => expect(loginMock).toHaveBeenCalled());
    expect(localStorage.getItem(LAST_WORKSPACE_LEGACY_KEY)).toBe('ws-ops');
    expect(window.location.href).toBe('/dashboard');
  });

  it('does not clear last workspace after 2FA login', async () => {
    loginMock.mockResolvedValue({ requires2FA: true });
    postMock.mockResolvedValue({ data: { success: true } });
    renderLogin();

    fireEvent.change(screen.getByPlaceholderText('Enter your email'), {
      target: { value: 'a@example.com' },
    });
    fireEvent.change(screen.getByPlaceholderText('Enter your password'), {
      target: { value: 'password-value' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Sign In' }));

    await waitFor(() =>
      expect(
        screen.getByPlaceholderText('Enter 6-digit code')
      ).toBeInTheDocument()
    );

    fireEvent.change(screen.getByPlaceholderText('Enter 6-digit code'), {
      target: { value: '123456' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Verify & Sign In' }));

    await waitFor(() => expect(postMock).toHaveBeenCalled());
    expect(localStorage.getItem(LAST_WORKSPACE_LEGACY_KEY)).toBe('ws-ops');
    expect(window.location.href).toBe('/dashboard');
  });

  it('does not clear last workspace on the email-verification success branch', async () => {
    loginMock.mockResolvedValue({ user: { id: 'user-a' } });
    window.location.search = '?verification_success=true';
    renderLogin({ search: '?verification_success=true' });

    fireEvent.change(screen.getByPlaceholderText('Enter your email'), {
      target: { value: 'a@example.com' },
    });
    fireEvent.change(screen.getByPlaceholderText('Enter your password'), {
      target: { value: 'password-value' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Sign In' }));

    await waitFor(() => expect(loginMock).toHaveBeenCalled());
    expect(localStorage.getItem(LAST_WORKSPACE_LEGACY_KEY)).toBe('ws-ops');
    expect(window.location.href).toBe('/dashboard?first_login=true');
  });
});

describe('SSO login', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          providers: {
            oidc: [
              { slug: 'oidc-office', displayName: 'Office', signInReady: true },
            ],
            saml: [
              {
                slug: 'saml-office',
                displayName: 'Partner',
                signInReady: true,
              },
            ],
          },
        }),
      })
    );
  });

  afterEach(() => vi.unstubAllGlobals());

  it('shows both ready protocols and refreshes readiness on focus', async () => {
    const next = '/system-settings?section=access#roles';
    renderLogin({ search: `?next=${encodeURIComponent(next)}` });

    for (const [type, slug, name] of [
      ['oidc', 'oidc-office', 'Office'],
      ['saml', 'saml-office', 'Partner'],
    ]) {
      const link = await screen.findByRole('link', {
        name: `Sign in with ${name}`,
      });
      expect(link.href).toContain(
        `/auth/${type}/${slug}?next=${encodeURIComponent(next)}`
      );
    }

    const first = fetch.mock.calls[0][1];
    expect(first.cache).toBe('no-store');
    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ providers: { oidc: [] } }),
    });
    fireEvent.focus(window);
    await waitFor(() =>
      expect(
        screen.queryByRole('link', { name: 'Sign in with Office' })
      ).toBeNull()
    );
    expect(first.signal.aborted).toBe(true);
  });

  it.each([undefined, { isAdmin: false }, { isAdmin: true }])(
    'limits callback diagnostics to administrator sessions (%j)',
    async session => {
      renderLogin({
        search:
          '?error=oidc_failed&reason=issuer_mismatch&provider=private-name',
        session,
      });

      await screen.findByRole('link', { name: 'Sign in with Office' });
      expect(screen.getByText(/Single sign-on failed/)).toBeInTheDocument();
      expect(screen.queryByText(/private-name/)).toBeNull();
      const details = screen.queryByRole('button', { name: 'Details' });
      if (session?.isAdmin) {
        fireEvent.click(details);
        expect(
          screen.getByText(/ID token issuer does not match/)
        ).toBeVisible();
      } else {
        expect(details).toBeNull();
      }
    }
  );

  it.each([
    'https://external.test',
    '//external.test',
    '/\\external.test',
    '/a/..//external.test',
    '/mcp/authorize?request=invalid',
  ])('rejects an unsafe next target %s', next =>
    expect(loginNextPath(new URLSearchParams({ next }))).toBeNull()
  );
});
