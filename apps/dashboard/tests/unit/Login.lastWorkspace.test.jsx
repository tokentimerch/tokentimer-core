import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { ChakraProvider } from '@chakra-ui/react';

import Login from '../../src/pages/Login.jsx';
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
  default: {
    post: postMock,
  },
  authAPI: {
    login: loginMock,
  },
}));

function renderLogin({ search = '' } = {}) {
  window.history.replaceState({}, '', `/login${search}`);
  return render(
    <ChakraProvider>
      <MemoryRouter initialEntries={[`/login${search}`]}>
        <Login />
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
