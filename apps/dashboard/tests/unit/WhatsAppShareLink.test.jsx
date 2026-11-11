import { render, screen, fireEvent } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { describe, it, expect } from 'vitest';
import ContactVerificationControls from '../../src/pages/ContactVerificationControls.jsx';

const url = 'https://example.test/verify/recipient/visible-link';
function controls({
  status = 'pending',
  expiresAt = new Date(Date.now() + 3600000).toISOString(),
  serverExpiry = expiresAt,
  isViewer = false,
  mode = 'enforce',
} = {}) {
  return render(
    <ChakraProvider>
      <ContactVerificationControls
        contact={{
          id: 'contact-b',
          phone_e164: '+12025550123',
          verification: {
            whatsapp: { status, invitation: { expires_at: serverExpiry } },
          },
        }}
        mode={mode}
        isViewer={isViewer}
        sharedInvitation={{ url, expiresAt }}
        onInviteEmail={() => {}}
        onShareWhatsApp={() => {}}
        onRevoke={() => {}}
      />
    </ChakraProvider>
  );
}
describe('WhatsApp invitation recovery', () => {
  it('keeps the generated link visible, read-only and selected on focus without clipboard permission', async () => {
    controls();
    fireEvent.click(screen.getByRole('button', { name: 'View confirmation link' }));
    const input = await screen.findByRole('textbox', {
      name: 'WhatsApp confirmation link',
    });
    expect(input).toHaveValue(url);
    expect(input).toHaveAttribute('readonly');
    fireEvent.focus(input);
    expect(input.selectionStart).toBe(0);
    expect(input.selectionEnd).toBe(url.length);
    expect(screen.getByText(/before leaving this page/)).toBeInTheDocument();
  });
  for (const status of ['verified', 'revoked', 'opted_out'])
    it('hides the link after consent becomes ' + status, () => {
      controls({ status });
      expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
    });
  it('hides expired invitations', () => {
    controls({ expiresAt: new Date(Date.now() - 1000).toISOString() });
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
  });
  it('hides a superseded invitation', () => {
    controls({ serverExpiry: new Date(Date.now() + 7200000).toISOString() });
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
  });
  it('explains shadow mode without claiming confirmation blocks delivery', () => {
    controls({ mode: 'shadow' });
    fireEvent.click(screen.getByRole('button', { name: 'View confirmation link' }));
    expect(screen.getByText(/does not block alerts or tests/)).toBeInTheDocument();
  });
  it('hides confirmation controls when verification is off', () => {
    controls({ mode: 'off' });
    expect(screen.queryByText('WhatsApp')).not.toBeInTheDocument();
  });
  it('does not show the manager link to a viewer', () => {
    controls({ isViewer: true });
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
  });
});
