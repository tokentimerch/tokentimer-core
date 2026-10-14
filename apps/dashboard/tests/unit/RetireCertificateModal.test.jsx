import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import RetireCertificateModal from '../../src/components/certops/RetireCertificateModal.jsx';

const older = {
  id: 'discovery-a',
  commonName: 'app.example',
  fingerprintSha256: 'a'.repeat(64),
  status: 'discovered',
  source: 'agent_filesystem',
  notAfter: '2026-10-20',
};
const renewed = {
  ...older,
  id: 'issuance-b',
  fingerprintSha256: 'b'.repeat(64),
  status: 'active',
  source: 'agent_issuance',
  notAfter: '2027-01-12',
};

function show(props = {}) {
  const onRetire = vi.fn().mockResolvedValue(undefined);
  render(
    <ChakraProvider>
      <RetireCertificateModal
        isOpen
        onClose={vi.fn()}
        onRetire={onRetire}
        token={{ id: 1, name: 'app.example' }}
        {...props}
      />
    </ChakraProvider>
  );
  return onRetire;
}

describe('retiring a certificate from a shared token', () => {
  it('requires explicit fingerprint selection and submits only the chosen renewed certificate', async () => {
    const onRetire = show({ certificates: [older, renewed] });
    fireEvent.click(screen.getByRole('radio', { name: /Mark revoked/ }));
    fireEvent.change(screen.getByPlaceholderText(/Reason/), {
      target: { value: 'Revocation recorded by operator' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Mark revoked' }));
    expect(onRetire).not.toHaveBeenCalled();
    expect(
      screen.getByText('Choose the certificate to retire.')
    ).toBeInTheDocument();
    fireEvent.change(
      screen.getByRole('combobox', { name: 'Certificate to retire' }),
      {
        target: { value: renewed.id },
      }
    );
    fireEvent.click(screen.getByRole('button', { name: 'Mark revoked' }));
    await waitFor(() =>
      expect(onRetire).toHaveBeenCalledWith({
        certificate: renewed,
        status: 'revoked',
        reason: 'Revocation recorded by operator',
        acknowledgeUncertainty: false,
      })
    );
  });

  it('groups same-fingerprint sources into one retirement target', async () => {
    const duplicate = {
      ...renewed,
      id: 'discovery-b',
      source: 'agent_filesystem',
    };
    const onRetire = show({ certificates: [renewed, duplicate] });
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('radio', { name: /Mark revoked/ }));
    fireEvent.change(screen.getByPlaceholderText(/Reason/), {
      target: { value: 'Revocation confirmed' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Mark revoked' }));
    await waitFor(() =>
      expect(onRetire).toHaveBeenCalledWith(
        expect.objectContaining({
          certificate: expect.objectContaining({
            fingerprintSha256: renewed.fingerprintSha256,
          }),
          status: 'revoked',
        })
      )
    );
  });

  it('retains reason and uncertainty acknowledgment for an explicitly selected certificate', async () => {
    const onRetire = show({ certificate: renewed });
    fireEvent.click(screen.getByRole('button', { name: 'Decommission' }));
    expect(onRetire).not.toHaveBeenCalled();
    fireEvent.change(screen.getByPlaceholderText(/Reason/), {
      target: { value: 'Service removed' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Decommission' }));
    expect(onRetire).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByRole('button', { name: 'Decommission' }));
    await waitFor(() =>
      expect(onRetire).toHaveBeenCalledWith({
        certificate: renewed,
        status: 'decommissioned',
        reason: 'Service removed',
        acknowledgeUncertainty: true,
      })
    );
  });
});
