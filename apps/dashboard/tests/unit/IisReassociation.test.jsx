import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import IisReassociation from '../../src/components/certops/IisReassociation.jsx';
import {
  listIisReassociationCandidates,
  reassociateWindowsSource,
} from '../../src/components/certops/certopsApi';

vi.mock('../../src/components/certops/certopsApi', () => ({
  listIisReassociationCandidates: vi.fn(),
  reassociateWindowsSource: vi.fn(),
}));

describe('IIS reassociation', () => {
  it('shows the exact binding and fingerprint before explicitly moving the profile', async () => {
    const candidate = {
      currentId: 'binding-443',
      host: 'pilot',
      site: 'Default Web Site',
      port: 443,
      expectedFingerprintSha256: 'abc123',
      expectedDnsName: 'pilot.example',
      agentId: 'agent',
    };
    listIisReassociationCandidates.mockResolvedValue({ items: [candidate] });
    reassociateWindowsSource.mockResolvedValue({});
    const changed = vi.fn();
    render(
      <ChakraProvider>
        <IisReassociation
          workspaceId='workspace'
          sourceId='legacy'
          onChanged={changed}
        />
      </ChakraProvider>
    );
    fireEvent.click(screen.getByText('Find matching IIS binding'));
    const select = await screen.findByLabelText(
      'IIS binding for reassociation'
    );
    fireEvent.change(select, { target: { value: 'binding-443' } });
    expect(screen.getByText(/Confirm Default Web Site:443/)).toHaveTextContent(
      'abc123'
    );
    expect(reassociateWindowsSource).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText('Move renewal profile to this binding'));
    await waitFor(() =>
      expect(reassociateWindowsSource).toHaveBeenCalledWith(
        'workspace',
        'legacy',
        candidate
      )
    );
    await waitFor(() => expect(changed).toHaveBeenCalled());
  });
});
