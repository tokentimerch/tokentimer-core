import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { LeadTimeEditor } from '../../src/components/certops/RenewalProfilesPanel.jsx';

describe('renewal lead time editor', () => {
  it('can reset a stored lead time to the deployment default', async () => {
    const onSave = vi.fn().mockResolvedValue(true);
    render(
      <ChakraProvider>
        <LeadTimeEditor profile={{ renewBeforeDays: 30 }} onSave={onSave} />
      </ChakraProvider>
    );
    fireEvent.click(screen.getByRole('button', { name: 'Change' }));
    fireEvent.click(
      screen.getByRole('button', { name: 'Use deployment default' })
    );
    await waitFor(() => expect(onSave).toHaveBeenCalledWith(null));
  });
  it('retains explicit numeric overrides', async () => {
    const onSave = vi.fn().mockResolvedValue(true);
    render(
      <ChakraProvider>
        <LeadTimeEditor profile={{ renewBeforeDays: 30 }} onSave={onSave} />
      </ChakraProvider>
    );
    fireEvent.click(screen.getByRole('button', { name: 'Change' }));
    fireEvent.change(screen.getByLabelText('Renewal lead time in days'), {
      target: { value: '12' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSave).toHaveBeenCalledWith(12));
  });
});
