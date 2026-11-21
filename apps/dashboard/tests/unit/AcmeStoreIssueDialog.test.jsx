import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { expect, it, vi } from 'vitest';
import AcmeStoreIssueDialog from '../../src/components/certops/AcmeStoreIssueDialog.jsx';
const mocks = vi.hoisted(() => ({ create: vi.fn() }));
vi.mock('../../src/components/certops/certopsJobsApi', () => ({ createJob: mocks.create }));
it('offers only qualified agents and reuses the idempotency key on retry', async () => {
  mocks.create.mockReset().mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce({ job: { id: 'job-1' } });
  const agents = [{ id: 'qualified', name: 'Qualified', status: 'active', platform: 'win32', declaredCapabilities: ['windows-store-only-acme-v1', 'evidence-claim-binding-v1'] },
    { id: 'unqualified', name: 'Unqualified', status: 'active', platform: 'win32', declaredCapabilities: [] }];
  render(<ChakraProvider><AcmeStoreIssueDialog isOpen onClose={() => {}} workspaceId='workspace-1' agents={agents} /></ChakraProvider>);
  expect(screen.queryByRole('option', { name: 'Unqualified' })).toBeNull();
  fireEvent.change(screen.getByLabelText('Windows agent'), { target: { value: 'qualified' } });
  for (const [label, value] of [['DNS name','app.example.com'],['ACME directory URL','https://acme.example.com'],['Allowed command name','certbot'],['DNS provider','provider'],['DNS zone','example.com']]) {
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
  }
  fireEvent.click(screen.getByRole('button', { name: 'Issue certificate' }));
  await screen.findByText('Could not create the issuance job.');
  fireEvent.click(screen.getByRole('button', { name: 'Issue certificate' }));
  await waitFor(() => expect(mocks.create).toHaveBeenCalledTimes(2));
  expect(mocks.create.mock.calls[0][1].idempotencyKey).toBe(mocks.create.mock.calls[1][1].idempotencyKey);
  expect(await screen.findByText(/certificate must still be configured on the service/)).toBeInTheDocument();
});
