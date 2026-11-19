import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, expect, it, vi } from 'vitest';
import AcmeStoreRecovery from '../../src/components/certops/AcmeStoreRecovery.jsx';
const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), canManage: vi.fn() }));
vi.mock('../../src/utils/apiClient', () => ({ default: { get: mocks.get, post: mocks.post } }));
vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({ useWorkspace: () => ({ workspaceId: 'workspace-1' }) }));
vi.mock('../../src/components/certops/useCertOps.js', () => ({ useCertOpsCanManage: mocks.canManage }));
beforeEach(() => { mocks.get.mockReset(); mocks.post.mockReset(); mocks.canManage.mockReset().mockReturnValue(true); });
it('requires explicit consent and a reason before recovering on the original agent', async () => {
  mocks.get.mockResolvedValue({ data: { enrollmentId: 'enrollment-1', outcomeUncertain: true, recoveryAvailable: true } });
  mocks.post.mockResolvedValue({ data: { jobId: 'recovery-1' } });
  render(<ChakraProvider><AcmeStoreRecovery job={{ id: 'job-1', status: 'orphaned_unknown_effect' }} /></ChakraProvider>);
  const button = await screen.findByRole('button', { name: 'Recover on original agent' });
  expect(button).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Recovery reason'), { target: { value: 'Checked the host' } });
  expect(button).toBeDisabled();
  fireEvent.click(screen.getByRole('checkbox'));
  fireEvent.click(button);
  await waitFor(() => expect(mocks.post).toHaveBeenCalledWith(expect.stringContaining('/enrollment-1/recover'),
    { orphanedJobId: 'job-1', reason: 'Checked the host', acknowledgeUnknownEffect: true }));
  expect(await screen.findByText(/Recovery job recovery-1 queued/)).toBeInTheDocument();
});
it('does not expose the action to users without management access', () => {
  mocks.canManage.mockReturnValue(false);
  render(<ChakraProvider><AcmeStoreRecovery job={{ id: 'job-1', status: 'orphaned_unknown_effect' }} /></ChakraProvider>);
  expect(mocks.get).not.toHaveBeenCalled();
  expect(screen.queryByRole('button', { name: 'Recover on original agent' })).toBeNull();
});
