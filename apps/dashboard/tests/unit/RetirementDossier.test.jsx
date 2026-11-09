import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import RetirementDossier from '../../src/components/certops/RetirementDossier.jsx';
import { distributionApi } from '../../src/components/certops/distributionApi.js';

vi.mock('../../src/components/certops/distributionApi.js', () => ({
  distributionApi: {
    retirementDossiers: vi.fn(),
    retirementDossier: vi.fn(),
    requestRetirementDossier: vi.fn(),
    reviewRetirementDossier: vi.fn(),
  },
}));
const detail = {
  id: 'case',
  status: 'pending_review',
  scopeStatus: 'current',
  original_job_id: 'job',
  dossier_hash: 'hash',
  requested_by: '1',
  reviewed_by: null,
  scope: {
    bindingId: 'binding',
    groupId: 'group',
    assignedAgentId: 'old-agent',
    currentAgentId: 'new-agent',
    bindingState: 'active',
    bindingAuthorizationRevision: '1',
    originalGeneration: 1,
    currentGeneration: 2,
    desiredGeneration: 2,
    desiredMaterialVersionId: 'version',
  },
  evidence: {
    writerInventory: 'a',
    writerIsolation: 'b',
    destinationIsolation: 'c',
    replacementReadback: 'd',
  },
};
function mount() {
  return render(
    <ChakraProvider>
      <RetirementDossier workspaceId='workspace' canManage />
    </ChakraProvider>
  );
}
async function select() {
  fireEvent.change(screen.getByLabelText('Original job ID'), {
    target: { value: 'job' },
  });
  fireEvent.click(screen.getByText('Find dossiers'));
  fireEvent.click(await screen.findByText('pending review · case'));
  await screen.findByText(/Original agent: old-agent/);
}
beforeEach(() => {
  vi.clearAllMocks();
  distributionApi.retirementDossiers.mockResolvedValue({
    items: [{ id: 'case', status: 'pending_review' }],
    hasMore: false,
  });
  distributionApi.retirementDossier.mockResolvedValue(detail);
});
describe('advisory retirement dossier', () => {
  it('shows unverified warning, full scope, and clears confirmation when job changes', async () => {
    mount();
    expect(screen.getByText(/History remains unknown/)).toBeTruthy();
    await select();
    fireEvent.click(screen.getByRole('checkbox'));
    expect(screen.getByText('Record advisory review').disabled).toBe(false);
    fireEvent.change(screen.getByLabelText('Original job ID'), {
      target: { value: 'other' },
    });
    expect(screen.queryByText('Record advisory review')).toBeNull();
    expect(screen.queryByText('pending review · case')).toBeNull();
  });
  it('blocks stale review and displays server rejection without clearing the obligation', async () => {
    distributionApi.retirementDossier.mockResolvedValueOnce({
      ...detail,
      scopeStatus: 'stale',
    });
    mount();
    await select();
    fireEvent.click(screen.getByRole('checkbox'));
    expect(screen.getByText('Record advisory review').disabled).toBe(true);
    distributionApi.retirementDossier.mockResolvedValue(detail);
    fireEvent.click(screen.getByText('pending review · case'));
    await screen.findByText(/Scope: current/);
    fireEvent.click(screen.getByRole('checkbox'));
    distributionApi.reviewRetirementDossier.mockRejectedValue({
      response: { data: { code: 'CERTOPS_RETIREMENT_REVIEW_STALE' } },
    });
    fireEvent.click(screen.getByText('Record advisory review'));
    await waitFor(() =>
      expect(screen.getByText('CERTOPS_RETIREMENT_REVIEW_STALE')).toBeTruthy()
    );
  });
  it('requests a dossier with four digests and reports request errors', async () => {
    mount();
    fireEvent.change(screen.getByLabelText('Original job ID'), {
      target: { value: 'job' },
    });
    for (const name of [
      'Writer and clone inventory',
      'Writer isolation',
      'Destination isolation',
      'Replacement readback',
    ])
      fireEvent.change(screen.getByLabelText(`${name} digest`), {
        target: { value: `sha256:${'a'.repeat(64)}` },
      });
    distributionApi.requestRetirementDossier.mockRejectedValueOnce({
      response: { data: { code: 'CERTOPS_RETIREMENT_EVIDENCE_INVALID' } },
    });
    fireEvent.click(screen.getByText('Request independent review'));
    await screen.findByText('CERTOPS_RETIREMENT_EVIDENCE_INVALID');
    distributionApi.requestRetirementDossier.mockResolvedValueOnce({
      id: 'case',
    });
    fireEvent.click(screen.getByText('Request independent review'));
    await screen.findByText('pending review · case');
    expect(distributionApi.requestRetirementDossier).toHaveBeenLastCalledWith(
      'workspace',
      'job',
      expect.objectContaining({ writerInventory: `sha256:${'a'.repeat(64)}` })
    );
  });
  it('records a separate review only after confirmation and reports unknown history', async () => {
    mount();
    await select();
    fireEvent.click(screen.getByRole('checkbox'));
    distributionApi.reviewRetirementDossier.mockResolvedValue({
      reconciliationCleared: false,
    });
    distributionApi.retirementDossier.mockResolvedValueOnce({
      ...detail,
      status: 'reviewed_history_unknown',
      reviewed_by: '2',
    });
    fireEvent.click(screen.getByText('Record advisory review'));
    await waitFor(() =>
      expect(distributionApi.reviewRetirementDossier).toHaveBeenCalledWith(
        'workspace',
        'case',
        'hash'
      )
    );
    await screen.findByText(/Reviewer: 2/);
    expect(screen.queryByText('Record advisory review')).toBeNull();
  });
  it('does not restore an old selection when a pending review completes after job changes', async () => {
    mount();
    await select();
    fireEvent.click(screen.getByRole('checkbox'));
    let resolveReview;
    distributionApi.reviewRetirementDossier.mockReturnValue(
      new Promise(resolve => {
        resolveReview = resolve;
      })
    );
    fireEvent.click(screen.getByText('Record advisory review'));
    fireEvent.change(screen.getByLabelText('Original job ID'), {
      target: { value: 'other' },
    });
    resolveReview({ reconciliationCleared: false });
    await waitFor(() =>
      expect(distributionApi.reviewRetirementDossier).toHaveBeenCalled()
    );
    expect(screen.queryByText(/Original agent: old-agent/)).toBeNull();
    expect(distributionApi.retirementDossier).toHaveBeenCalledTimes(1);
  });
  it('does not list an old job when a pending request completes after job changes', async () => {
    mount();
    fireEvent.change(screen.getByLabelText('Original job ID'), {
      target: { value: 'job' },
    });
    let resolveRequest;
    distributionApi.requestRetirementDossier.mockReturnValue(
      new Promise(resolve => {
        resolveRequest = resolve;
      })
    );
    fireEvent.click(screen.getByText('Request independent review'));
    fireEvent.change(screen.getByLabelText('Original job ID'), {
      target: { value: 'other' },
    });
    resolveRequest({ id: 'case' });
    await waitFor(() =>
      expect(distributionApi.requestRetirementDossier).toHaveBeenCalled()
    );
    expect(distributionApi.retirementDossiers).not.toHaveBeenCalled();
    expect(screen.queryByText('pending review · case')).toBeNull();
  });
});
