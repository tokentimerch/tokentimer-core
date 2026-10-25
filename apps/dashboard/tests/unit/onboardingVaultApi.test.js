import { beforeEach, describe, expect, it, vi } from 'vitest';
const client = vi.hoisted(() => ({
  get: vi.fn(),
  put: vi.fn(),
  post: vi.fn(),
}));
vi.mock('../../src/utils/apiClient', () => ({ default: client }));
import {
  assignConsumer,
  readDistribution,
  requestRollout,
  retryDeployment,
} from '../../src/components/onboarding/vaultGuideApi.js';

beforeEach(() => vi.clearAllMocks());
describe('Vault guide uses the authenticated workspace surface', () => {
  it('reads versions and consumer evidence together, and propagates failed reads', async () => {
    const abort = new AbortController();
    client.get.mockImplementation(url =>
      Promise.resolve({
        data: url.endsWith('versions')
          ? { versions: [{ id: 'v' }] }
          : { consumers: [{ binding_id: 'b' }] },
      })
    );
    expect(
      await readDistribution('ws', 'group', { signal: abort.signal })
    ).toEqual({ versions: [{ id: 'v' }], consumers: [{ binding_id: 'b' }] });
    expect(client.get).toHaveBeenCalledWith(
      '/api/v1/workspaces/ws/certops/distribution-groups/group/versions',
      { signal: abort.signal }
    );
    client.get.mockRejectedValue(new Error('Access denied'));
    await expect(readDistribution('ws', 'group')).rejects.toThrow(
      'Access denied'
    );
  });
  it('returns the exact assignment response without inventing a local revision', async () => {
    const binding = { agentId: 'agent-row', profileRevision: 4, wave: 1 };
    client.put.mockResolvedValue({ data: { authorization_revision: 7 } });
    expect(await assignConsumer('ws', 'group', 'binding', binding)).toEqual({
      authorization_revision: 7,
    });
    expect(client.put).toHaveBeenCalledWith(
      '/api/v1/workspaces/ws/certops/distribution-groups/group/consumers/binding',
      binding
    );
  });
  it('sends the selected intent and stable idempotency header without forcing approval', async () => {
    const body = { materialVersionId: 'published-v', maxParallel: 1 };
    client.post.mockResolvedValue({ data: { id: 'coordinator-job' } });
    expect(await requestRollout('ws', 'group', body, 'request-key')).toEqual({
      id: 'coordinator-job',
    });
    expect(client.post).toHaveBeenCalledWith(
      '/api/v1/workspaces/ws/certops/distribution-groups/group/rollouts',
      body,
      { headers: { 'Idempotency-Key': 'request-key' } }
    );
    expect(client.post.mock.calls[0][1]).not.toHaveProperty('requiresApproval');
  });
  it('retries only the named distribution job through its normal guarded endpoint', async () => {
    client.post.mockResolvedValue({
      data: { jobId: 'job', status: 'pending' },
    });
    expect(await retryDeployment('ws', 'job')).toEqual({
      jobId: 'job',
      status: 'pending',
    });
    expect(client.post).toHaveBeenCalledWith(
      '/api/v1/workspaces/ws/certops/distribution-jobs/job/retry',
      {}
    );
  });
});
