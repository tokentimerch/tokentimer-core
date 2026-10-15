import { beforeEach, describe, expect, it, vi } from 'vitest';
import { retireCertificate } from '../../src/components/certops/certopsApi.js';

const post = vi.hoisted(() => vi.fn());
vi.mock('../../src/utils/apiClient', () => ({ default: { post } }));

describe('certificate retirement request', () => {
  beforeEach(() => {
    post.mockReset();
  });

  it('refuses to send a retirement without the displayed fingerprint', async () => {
    post.mockRejectedValue({
      response: {
        status: 428,
        data: {
          error: 'Certificate fingerprint precondition required',
        },
      },
    });
    await expect(
      retireCertificate('workspace', 'source', {
        status: 'revoked',
        reason: 'Operator decision',
      })
    ).rejects.toThrow(/fingerprint/i);
    expect(post).not.toHaveBeenCalled();
  });

  it('sends the selected immutable identity with its normalized expected SHA-256', async () => {
    post.mockResolvedValue({ data: { certificate: {} } });
    const expected = 'ab'.repeat(32);
    await retireCertificate('workspace', 'source', {
      identityId: 'identity-a',
      fingerprintSha256: expected.toUpperCase().match(/../g).join(':'),
      status: 'decommissioned',
      reason: 'Service removed',
      acknowledgeUncertainty: true,
    });
    expect(post).toHaveBeenCalledWith(
      '/api/v1/workspaces/workspace/certops/certificate-identities/identity-a/retire',
      {
        status: 'decommissioned',
        reason: 'Service removed',
        expectedFingerprintSha256: expected,
        acknowledgeUncertainty: true,
      }
    );
  });

  it('preserves a stale fingerprint rejection without retrying or fetching a different identity', async () => {
    const error = {
      response: {
        status: 412,
        data: { code: 'CERTOPS_IDENTITY_PRECONDITION_FAILED' },
      },
    };
    post.mockRejectedValue(error);
    await expect(
      retireCertificate('workspace', 'source', {
        identityId: 'identity-a',
        fingerprintSha256: 'a'.repeat(64),
        status: 'revoked',
        reason: 'Selected certificate',
      })
    ).rejects.toBe(error);
    expect(post).toHaveBeenCalledTimes(1);
  });
});
