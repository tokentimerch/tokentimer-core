import { describe, it, expect } from 'vitest';
import {
  isCertOpsResourceId,
  jobAgentHref,
  jobSubjectHref,
} from '../../src/components/certops/certopsResourceLinks.js';

const CERT_ID = '11111111-1111-4111-8111-111111111111';
const AGENT_ID = '22222222-2222-4222-8222-222222222222';
const ANCHOR_ID = '33333333-3333-4333-8333-333333333333';

describe('certopsResourceLinks', () => {
  it('accepts only UUID resource identifiers', () => {
    expect(isCertOpsResourceId(CERT_ID)).toBe(true);
    expect(isCertOpsResourceId('cert-alpha')).toBe(false);
    expect(isCertOpsResourceId('')).toBe(false);
    expect(isCertOpsResourceId(null)).toBe(false);
  });

  it('builds certificate and trust-anchor deep links from subject ids', () => {
    expect(jobSubjectHref('managed_certificate', CERT_ID)).toBe(
      `/certops/certificates?certificateId=${CERT_ID}`
    );
    expect(jobSubjectHref('trust_anchor', ANCHOR_ID)).toBe(
      `/certops/agents?trustAnchorId=${ANCHOR_ID}`
    );
  });

  it('does not invent links for unsupported or missing subjects', () => {
    expect(jobSubjectHref('token', CERT_ID)).toBeNull();
    expect(jobSubjectHref('managed_certificate', 'not-a-uuid')).toBeNull();
    expect(jobSubjectHref('managed_certificate', '')).toBeNull();
  });

  it('builds agent deep links from agent ids', () => {
    expect(jobAgentHref(AGENT_ID)).toBe(
      `/certops/agents?agentId=${AGENT_ID}`
    );
    expect(jobAgentHref('agent-1')).toBeNull();
  });
});
