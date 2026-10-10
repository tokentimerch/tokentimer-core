import { describe, expect, it, vi, beforeEach } from 'vitest';
import {
  loadAgentLogPages,
  mapWithConcurrency,
} from '../../src/components/certops/AgentFleetPanel.jsx';

vi.mock('../../src/components/certops/certopsJobsApi', () => ({
  listAgentJobLog: vi.fn(),
  listAgentFleetLog: vi.fn(),
}));

import { listAgentJobLog } from '../../src/components/certops/certopsJobsApi';

describe('AgentFleetPanel fleet log helpers', () => {
  beforeEach(() => {
    listAgentJobLog.mockReset();
  });

  it('stops at maxItems and reports truncation when more pages remain', async () => {
    listAgentJobLog
      .mockResolvedValueOnce({
        items: Array.from({ length: 100 }, (_, i) => ({ seq: i + 1 })),
        hasMore: true,
        nextCursor: 'c1',
      })
      .mockResolvedValueOnce({
        items: Array.from({ length: 50 }, (_, i) => ({ seq: i + 101 })),
        hasMore: true,
        nextCursor: 'c2',
      });

    const result = await loadAgentLogPages('ws', 'job-1', {
      pageSize: 100,
      maxPages: 10,
      maxItems: 150,
    });

    expect(result.items).toHaveLength(150);
    expect(result.truncated).toBe(true);
    expect(listAgentJobLog).toHaveBeenCalledTimes(2);
  });

  it('mapWithConcurrency bounds parallel workers', async () => {
    let inflight = 0;
    let peak = 0;
    const items = [1, 2, 3, 4, 5];
    const results = await mapWithConcurrency(items, 2, async value => {
      inflight += 1;
      peak = Math.max(peak, inflight);
      await Promise.resolve();
      inflight -= 1;
      return value * 2;
    });
    expect(results).toEqual([2, 4, 6, 8, 10]);
    expect(peak).toBeLessThanOrEqual(2);
  });
});
