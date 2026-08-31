import { describe, it, expect } from 'vitest';
import {
  agentDisplayName,
  indexAgentsByAnyId,
  formatAgentLabel,
  formatAgentAuditParts,
} from '../../src/components/certops/certopsAgentLabel.js';

const linux = {
  id: 'feca50eb-babe-422d-b201-ccc345f4fb78',
  agentId: 'candidate-DESKTOP-J85DKKR-153006',
  name: 'DESKTOP-J85DKKR',
  hostname: 'DESKTOP-J85DKKR',
};
const win = {
  id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
  agentId: 'candidate-tt-trustvfy-5100',
  hostname: 'tt-trustvfy',
};

describe('certopsAgentLabel', () => {
  it('prefers name over hostname', () => {
    expect(
      agentDisplayName({ name: 'edge-01', hostname: 'ip-10-0-0-1' })
    ).toBe('edge-01');
    expect(agentDisplayName({ hostname: 'tt-trustvfy' })).toBe('tt-trustvfy');
    expect(agentDisplayName(null)).toBe('');
  });

  it('indexes both the row UUID and the public agentId', () => {
    const map = indexAgentsByAnyId([linux, win]);
    expect(map.get(linux.id)).toBe(linux);
    expect(map.get(linux.agentId)).toBe(linux);
    expect(map.get(win.agentId).hostname).toBe('tt-trustvfy');
  });

  it('formats name plus id, and falls back to the id alone', () => {
    const map = indexAgentsByAnyId([linux]);
    expect(formatAgentLabel(linux.id, map)).toBe(
      `DESKTOP-J85DKKR (${linux.id})`
    );
    expect(formatAgentLabel(linux.agentId, map)).toBe(
      `DESKTOP-J85DKKR (${linux.agentId})`
    );
    expect(formatAgentLabel('unknown-id', map)).toBe('unknown-id');
    expect(formatAgentLabel('', map)).toBe('');
  });

  it('uses metadata hostname when the fleet lookup misses', () => {
    expect(
      formatAgentLabel('abc', new Map(), { hostname: 'tt-trustvfy' })
    ).toBe('tt-trustvfy (abc)');
  });

  it('omits host when it is the same UUID as agentId', () => {
    const map = indexAgentsByAnyId([win]);
    expect(
      formatAgentAuditParts(
        { agentId: win.id, host: win.id, hostname: 'tt-trustvfy' },
        map
      )
    ).toEqual([`Agent: tt-trustvfy (${win.id})`]);
  });
});
