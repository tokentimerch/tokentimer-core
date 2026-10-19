import { describe, expect, it } from 'vitest';
import {
  markChecked,
  shouldNudge,
  wasChecked,
} from '../../src/components/onboarding/nudgeRules.js';

const empty = { assets: { total: 0 }, monitors: { total: 0 } };
const fresh = { revision: 0, status: 'in_progress', intent: {} };

describe('shouldNudge', () => {
  it('invites the owner of a truly empty workspace', () => {
    expect(shouldNudge({ session: fresh, summary: empty })).toBe(true);
  });

  it('stays quiet for viewers', () => {
    expect(
      shouldNudge({ session: fresh, summary: empty, isViewer: true })
    ).toBe(false);
  });

  it('stays quiet once there is anything to watch', () => {
    expect(
      shouldNudge({
        session: fresh,
        summary: { assets: { total: 1 }, monitors: { total: 0 } },
      })
    ).toBe(false);
    expect(
      shouldNudge({
        session: fresh,
        summary: { assets: { total: 0 }, monitors: { total: 2 } },
      })
    ).toBe(false);
  });

  it('never reads an unknown count as empty', () => {
    expect(shouldNudge({ session: fresh, summary: {} })).toBe(false);
    expect(
      shouldNudge({
        session: fresh,
        summary: { assets: { total: undefined }, monitors: { total: 0 } },
      })
    ).toBe(false);
    expect(shouldNudge({ session: fresh, summary: null })).toBe(false);
    expect(shouldNudge({ session: null, summary: empty })).toBe(false);
  });

  it('respects "Not now" and a finished guide', () => {
    expect(
      shouldNudge({
        session: { ...fresh, status: 'dismissed' },
        summary: empty,
      })
    ).toBe(false);
    expect(
      shouldNudge({
        session: { ...fresh, status: 'completed' },
        summary: empty,
      })
    ).toBe(false);
  });

  it('does not nag someone who already chose a goal', () => {
    expect(
      shouldNudge({
        session: { ...fresh, intent: { goal: 'alerting' } },
        summary: empty,
      })
    ).toBe(false);
  });
});

describe('check memory', () => {
  const memory = () => {
    const data = new Map();
    return {
      getItem: k => (data.has(k) ? data.get(k) : null),
      setItem: (k, v) => data.set(k, v),
    };
  };

  it('remembers per workspace', () => {
    const s = memory();
    expect(wasChecked('a', s)).toBe(false);
    markChecked('a', s);
    expect(wasChecked('a', s)).toBe(true);
    expect(wasChecked('b', s)).toBe(false);
  });

  it('survives storage that throws', () => {
    const broken = {
      getItem: () => {
        throw new Error('denied');
      },
      setItem: () => {
        throw new Error('denied');
      },
    };
    expect(() => markChecked('a', broken)).not.toThrow();
    expect(wasChecked('a', broken)).toBe(false);
  });
});
