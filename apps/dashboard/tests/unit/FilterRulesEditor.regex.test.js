import { describe, it, expect } from 'vitest';
import { findUnsafeRegexReason } from '../../src/components/FilterRulesEditor.jsx';

describe('findUnsafeRegexReason', () => {
  it('rejects overlapping quantified alternatives', () => {
    expect(findUnsafeRegexReason('^(a|aa)+$')).toBe(
      'overlapping alternatives detected'
    );
    expect(findUnsafeRegexReason('(a|aa)+')).toBe(
      'overlapping alternatives detected'
    );
    expect(findUnsafeRegexReason('(?:a|aa)+')).toBe(
      'overlapping alternatives detected'
    );
  });

  it('rejects nested quantifiers', () => {
    expect(findUnsafeRegexReason('^(a+)+$')).toBe('nested quantifiers detected');
    expect(findUnsafeRegexReason('(a*)*')).toBe('nested quantifiers detected');
  });

  it('accepts ordinary alternation and common filters', () => {
    expect(findUnsafeRegexReason('(foo|bar)+')).toBeNull();
    expect(findUnsafeRegexReason('^iac-provisioned:.*')).toBeNull();
    expect(findUnsafeRegexReason('^[a-z0-9_-]+$')).toBeNull();
  });
});
