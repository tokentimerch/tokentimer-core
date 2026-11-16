import { describe, it, expect } from 'vitest';
import {
  findUnsafeRegexReason,
  sanitizeFilterRules,
} from '../../src/components/FilterRulesEditor.jsx';

describe('sanitizeFilterRules', () => {
  const rule = { action: 'include', field: 'name', matchType: 'regex' };
  it('drops blank rows but preserves invalid nonempty rules for rejection', () => {
    const invalid = ['[', '^(a+)+$'].map(value => ({ ...rule, value }));
    expect(sanitizeFilterRules([{ ...rule, value: '' }, ...invalid])).toEqual(
      invalid
    );
  });
  it('preserves malformed definitions instead of broadening the scan', () => {
    const invalid = [null, { ...rule, field: 'unknown', value: 'restricted' }];
    expect(sanitizeFilterRules(invalid)).toEqual(invalid);
  });
});

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
    expect(findUnsafeRegexReason('^(a+)+$')).toBe(
      'nested quantifiers detected'
    );
    expect(findUnsafeRegexReason('(a*)*')).toBe('nested quantifiers detected');
  });

  it('accepts ordinary alternation and common filters', () => {
    expect(findUnsafeRegexReason('(foo|bar)+')).toBeNull();
    expect(findUnsafeRegexReason('^iac-provisioned:.*')).toBeNull();
    expect(findUnsafeRegexReason('^[a-z0-9_-]+$')).toBeNull();
  });
});
