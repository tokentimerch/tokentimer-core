import { describe, it, expect } from 'vitest';
import { truncationSummary } from '../../src/components/certops/certopsPagination';

describe('truncationSummary', () => {
  it('returns null when there is no pagination metadata', () => {
    expect(
      truncationSummary({ shown: 20, pagination: null, noun: 'jobs' })
    ).toBeNull();
    expect(
      truncationSummary({ shown: 20, pagination: undefined, noun: 'jobs' })
    ).toBeNull();
  });

  it('returns null when nothing is shown', () => {
    expect(
      truncationSummary({
        shown: 0,
        pagination: { limit: 20, offset: 0, total: 57 },
        noun: 'jobs',
      })
    ).toBeNull();
  });

  it('renders "Showing X of Y" when total exceeds the shown count', () => {
    expect(
      truncationSummary({
        shown: 20,
        pagination: { limit: 20, offset: 0, total: 57 },
        noun: 'jobs',
      })
    ).toBe('Showing 20 of 57 jobs');
  });

  it('returns null when total equals or is below the shown count', () => {
    expect(
      truncationSummary({
        shown: 7,
        pagination: { limit: 20, offset: 0, total: 7 },
        noun: 'jobs',
      })
    ).toBeNull();
    expect(
      truncationSummary({
        shown: 7,
        pagination: { limit: 20, offset: 0, total: 5 },
        noun: 'jobs',
      })
    ).toBeNull();
  });

  it('renders "Showing first X" when hasMore is true without a total', () => {
    expect(
      truncationSummary({
        shown: 20,
        pagination: { limit: 20, offset: 0, hasMore: true },
        noun: 'jobs',
      })
    ).toBe('Showing first 20 jobs');
  });

  it('renders "Showing first X" when the page came back full and no total is known', () => {
    expect(
      truncationSummary({
        shown: 100,
        pagination: { limit: 100, offset: 0 },
        noun: 'log entries',
      })
    ).toBe('Showing first 100 log entries');
  });

  it('returns null for a partial page without total/hasMore', () => {
    expect(
      truncationSummary({
        shown: 12,
        pagination: { limit: 20, offset: 0 },
        noun: 'jobs',
      })
    ).toBeNull();
  });
});
