import { describe, expect, it } from 'vitest';
import {
  canonicalAgentContactGroupFields,
  canonicalContactGroupFields,
  contactGroupFieldsForImportDefaults,
  formatContactGroupNames,
  hydrateContactGroupIds,
  joinContactGroupIdsForExport,
} from '../../src/utils/contactGroupAssignment.js';

describe('contactGroupAssignment', () => {
  it('prefers contact_group_ids even when empty', () => {
    expect(
      hydrateContactGroupIds({
        contact_group_ids: [],
        contact_group_id: 'group-1',
      })
    ).toEqual([]);
  });

  it('falls back to the singular token or agent id', () => {
    expect(hydrateContactGroupIds({ contact_group_id: 'group-2' })).toEqual([
      'group-2',
    ]);
    expect(hydrateContactGroupIds({ contactGroupId: 'g1' })).toEqual(['g1']);
  });

  it('sorts and canonicalizes both wire fields', () => {
    expect(canonicalContactGroupFields(['group-2', 'group-1'])).toEqual({
      contact_group_ids: ['group-1', 'group-2'],
      contact_group_id: 'group-1',
    });
    expect(canonicalContactGroupFields([])).toEqual({
      contact_group_ids: [],
      contact_group_id: null,
    });
    expect(canonicalAgentContactGroupFields(['g2', 'g1'])).toEqual({
      contactGroupIds: ['g1', 'g2'],
      contactGroupId: 'g1',
    });
    expect(contactGroupFieldsForImportDefaults(['group-2', 'group-1'])).toEqual(
      {
        contact_group_ids: ['group-1', 'group-2'],
        contact_group_id: 'group-1',
      }
    );
    expect(contactGroupFieldsForImportDefaults([])).toEqual({});
    expect(canonicalContactGroupFields(['\uFFFF', '\u{1F600}'])).toEqual({
      contact_group_ids: ['\uFFFF', '\u{1F600}'],
      contact_group_id: '\uFFFF',
    });
  });

  it('formats names and CSV export values', () => {
    const groups = [
      { id: 'group-1', name: 'Platform On-Call' },
      { id: 'group-2', name: 'Security On-Call' },
    ];
    expect(formatContactGroupNames(['group-1', 'group-2'], groups)).toBe(
      'Platform On-Call, Security On-Call'
    );
    expect(formatContactGroupNames([], groups)).toBe('Use workspace default');
    expect(
      joinContactGroupIdsForExport({
        contact_group_ids: ['group-2', 'group-1'],
      })
    ).toBe('group-1;group-2');
  });
});
