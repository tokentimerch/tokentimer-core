import { describe, expect, it } from 'vitest';
import {
  createTokenEditData,
  createTokenUpdatePayload,
} from '../../src/components/tokenDetailForm.js';

describe('tokenDetailForm contact groups', () => {
  it('hydrates edit data from contact_group_ids when present', () => {
    expect(
      createTokenEditData({
        contact_group_ids: ['group-2', 'group-1'],
        contact_group_id: 'group-9',
      }).contact_group_ids
    ).toEqual(['group-1', 'group-2']);
  });

  it('hydrates from the singular id when the plural list is missing', () => {
    expect(
      createTokenEditData({ contact_group_id: 'group-2' }).contact_group_ids
    ).toEqual(['group-2']);
  });

  it('always sends contact_group_ids on save, including an empty list', () => {
    const cleared = createTokenUpdatePayload(
      {
        ...createTokenEditData({ contact_group_id: 'group-1' }),
        contact_group_ids: [],
      },
      { contact_group_id: 'group-1' }
    );
    expect(cleared.contact_group_ids).toEqual([]);
    expect(cleared.contact_group_id).toBe(null);

    const selected = createTokenUpdatePayload(
      {
        ...createTokenEditData({}),
        contact_group_ids: ['group-2', 'group-1'],
      },
      {}
    );
    expect(selected.contact_group_ids).toEqual(['group-1', 'group-2']);
    expect(selected.contact_group_id).toBe('group-1');
  });
});
