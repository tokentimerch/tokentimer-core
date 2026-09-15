import { describe, it, expect } from 'vitest';
import {
  columnsByMode,
  inventoryMode,
} from '../../src/components/AssetInventoryTable.jsx';

const EXPECTED_COLUMNS = {
  mixed: [
    'name',
    'type',
    'location',
    'owner',
    'contact_group',
    'expiresAt',
    'status',
    'actions',
  ],
  cert: [
    'name',
    'type',
    'domains',
    'issuer',
    'contact_group',
    'expiresAt',
    'status',
    'actions',
  ],
  key_secret: [
    'name',
    'type',
    'location',
    'used_by',
    'contact_group',
    'privileges',
    'last_used',
    'expiresAt',
    'status',
    'actions',
  ],
  license: [
    'name',
    'type',
    'vendor',
    'license_type',
    'contact_group',
    'expiresAt',
    'status',
    'actions',
  ],
  general: [
    'name',
    'type',
    'location',
    'used_by',
    'contact_group',
    'expiresAt',
    'status',
    'actions',
  ],
};

describe('AssetInventoryTable column config', () => {
  describe('inventoryMode', () => {
    it.each([
      [[], 'mixed'],
      [['cert'], 'cert'],
      [['key_secret'], 'key_secret'],
      [['license'], 'license'],
      [['general'], 'general'],
      [['cert', 'license'], 'mixed'],
      [['cert', 'key_secret', 'general'], 'mixed'],
    ])('derives %j as %s', (selectedCategories, expected) => {
      expect(inventoryMode(selectedCategories)).toBe(expected);
    });

    it('treats non-array input as mixed', () => {
      expect(inventoryMode(undefined)).toBe('mixed');
      expect(inventoryMode(null)).toBe('mixed');
    });
  });

  describe('columnsByMode', () => {
    it('defines all inventory modes from the remediation plan', () => {
      expect(Object.keys(columnsByMode).sort()).toEqual(
        Object.keys(EXPECTED_COLUMNS).sort()
      );
    });

    it.each(Object.entries(EXPECTED_COLUMNS))(
      '%s columns match the remediation plan',
      (mode, expectedColumns) => {
        expect(columnsByMode[mode]).toEqual(expectedColumns);
      }
    );

    it('maps each inventoryMode result to a column set', () => {
      const cases = [
        [[], 'mixed'],
        [['cert'], 'cert'],
        [['key_secret'], 'key_secret'],
        [['license'], 'license'],
        [['general'], 'general'],
      ];

      for (const [selectedCategories, mode] of cases) {
        expect(columnsByMode[inventoryMode(selectedCategories)]).toEqual(
          EXPECTED_COLUMNS[mode]
        );
      }
    });
  });
});
