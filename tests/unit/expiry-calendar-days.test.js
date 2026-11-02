const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');
const path = require('node:path');

for (const timezone of ['Africa/Cairo', 'America/St_Johns', 'Europe/Berlin']) {
  test(`expiry dates use calendar days in ${timezone}`, () => {
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', `
      import assert from 'node:assert/strict';
      import { getDaysUntilExpiration, formatExpirationDate, formatRelativeExpiration } from './utils/dateUtils.js';
      import { getExpiryStatus } from './styles/colors.js';
      const OriginalDate = Date;
      const now = new Date(2026, 9, 26, 12).getTime();
      globalThis.Date = class extends OriginalDate {
        constructor(...args) { super(...(args.length ? args : [now])); }
        static now() { return now; }
      };
      assert.equal(getDaysUntilExpiration('2026-11-02'), 7);
      assert.equal(getExpiryStatus('2026-11-02').label, '≤ 7 days');
      assert.equal(getDaysUntilExpiration('2026-10-26'), 0);
      assert.equal(getDaysUntilExpiration('2026-10-25'), -1);
      assert.equal(formatRelativeExpiration('2026-10-27'), 'Expires tomorrow');
      assert.equal(formatExpirationDate('2026-11-02'), 'November 2, 2026');
      assert.equal(getDaysUntilExpiration(new Date(2026, 10, 2, 23).toISOString()), 7);
      assert.equal(getDaysUntilExpiration('invalid'), null);
      assert.equal(getDaysUntilExpiration('2099-12-31'), null);
    `], { cwd: path.resolve(__dirname, '../../apps/dashboard/src'), env: { ...process.env, TZ: timezone }, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  });
}
