import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { STEP_DEFS } from '../../src/components/onboarding/modules.js';

// The steps list and the page header must read the same, so a person can
// match "Step 3" in the list to the page in front of them.
const HEADER_FILE = {
  goal: 'steps.jsx',
  monitor: 'monitorStep.jsx',
  asset: 'assetStep.jsx',
  file_import: 'importSteps.jsx',
  integration: 'integrationStep.jsx',
  recipients: 'alertRecipientsStep.jsx',
  notifications: 'notificationSteps.jsx',
  smtp: 'notificationSteps.jsx',
  verify: 'recipientAndVerifySteps.jsx',
  certops_objective: 'certopsSetupSteps.jsx',
  certops_config: 'certopsSetupSteps.jsx',
  certops_agent: 'certopsAgentStep.jsx',
  certops_execution: 'certopsExecutionStep.jsx',
  certops_first: 'certopsFinalSteps.jsx',
  certops_adcs: 'certopsAdcsStep.jsx',
  certops_vault: 'certopsFinalSteps.jsx',
};

const read = file =>
  readFileSync(
    resolve(__dirname, '../../src/components/onboarding', file),
    'utf8'
  );

describe('steps list titles match page headers', () => {
  it('covers every step definition', () => {
    expect(Object.keys(HEADER_FILE).sort()).toEqual(
      Object.keys(STEP_DEFS).sort()
    );
  });

  for (const [id, file] of Object.entries(HEADER_FILE)) {
    it(`${id} is headed "${STEP_DEFS[id].title}"`, () => {
      expect(read(file)).toContain(`title='${STEP_DEFS[id].title}'`);
    });
  }

  it('keeps the old jargon out of the list', () => {
    const titles = Object.values(STEP_DEFS).map(d => d.title);
    expect(titles.join('|')).not.toMatch(
      /objective|Enable execution|Import from an integration|Distribute through/
    );
  });
});
