import { describe, expect, it } from 'vitest';
import { planJourney } from '../../src/components/onboarding/journeyPlanner.js';
import { importStepComponents } from '../../src/components/onboarding/OnboardingPage.jsx';

const FIRST_STEP = {
  import_file: 'file_import',
  import_integration: 'integration',
};

// The journey is the same with the guided steps off or on: goal, import,
// recipients, verify. Only the component behind the import step differs.
describe.each([false, true])('import journeys (guided steps: %s)', guided => {
  const components = importStepComponents(guided);

  for (const [goal, importStep] of Object.entries(FIRST_STEP)) {
    it(`${goal}: goal -> ${importStep} -> recipients -> verify`, () => {
      const plan = planJourney({ intent: { goal }, reality: null });
      expect(plan.steps.map(s => s.id)).toEqual([
        'goal',
        importStep,
        'recipients',
        'verify',
      ]);
      expect(plan.currentStepId).toBe(importStep);
      expect(typeof components[importStep]).toBe('function');
    });

    it(`${goal}: moves on once an import is recorded and the assets exist`, () => {
      const plan = planJourney({
        intent: { goal },
        progress: { imported: [{ step: importStep, count: 3 }] },
        reality: { assets: { total: 3 } },
      });
      expect(plan.steps.find(s => s.id === importStep).status).toBe('done');
      expect(plan.currentStepId).toBe('recipients');
    });

    it(`${goal}: reopens when the imported assets are gone`, () => {
      const plan = planJourney({
        intent: { goal },
        progress: { imported: [{ step: importStep, count: 3 }] },
        reality: { assets: { total: 1 } },
      });
      expect(plan.currentStepId).toBe(importStep);
    });
  }
});

describe('import step components', () => {
  it('differ between the two paths', () => {
    const off = importStepComponents(false);
    const on = importStepComponents(true);
    expect(off.file_import).not.toBe(on.file_import);
    expect(off.integration).not.toBe(on.integration);
  });
});
