import { describe, expect, it } from 'vitest';
import {
  STEP_COMPONENTS,
  nextSteps,
} from '../../src/components/onboarding/OnboardingPage.jsx';
import { GOALS } from '../../src/components/onboarding/modules.js';
import { planJourney } from '../../src/components/onboarding/journeyPlanner.js';
import docLinks from '../../src/components/onboarding/docLinks.json';

// Every screen the planner can send a user to must exist, otherwise they see
// a blank page with no error.
describe('wizard wiring', () => {
  const stepIds = new Set(['goal']);
  for (const goal of Object.values(GOALS))
    goal.steps.forEach(s => stepIds.add(s));

  it('has a component for every step id any goal can reach', () => {
    const missing = [...stepIds].filter(
      id => typeof STEP_COMPONENTS[id] !== 'function'
    );
    expect(missing).toEqual([]);
  });

  it('has no component that no goal can reach', () => {
    const unused = Object.keys(STEP_COMPONENTS).filter(id => !stepIds.has(id));
    expect(unused).toEqual([]);
  });

  it('plans a reachable current step for every goal at every point', () => {
    for (const id of Object.keys(GOALS)) {
      const plan = planJourney({ intent: { goal: id } });
      expect(STEP_COMPONENTS[plan.currentStepId], id).toBeDefined();
    }
  });

  it('only uses documentation keys that exist in the registry', () => {
    // Steps reference keys as string literals in ctx.docs('<key>', ...).
    const fs = require('node:fs');
    const path = require('node:path');
    const dir = path.resolve(__dirname, '../../src/components/onboarding');
    const used = new Set();
    for (const file of fs.readdirSync(dir).filter(f => f.endsWith('.jsx'))) {
      const src = fs.readFileSync(path.join(dir, file), 'utf8');
      for (const m of src.matchAll(/docs\(\s*['"`]([A-Za-z0-9_.-]+)['"`]/g))
        used.add(m[1]);
    }
    const registered = new Set(Object.keys(docLinks));
    const unknown = [...used].filter(
      k => !registered.has(k) && !k.includes('${')
    );
    expect(unknown).toEqual([]);
  });
  it('every goal has a completion message and goal-specific follow-ups', () => {
    for (const [id, goal] of Object.entries(GOALS)) {
      expect(goal.doneText, id).toMatch(/\S/);
      expect(nextSteps(id).length, id).toBeGreaterThan(0);
    }
  });

  it('never suggests what the user just finished', () => {
    expect(nextSteps('import_file').join(' ')).not.toMatch(
      /Import many assets/
    );
    expect(nextSteps('import_integration').join(' ')).not.toMatch(
      /Import many assets/
    );
    expect(nextSteps('alerting').join(' ')).not.toMatch(/thresholds/);
  });

  it('does not overclaim for the candidate Vault goal', () => {
    expect(GOALS.certops_vault.doneText).toMatch(/not verified/i);
    expect(GOALS.certops_vault.doneText).not.toMatch(
      /distributed|working|complete/i
    );
  });
});
