// Switch for the step-by-step import path of the setup guide.
//
// Parked until the import modal is reworked: the guided steps (importSteps.jsx,
// integrationStep.jsx, integrationModes.js) stay in the repo but are off. With
// the switch off, the two import goals open the regular import dialog, the same
// component the dashboard uses, configured by props.
//
// For local testing of the parked path, set
// VITE_ONBOARDING_GUIDED_IMPORT_STEPS=true. Code that needs both paths takes
// the flag as a parameter so tests can run either one.
export const GUIDED_IMPORT_STEPS =
  String(import.meta.env?.VITE_ONBOARDING_GUIDED_IMPORT_STEPS || '') === 'true';
