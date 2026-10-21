import { fireEvent, render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { describe, expect, it } from 'vitest';
import { CollapsibleSteps } from '../../src/components/onboarding/OnboardingPage.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const steps = [
  { id: 'a', title: 'Add the websites to monitor', status: 'done' },
  { id: 'b', title: 'Choose who gets alerted', status: 'current' },
  { id: 'c', title: 'Check that it is working', status: 'upcoming' },
];

const mount = (shownId = 'b') => {
  const closes = [];
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <CollapsibleSteps steps={steps} shownId={shownId}>
          {close => {
            closes.push(close);
            return (
              <ol aria-label='All steps'>
                {steps.map(s => (
                  <li key={s.id}>
                    <button type='button' onClick={close}>
                      {s.title}
                    </button>
                  </li>
                ))}
              </ol>
            );
          }}
        </CollapsibleSteps>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
};

const toggle = () => screen.getByRole('button', { name: /^Step \d of \d:/ });
const list = () =>
  document.getElementById(toggle().getAttribute('aria-controls'));

describe('narrow-screen steps summary', () => {
  it('names the active step and how far along it is', () => {
    mount('b');
    expect(toggle().textContent).toBe('Step 2 of 3: Choose who gets alerted');
  });

  it('follows the step being shown, not only the current one', () => {
    mount('a');
    expect(toggle().textContent).toBe(
      'Step 1 of 3: Add the websites to monitor'
    );
  });

  it('keeps the list folded until asked, then folds it again', () => {
    mount();
    expect(toggle().getAttribute('aria-expanded')).toBe('false');
    expect(getComputedStyle(list()).display).toBe('none');
    fireEvent.click(toggle());
    expect(toggle().getAttribute('aria-expanded')).toBe('true');
    expect(getComputedStyle(list()).display).toBe('block');
    fireEvent.click(screen.getByText('Check that it is working'));
    expect(toggle().getAttribute('aria-expanded')).toBe('false');
    expect(getComputedStyle(list()).display).toBe('none');
  });

  it('leaves the wide layout alone: the list shows from lg up', () => {
    mount();
    const css = [...document.querySelectorAll('style')]
      .map(
        s =>
          s.textContent +
          [...(s.sheet?.cssRules || [])].map(r => r.cssText).join('')
      )
      .join('');
    const cls = [...list().classList].find(c => c.startsWith('css-'));
    expect(cls).toBeTruthy();
    expect(css).toMatch(
      new RegExp(
        `@media[^{]*min-width[^{]*\\{\\s*\\.${cls}\\s*\\{[^}]*display:\\s*block`
      )
    );
  });
});
