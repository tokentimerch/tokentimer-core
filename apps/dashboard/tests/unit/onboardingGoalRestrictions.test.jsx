import { ChakraProvider } from '@chakra-ui/react';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { GoalStep } from '../../src/components/onboarding/steps.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const label = 'Issue certificates from my Microsoft CA (AD CS)';
const explanation = 'Restricted to workspace managers and owners.';

function show(state = 'role_handoff') {
  const update = vi.fn();
  render(
    <MemoryRouter>
      <ChakraProvider>
        <DashboardThemeProvider>
          <GoalStep
            ctx={{
              session: { intent: {}, progress: {} },
              capabilities: {
                items: [
                  {
                    id: 'certops.adcs',
                    state,
                    blockers:
                      state === 'role_handoff'
                        ? [{ code: 'ROLE_REQUIRED', remediation: explanation }]
                        : [],
                  },
                ],
              },
              docs: () => [],
              refresh: vi.fn(),
              controller: { update },
            }}
          />
        </DashboardThemeProvider>
      </ChakraProvider>
    </MemoryRouter>
  );
  return { update };
}

afterEach(cleanup);

describe('disabled setup goal explanations', () => {
  it('explains the role restriction on hover while keeping the goal disabled', async () => {
    const { update } = show();
    const goal = screen.getByRole('radio', { name: label });
    expect(goal).toBeDisabled();
    const restriction = screen.getByRole('group', {
      name: `Restriction for ${label}`,
    });
    fireEvent.pointerEnter(restriction, { pointerType: 'mouse' });
    expect(await screen.findByRole('tooltip')).toHaveTextContent(explanation);
    fireEvent.click(goal);
    expect(update).not.toHaveBeenCalled();
  });

  it('makes the same explanation available to keyboard users', async () => {
    show();
    const restriction = screen.getByRole('group', {
      name: `Restriction for ${label}`,
    });
    expect(restriction).toHaveAttribute('tabindex', '0');
    fireEvent.focus(restriction);
    expect(await screen.findByRole('tooltip')).toHaveTextContent(explanation);
  });

  it('keeps an authorized goal selectable without an extra restriction tab stop', () => {
    show('ready');
    expect(screen.getByRole('radio', { name: label })).toBeEnabled();
    expect(
      screen.queryByRole('group', { name: `Restriction for ${label}` })
    ).toBeNull();
  });
});
