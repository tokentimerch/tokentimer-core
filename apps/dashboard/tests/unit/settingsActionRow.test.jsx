import { render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { describe, expect, it } from 'vitest';
import {
  SettingsActionList,
  SettingsActionRow,
} from '../../src/components/SettingsPageShell.jsx';
import SetupBanner from '../../src/components/onboarding/SetupBanner.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const wrap = ui =>
  render(
    <ChakraProvider>
      <DashboardThemeProvider>{ui}</DashboardThemeProvider>
    </ChakraProvider>
  );

describe('SettingsActionRow', () => {
  it('shows label, status, description, note and the control', () => {
    wrap(
      <SettingsActionList>
        <SettingsActionRow
          label='Job approval'
          status={<span>Always required</span>}
          description='Require approval before every new job can run.'
          note='Only admins can change this.'
        >
          <button type='button'>Change</button>
        </SettingsActionRow>
      </SettingsActionList>
    );
    expect(screen.getByText('Job approval')).toBeInTheDocument();
    expect(screen.getByText('Always required')).toBeInTheDocument();
    expect(
      screen.getByText('Require approval before every new job can run.')
    ).toBeInTheDocument();
    expect(
      screen.getByText('Only admins can change this.')
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Change' })).toBeInTheDocument();
  });

  it('works without a control, a status or a note', () => {
    wrap(<SettingsActionRow label='Plain' description='Only text.' />);
    expect(screen.getByText('Plain')).toBeInTheDocument();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it('draws a divider only when asked', () => {
    const { container, rerender } = wrap(
      <SettingsActionRow label='A' description='a' />
    );
    expect(container.querySelector('hr')).toBeNull();
    rerender(
      <ChakraProvider>
        <DashboardThemeProvider>
          <SettingsActionRow label='A' description='a' showDivider />
        </DashboardThemeProvider>
      </ChakraProvider>
    );
    expect(container.querySelector('hr')).not.toBeNull();
  });
});

describe('SetupBanner', () => {
  it('lets its actions wrap, so a long label cannot push Hide off the edge', () => {
    wrap(
      <SetupBanner
        title='Certificate management is not set up yet.'
        message='Nothing is reporting certificates here.'
        actionLabel='Start the CertOps quickstart'
        onAction={() => {}}
        onHide={() => {}}
      />
    );
    const hide = screen.getByRole('button', { name: 'Hide' });
    const group = hide.parentElement;
    expect(getComputedStyle(group).flexWrap).toBe('wrap');
  });
});
