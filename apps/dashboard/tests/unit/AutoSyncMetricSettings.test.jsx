import React from 'react';
import { describe, it, expect, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import AutoSyncMetricSettings, {
  DEFAULT_METRIC_SETTINGS,
} from '../../src/components/imports/AutoSyncMetricSettings.jsx';
function Harness({ allowHighCardinality = true }) {
  const [settings, setSettings] = React.useState(DEFAULT_METRIC_SETTINGS);
  return (
    <ChakraProvider>
      <AutoSyncMetricSettings
        value={settings}
        allowHighCardinality={allowHighCardinality}
        onChange={setSettings}
      />
      <output data-testid='settings'>{JSON.stringify(settings)}</output>
    </ChakraProvider>
  );
}
afterEach(cleanup);
describe('auto-sync metric exposure controls', () => {
  it('keeps details private until explicitly enabled, with readable defaults and a stable ID', () => {
    render(<Harness />);
    expect(
      screen.getByRole('checkbox', {
        name: 'Expose additional auto-sync metrics',
      })
    ).not.toBeChecked();
    expect(
      screen.queryByRole('checkbox', { name: 'Token / asset name' })
    ).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole('checkbox', {
        name: 'Expose additional auto-sync metrics',
      })
    );
    for (const name of ['Configuration name', 'Monitoring group', 'Asset type'])
      expect(screen.getByRole('checkbox', { name, exact: true })).toBeChecked();
    expect(
      screen.getByText(/Configuration ID is always included/)
    ).toBeVisible();
    expect(
      screen.getByRole('checkbox', { name: 'Token / asset name' })
    ).not.toBeChecked();
  });
  it('lets users opt into names and project/group details with a series and metadata warning', () => {
    render(<Harness />);
    fireEvent.click(
      screen.getByRole('checkbox', {
        name: 'Expose additional auto-sync metrics',
      })
    );
    for (const name of [
      'Token / asset name',
      'Project / repository',
      'Source group',
    ])
      fireEvent.click(screen.getByRole('checkbox', { name, exact: true }));
    fireEvent.change(
      screen.getByRole('textbox', { name: 'Monitoring group label' }),
      { target: { value: 'critical' } }
    );
    expect(screen.getByRole('alert')).toHaveAttribute('data-status', 'warning');
    expect(screen.getByRole('alert')).toHaveTextContent(
      /Each different label combination creates a time series/
    );
    expect(
      screen.getByText(/metadata is visible to readers/)
    ).toHaveTextContent(/token secrets are never included/);
    const settings = JSON.parse(screen.getByTestId('settings').textContent);
    expect(settings.labels).toEqual(
      expect.arrayContaining(['asset_name', 'project', 'group'])
    );
    expect(settings.monitoring_group).toBe('critical');
    fireEvent.click(
      screen.getByRole('checkbox', {
        name: 'Expose additional auto-sync metrics',
      })
    );
    expect(JSON.parse(screen.getByTestId('settings').textContent).enabled).toBe(
      false
    );
    expect(
      screen.queryByRole('textbox', { name: 'Monitoring group label' })
    ).not.toBeInTheDocument();
  });
  it('disables token names and project/group labels when the deployment gate is off', () => {
    render(<Harness allowHighCardinality={false} />);
    fireEvent.click(
      screen.getByRole('checkbox', {
        name: 'Expose additional auto-sync metrics',
      })
    );
    for (const name of [
      'Token / asset name',
      'Project / repository',
      'Source group',
    ]) {
      expect(
        screen.getByRole('checkbox', { name, exact: true })
      ).toBeDisabled();
      expect(
        screen.getByRole('checkbox', { name, exact: true })
      ).not.toBeChecked();
    }
    expect(
      screen.getByRole('checkbox', { name: 'Asset type', exact: true })
    ).toBeEnabled();
    expect(screen.getByText(/disabled by deployment settings/)).toBeVisible();
  });
});
