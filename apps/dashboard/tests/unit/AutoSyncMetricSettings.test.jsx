import React from 'react';
import { describe, it, expect, afterEach, vi } from 'vitest';
import {
  render,
  screen,
  fireEvent,
  cleanup,
  waitFor,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import AutoSyncMetricSettings, {
  DEFAULT_METRIC_SETTINGS,
} from '../../src/components/imports/AutoSyncMetricSettings.jsx';
import AutoSyncSystemMetricSettings from '../../src/components/AutoSyncSystemMetricSettings.jsx';
import apiClient from '../../src/utils/apiClient';
vi.mock('../../src/utils/apiClient', () => ({
  default: { get: vi.fn(), put: vi.fn() },
}));
vi.mock('../../src/components/DashboardPrimitives', () => ({
  DashboardActionButton: ({ children, onClick, isLoading }) => (
    <button onClick={onClick} disabled={isLoading}>
      {children}
    </button>
  ),
}));
const low = ['configuration_name', 'monitoring_group', 'kind'];
function Harness({
  policy = { enabled: true, labels: low },
  allowed = ['asset_name', 'project', 'group'],
}) {
  const [value, setValue] = React.useState(DEFAULT_METRIC_SETTINGS);
  return (
    <ChakraProvider>
      <AutoSyncMetricSettings
        value={value}
        onChange={setValue}
        systemPolicy={policy}
        allowedExtraLabels={allowed}
      />
      <output data-testid='value'>{JSON.stringify(value)}</output>
    </ChakraProvider>
  );
}
const expand = async () => {
  fireEvent.click(
    screen.getByRole('button', { name: 'Auto-sync metrics', exact: true })
  );
  await screen.findByRole('checkbox', { name: 'Use system settings' });
};
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});
describe('collapsed per-connection metric settings', () => {
  it('starts collapsed and inherits enabled system labels without another per-connection opt-in', async () => {
    render(<Harness />);
    expect(
      screen.getByRole('button', { name: 'Auto-sync metrics' })
    ).toHaveAttribute('aria-expanded', 'false');
    expect(
      screen.queryByRole('checkbox', { name: 'Use system settings' })
    ).not.toBeInTheDocument();
    await expand();
    expect(
      screen.getByRole('checkbox', { name: 'Use system settings' })
    ).toBeChecked();
    expect(
      screen.getByRole('checkbox', {
        name: 'Expose additional auto-sync metrics',
      })
    ).toBeChecked();
    expect(
      screen.getByRole('checkbox', { name: 'Asset type', exact: true })
    ).toBeDisabled();
    fireEvent.change(
      screen.getByRole('textbox', { name: 'Monitoring group label' }),
      { target: { value: 'critical' } }
    );
    expect(JSON.parse(screen.getByTestId('value').textContent)).toMatchObject({
      inherit_system: true,
      monitoring_group: 'critical',
    });
  });
  it('can use fewer labels or opt out locally while system defaults remain enabled', async () => {
    render(<Harness />);
    await expand();
    fireEvent.click(
      screen.getByRole('checkbox', { name: 'Use system settings' })
    );
    fireEvent.click(
      screen.getByRole('checkbox', { name: 'Asset type', exact: true })
    );
    expect(JSON.parse(screen.getByTestId('value').textContent)).toMatchObject({
      inherit_system: false,
      enabled: true,
      labels: ['configuration_name', 'monitoring_group'],
    });
    fireEvent.click(
      screen.getByRole('checkbox', {
        name: 'Expose additional auto-sync metrics',
      })
    );
    expect(JSON.parse(screen.getByTestId('value').textContent).enabled).toBe(
      false
    );
  });
  it('cannot bypass a global disable', async () => {
    render(<Harness policy={{ enabled: false, labels: low }} />);
    await expand();
    fireEvent.click(
      screen.getByRole('checkbox', { name: 'Use system settings' })
    );
    expect(
      screen.getByRole('checkbox', {
        name: 'Expose additional auto-sync metrics',
      })
    ).toBeDisabled();
    expect(
      screen.getByText('Additional metrics are disabled in System Settings.')
    ).toBeVisible();
  });
  it('cannot enable globally disabled or deployment-blocked labels', async () => {
    render(
      <Harness
        policy={{ enabled: true, labels: [...low, 'project', 'asset_name'] }}
        allowed={['project']}
      />
    );
    await expand();
    fireEvent.click(
      screen.getByRole('checkbox', { name: 'Use system settings' })
    );
    expect(
      screen.getByRole('checkbox', { name: 'Project / repository' })
    ).toBeEnabled();
    expect(
      screen.getByRole('checkbox', { name: 'Token / asset name' })
    ).toBeDisabled();
    expect(
      screen.getByRole('checkbox', { name: 'Source group' })
    ).toBeDisabled();
    expect(screen.getByRole('alert')).toHaveAttribute('data-status', 'warning');
  });
});
describe('system metric controls', () => {
  it('saves a global switch and selected labels with deployment restrictions', async () => {
    const policy = {
      enabled: false,
      labels: low,
      extra_labels: ['project'],
      locked: false,
    };
    apiClient.get.mockResolvedValue({ data: policy });
    apiClient.put.mockImplementation((_url, body) =>
      Promise.resolve({ data: { ...policy, ...body } })
    );
    render(
      <ChakraProvider>
        <AutoSyncSystemMetricSettings />
      </ChakraProvider>
    );
    fireEvent.click(
      await screen.findByRole('checkbox', {
        name: 'Enable additional auto-sync metrics',
      })
    );
    expect(
      screen.getByRole('checkbox', { name: 'Token / asset name' })
    ).toBeDisabled();
    fireEvent.click(
      screen.getByRole('checkbox', { name: 'Project / repository' })
    );
    fireEvent.click(
      screen.getByRole('button', { name: 'Save auto-sync metrics' })
    );
    await waitFor(() =>
      expect(apiClient.put).toHaveBeenCalledWith(
        '/api/v1/admin/auto-sync/metrics',
        { enabled: true, labels: [...low, 'project'] }
      )
    );
    expect(await screen.findByRole('status')).toHaveTextContent('saved');
  });
  it('shows and locks an environment override', async () => {
    apiClient.get.mockResolvedValue({
      data: {
        enabled: false,
        labels: low,
        extra_labels: [],
        locked: true,
        source: 'env',
      },
    });
    render(
      <ChakraProvider>
        <AutoSyncSystemMetricSettings />
      </ChakraProvider>
    );
    expect(
      await screen.findByRole('checkbox', {
        name: 'Enable additional auto-sync metrics',
      })
    ).toBeDisabled();
    expect(screen.getByText('Set by environment')).toBeVisible();
  });
  it('locks deployment label selections but permits lower-cardinality choices', async () => {
    apiClient.get.mockResolvedValue({
      data: {
        enabled: true,
        labels: [...low, 'project'],
        extra_labels: ['project'],
        extra_labels_locked: true,
        locked: false,
      },
    });
    render(
      <ChakraProvider>
        <AutoSyncSystemMetricSettings />
      </ChakraProvider>
    );
    expect(
      await screen.findByRole('checkbox', { name: 'Project / repository' })
    ).toBeDisabled();
    expect(
      screen.getByRole('checkbox', { name: 'Project / repository' })
    ).toBeChecked();
    expect(screen.getByRole('checkbox', { name: 'Asset type' })).toBeEnabled();
    expect(screen.getByText('Labels set by environment')).toBeVisible();
  });
});
