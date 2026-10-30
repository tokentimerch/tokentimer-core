import { describe, it, expect, afterEach, vi } from 'vitest';
import {
  render,
  screen,
  fireEvent,
  cleanup,
  waitFor,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import AutoSyncMetricSettings from '../../src/components/imports/AutoSyncMetricSettings.jsx';
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
const defaults = {
  enabled: false,
  labels: low,
  override_metrics: false,
  override_monitoring_group: false,
  monitoring_group: '',
  locked: false,
  monitoring_group_locked: false,
  extra_labels: ['asset_name', 'project', 'group'],
  extra_labels_locked: false,
};
const local = { enabled: true, labels: ['kind'], monitoring_group: 'local' };
function view(policy = {}, value = local, onChange = vi.fn()) {
  return (
    <ChakraProvider>
      <AutoSyncMetricSettings
        value={value}
        systemPolicy={{ ...defaults, ...policy }}
        allowedExtraLabels={['project']}
        onChange={onChange}
      />
    </ChakraProvider>
  );
}
async function expand() {
  fireEvent.click(screen.getByRole('button', { name: /Auto-sync metrics/ }));
  await screen.findByRole('checkbox', {
    name: 'Expose additional auto-sync metrics',
  });
}
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
describe('connection metric settings', () => {
  it('starts collapsed and has no inheritance switch', async () => {
    render(view());
    expect(
      screen.getByRole('button', { name: /Auto-sync metrics/ })
    ).toHaveAttribute('aria-expanded', 'false');
    await expand();
    expect(
      screen.queryByRole('checkbox', { name: 'Use system settings' })
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole('checkbox', {
        name: 'Expose additional auto-sync metrics',
      })
    ).toBeEnabled();
    expect(
      screen.getByRole('textbox', { name: 'Monitoring group label' })
    ).toHaveValue('local');
  });
  it('forces metrics even for a locally disabled connection but leaves its group editable', async () => {
    render(
      view(
        { override_metrics: true, enabled: true, labels: low },
        { ...local, enabled: false }
      )
    );
    await expand();
    expect(
      screen.getByRole('checkbox', {
        name: 'Expose additional auto-sync metrics',
      })
    ).toBeChecked();
    expect(
      screen.getByRole('checkbox', {
        name: 'Expose additional auto-sync metrics',
      })
    ).toBeDisabled();
    expect(
      screen.getByRole('checkbox', { name: 'Configuration name' })
    ).toBeChecked();
    expect(screen.getByRole('checkbox', { name: 'Asset type' })).toBeDisabled();
    expect(
      screen.getByRole('textbox', { name: 'Monitoring group label' })
    ).toBeEnabled();
  });
  it('forces only the group and keeps the saved local group when editing metrics', async () => {
    const change = vi.fn();
    render(
      view(
        { override_monitoring_group: true, monitoring_group: 'critical' },
        local,
        change
      )
    );
    await expand();
    expect(
      screen.getByRole('textbox', { name: 'Monitoring group label' })
    ).toHaveValue('critical');
    expect(
      screen.getByRole('textbox', { name: 'Monitoring group label' })
    ).toBeDisabled();
    fireEvent.click(
      screen.getByRole('checkbox', {
        name: 'Expose additional auto-sync metrics',
      })
    );
    expect(change).toHaveBeenCalledWith({ ...local, enabled: false });
  });
  it('restores local controls and values when the independent overrides are released', async () => {
    const { rerender } = render(
      view({
        override_metrics: true,
        enabled: false,
        override_monitoring_group: true,
        monitoring_group: 'global',
      })
    );
    await expand();
    expect(
      screen.getByRole('checkbox', {
        name: 'Expose additional auto-sync metrics',
      })
    ).not.toBeChecked();
    rerender(view());
    expect(
      screen.getByRole('checkbox', {
        name: 'Expose additional auto-sync metrics',
      })
    ).toBeChecked();
    expect(
      screen.getByRole('checkbox', {
        name: 'Expose additional auto-sync metrics',
      })
    ).toBeEnabled();
    expect(
      screen.getByRole('textbox', { name: 'Monitoring group label' })
    ).toHaveValue('local');
  });
  it('still enforces deployment label restrictions', async () => {
    render(view());
    await expand();
    expect(
      screen.getByRole('checkbox', { name: 'Token / asset name' })
    ).toBeDisabled();
    expect(
      screen.getByRole('checkbox', { name: 'Project / repository' })
    ).toBeEnabled();
  });
});
describe('global overrides', () => {
  it('saves two independent overrides and reports configured only after persistence', async () => {
    const configured = vi.fn();
    apiClient.get.mockResolvedValue({ data: defaults });
    apiClient.put.mockImplementation((_url, body) =>
      Promise.resolve({ data: { ...defaults, ...body } })
    );
    render(
      <ChakraProvider>
        <AutoSyncSystemMetricSettings onConfiguredChange={configured} />
      </ChakraProvider>
    );
    await screen.findByRole('switch', {
      name: 'Override integration metrics',
    });
    expect(configured).toHaveBeenLastCalledWith(false);
    fireEvent.click(
      screen.getByRole('switch', { name: 'Override integration metrics' })
    );
    fireEvent.click(
      screen.getByRole('checkbox', {
        name: 'Enable additional auto-sync metrics',
      })
    );
    fireEvent.click(
      screen.getByRole('checkbox', { name: 'Project / repository' })
    );
    fireEvent.click(
      screen.getByRole('checkbox', { name: 'Override monitoring group' })
    );
    fireEvent.change(
      screen.getByRole('textbox', { name: 'Monitoring group label' }),
      { target: { value: 'critical' } }
    );
    expect(configured).toHaveBeenCalledTimes(1);
    fireEvent.click(
      screen.getByRole('button', { name: 'Save auto-sync settings' })
    );
    await screen.findByRole('status');
    expect(apiClient.put).toHaveBeenCalledWith(
      '/api/v1/admin/auto-sync/metrics',
      {
        override_metrics: true,
        enabled: true,
        labels: [...low, 'project'],
        override_monitoring_group: true,
        monitoring_group: 'critical',
      }
    );
    expect(configured).toHaveBeenLastCalledWith(true);
  });
  it('treats the group alone as configured and locks environment-controlled fields', async () => {
    apiClient.get.mockResolvedValue({
      data: {
        ...defaults,
        override_monitoring_group: true,
        monitoring_group: 'forced',
        monitoring_group_locked: true,
      },
    });
    const configured = vi.fn();
    render(
      <ChakraProvider>
        <AutoSyncSystemMetricSettings onConfiguredChange={configured} />
      </ChakraProvider>
    );
    expect(
      await screen.findByRole('checkbox', { name: 'Override monitoring group' })
    ).toBeDisabled();
    expect(
      screen.getByRole('textbox', { name: 'Monitoring group label' })
    ).toBeDisabled();
    expect(
      screen.getByRole('switch', { name: 'Override integration metrics' })
    ).toBeEnabled();
    expect(configured).toHaveBeenLastCalledWith(true);
  });
  it('preserves the configured state when saving fails', async () => {
    apiClient.get.mockResolvedValue({
      data: { ...defaults, override_metrics: true },
    });
    apiClient.put.mockRejectedValue(new Error('offline'));
    const configured = vi.fn();
    render(
      <ChakraProvider>
        <AutoSyncSystemMetricSettings onConfiguredChange={configured} />
      </ChakraProvider>
    );
    fireEvent.click(
      await screen.findByRole('switch', {
        name: 'Override integration metrics',
      })
    );
    fireEvent.click(
      screen.getByRole('button', { name: 'Save auto-sync settings' })
    );
    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent('Unable to save')
    );
    expect(configured).toHaveBeenLastCalledWith(true);
  });
});

it('explains the prominent override switch through its keyboard-accessible tooltip', async () => {
  apiClient.get.mockResolvedValue({ data: defaults });
  render(
    <ChakraProvider>
      <AutoSyncSystemMetricSettings />
    </ChakraProvider>
  );
  expect(
    await screen.findByRole('switch', { name: 'Override integration metrics' })
  ).toBeEnabled();
  fireEvent.focus(
    screen.getByRole('button', { name: 'About overriding integration metrics' })
  );
  expect(await screen.findByRole('tooltip')).toHaveTextContent(
    'locks their metric controls'
  );
  expect(screen.getByRole('tooltip')).toHaveTextContent(
    'restore each integration’s saved choices'
  );
});
