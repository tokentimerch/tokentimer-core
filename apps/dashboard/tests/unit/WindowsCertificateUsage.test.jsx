import { ChakraProvider } from '@chakra-ui/react';
import { fireEvent, render, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import WindowsCertificateUsage from '../../src/components/certops/WindowsCertificateUsage.jsx';
const binding = {
  targetId: 'iis',
  site: 'Site',
  port: 443,
  relationship: 'observed',
  deployment: 'observed_only',
  canEnable: true,
  automaticUpdate: false,
};
const group = {
  periodId: 'period',
  managedCertificateId: 'store',
  host: 'server-01',
  store: 'LocalMachine\\My',
  profileName: 'AD CS · automatic',
  bindings: [binding],
};
const show = props =>
  render(
    <ChakraProvider>
      <WindowsCertificateUsage groups={[group]} canManage {...props} />
    </ChakraProvider>
  );
it('offers one Store renewal configuration and an explicit default-off IIS update control', () => {
  const onSelect = vi.fn(),
    onToggle = vi.fn();
  show({ onSelect, onToggle });
  expect(screen.getByText('server-01 › LocalMachine\\My')).toBeInTheDocument();
  expect(
    screen.queryByRole('button', { name: /IIS renewal/ })
  ).not.toBeInTheDocument();
  const checkbox = screen.getByRole('checkbox');
  expect(checkbox).not.toBeChecked();
  fireEvent.click(checkbox);
  expect(onToggle).toHaveBeenCalledWith(group, binding, true);
  fireEvent.click(screen.getByRole('button', { name: 'Renewal settings' }));
  expect(onSelect).toHaveBeenCalledWith('store');
});
it('keeps opt-out available while an agent is unavailable and explains qualification', () => {
  const ready = {
    ...group,
    readinessReason: 'A qualified agent is required.',
    bindings: [{ ...binding, automaticUpdate: true, canEnable: false }],
  };
  show({ groups: [ready] });
  expect(screen.getByRole('checkbox')).not.toBeDisabled();
  expect(
    screen.getByText('A qualified agent is required.')
  ).toBeInTheDocument();
});
it('locks opt-in for a conflicting profile and never offers an independent renewal selector', () => {
  show({
    groups: [
      {
        ...group,
        bindings: [{ ...binding, deployment: 'conflict', canEnable: false }],
      },
    ],
  });
  expect(screen.getByRole('checkbox')).toBeDisabled();
  expect(screen.getByText(/Existing IIS renewal profile/)).toBeInTheDocument();
  expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
});
it('keeps separate Store owners per agent even for the same wildcard certificate', () => {
  show({
    certificateName: '*.example.test',
    groups: [
      group,
      {
        ...group,
        periodId: 'other',
        managedCertificateId: 'other-store',
        host: 'server-02',
      },
    ],
  });
  expect(
    screen.getAllByRole('button', { name: 'Renewal settings' })
  ).toHaveLength(2);
  expect(screen.getByText('server-02 › LocalMachine\\My')).toBeInTheDocument();
});
