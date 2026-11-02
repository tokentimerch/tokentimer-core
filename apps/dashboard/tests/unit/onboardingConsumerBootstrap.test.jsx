import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import ConsumerBootstrapToken from '../../src/components/onboarding/ConsumerBootstrapToken.jsx';
const create = vi.hoisted(() => vi.fn());
vi.mock('../../src/components/certops/certopsAgentsApi.js', () => ({
  createBootstrapToken: create,
}));
beforeEach(() => create.mockReset());
it('creates a separate one-time token for each consumer without persisting it in guide progress', async () => {
  create
    .mockResolvedValueOnce({ plaintextToken: 'ttboot_first' })
    .mockResolvedValueOnce({ plaintextToken: 'ttboot_second' });
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <ConsumerBootstrapToken workspaceId='workspace' />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
  expect(create).not.toHaveBeenCalled();
  fireEvent.click(
    screen.getByRole('button', { name: 'Create a consumer bootstrap token' })
  );
  await screen.findByText('ttboot_first');
  const [workspace, body] = create.mock.calls[0];
  expect(workspace).toBe('workspace');
  expect(Date.parse(body.expiresAt) - Date.now()).toBeGreaterThan(23 * 3600000);
  fireEvent.click(
    screen.getByRole('button', { name: 'Create another consumer token' })
  );
  await screen.findByText('ttboot_second');
  await waitFor(() => expect(screen.queryByText('ttboot_first')).toBeNull());
});

it('drops a previous workspace token even if its creation completes after switching workspaces', async () => {
  let resolveOld;
  create.mockImplementationOnce(
    () =>
      new Promise(resolve => {
        resolveOld = resolve;
      })
  );
  const viewFor = workspaceId => (
    <ChakraProvider>
      <DashboardThemeProvider>
        <ConsumerBootstrapToken workspaceId={workspaceId} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
  const view = render(viewFor('first-workspace'));
  fireEvent.click(
    screen.getByRole('button', { name: 'Create a consumer bootstrap token' })
  );
  view.rerender(viewFor('second-workspace'));
  await act(async () => {
    resolveOld({ plaintextToken: 'ttboot_old_workspace' });
  });
  expect(screen.queryByText('ttboot_old_workspace')).toBeNull();
  create.mockResolvedValueOnce({ plaintextToken: 'ttboot_second_workspace' });
  fireEvent.click(
    screen.getByRole('button', { name: 'Create a consumer bootstrap token' })
  );
  await screen.findByText('ttboot_second_workspace');
  expect(create).toHaveBeenLastCalledWith(
    'second-workspace',
    expect.any(Object)
  );
});
