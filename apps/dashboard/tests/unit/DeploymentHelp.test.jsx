import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { expect, it, vi } from 'vitest';
import DeploymentHelp, {
  deploymentFieldHelp,
} from '../../src/components/certops/DeploymentHelp.jsx';
const show = () =>
  render(
    <ChakraProvider>
      <DeploymentHelp
        label='Expected version'
        text={deploymentFieldHelp['Expected version']}
      />
    </ChakraProvider>
  );
it('opens help on keyboard focus with an accessible description and dismisses it on Escape', async () => {
  show();
  const button = screen.getByRole('button', { name: 'About Expected version' });
  fireEvent.focus(button);
  const help = await screen.findByRole('tooltip');
  expect(help).toHaveTextContent('expected and authorized to use');
  expect(button).toHaveAttribute('aria-describedby', help.id);
  expect(button).toHaveAttribute('aria-expanded', 'true');
  fireEvent.keyDown(button, { key: 'Escape' });
  await waitFor(() =>
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
  );
});
it('supports hover and closes when the trigger loses focus', async () => {
  show();
  const button = screen.getByRole('button', { name: 'About Expected version' });
  fireEvent.pointerEnter(button, { pointerType: 'mouse' });
  expect(await screen.findByRole('tooltip')).toHaveTextContent(
    'material store'
  );
  fireEvent.blur(button);
  await waitFor(() =>
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
  );
});
it('allows touch users to tap help open, keep reading after pointer leave, and tap to close', async () => {
  show();
  const button = screen.getByRole('button', { name: 'About Expected version' });
  fireEvent.pointerDown(button, { pointerType: 'touch' });
  fireEvent.click(button);
  await screen.findByRole('tooltip');
  fireEvent.pointerLeave(button, { pointerType: 'touch' });
  expect(screen.getByRole('tooltip')).toBeInTheDocument();
  fireEvent.click(button);
  await waitFor(() =>
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
  );
});
it('dismisses pinned help without propagating Escape to the surrounding modal', async () => {
  const onKeyDown = vi.fn();
  render(
    <ChakraProvider>
      <div onKeyDown={onKeyDown}>
        <DeploymentHelp label='Expected version' text='Help' />
      </div>
    </ChakraProvider>
  );
  const button = screen.getByRole('button');
  fireEvent.click(button);
  await screen.findByRole('tooltip');
  fireEvent.keyDown(button, { key: 'Escape' });
  expect(onKeyDown).not.toHaveBeenCalled();
  await waitFor(() =>
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
  );
});
