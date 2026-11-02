import { describe, expect, it, vi, beforeEach } from 'vitest';
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import {
  Callout,
  DetailsSection,
  FactsList,
  StatusPanel,
  StatusTag,
  StepCard,
} from '../../src/components/onboarding/panels.jsx';
import { CopyBlock } from '../../src/components/onboarding/blocks.jsx';

const wrap = ui =>
  render(
    <ChakraProvider>
      <DashboardThemeProvider>{ui}</DashboardThemeProvider>
    </ChakraProvider>
  );

describe('StatusPanel', () => {
  it.each([
    ['info', 'status'],
    ['success', 'status'],
    ['warning', 'note'],
    ['error', 'alert'],
  ])('renders the %s variant with role %s', (status, role) => {
    wrap(
      <StatusPanel status={status} title='Heads up'>
        Body text
      </StatusPanel>
    );
    const panel = screen.getByRole(role);
    expect(within(panel).getByText('Heads up')).toBeVisible();
    expect(within(panel).getByText('Body text')).toBeVisible();
  });

  it('adds docs links and hides ones without a url', () => {
    wrap(
      <StatusPanel
        links={[
          { label: 'Guide', url: 'https://docs.example/guide' },
          { label: 'Dead', url: '' },
        ]}
      >
        See the guide
      </StatusPanel>
    );
    const link = screen.getByRole('link', { name: /Guide/ });
    expect(link).toHaveAttribute('href', 'https://docs.example/guide');
    expect(screen.queryByRole('link', { name: /Dead/ })).toBeNull();
  });

  it('works without a title', () => {
    wrap(<StatusPanel>Just text</StatusPanel>);
    expect(screen.getByText('Just text')).toBeVisible();
  });
});

describe('StatusTag', () => {
  it('shows its text', () => {
    wrap(<StatusTag tone='green'>Done</StatusTag>);
    expect(screen.getByText('Done')).toBeVisible();
  });
});

describe('StepCard', () => {
  it('names the section by number and title, with description and children', () => {
    wrap(
      <StepCard n={2} title='Create a token' description='Shown once'>
        <p>inside</p>
      </StepCard>
    );
    const card = screen.getByRole('region', { name: '2. Create a token' });
    expect(within(card).getByText('Shown once')).toBeVisible();
    expect(within(card).getByText('inside')).toBeVisible();
  });

  it('marks a done step and a step that needs attention', () => {
    wrap(
      <>
        <StepCard n={1} title='One' status='done' />
        <StepCard n={2} title='Two' status='blocked' />
      </>
    );
    expect(screen.getByText('Done')).toBeVisible();
    expect(screen.getByText('Needs attention')).toBeVisible();
  });

  it('shows who runs it', () => {
    wrap(<StepCard n={3} title='Install' who='root on the server' />);
    expect(screen.getByText('root on the server')).toBeVisible();
  });
});

describe('FactsList', () => {
  it('renders a definition list', () => {
    wrap(
      <FactsList
        items={[
          { label: 'Certificate', value: '/etc/ssl/a.pem', mono: true },
          { label: 'Port', value: 443 },
        ]}
      />
    );
    expect(screen.getByText('Certificate').tagName).toBe('DT');
    expect(screen.getByText('/etc/ssl/a.pem').tagName).toBe('DD');
    expect(screen.getByText('443')).toBeVisible();
  });

  it('skips rows without a value and renders nothing when empty', () => {
    const { container } = wrap(
      <FactsList items={[{ label: 'A', value: undefined }]} />
    );
    expect(container.querySelector('dl')).toBeNull();
  });
});

describe('Callout', () => {
  it.each([
    ['before', 'Before you start'],
    ['next', 'What happens next'],
    ['check', 'How to check'],
  ])('uses the %s heading', (kind, heading) => {
    wrap(<Callout kind={kind} items={['one']} />);
    expect(screen.getByRole('heading', { name: heading })).toBeVisible();
  });

  it('turns items into a list and accepts a custom title', () => {
    wrap(<Callout title='Needs' items={['a', 'b', null]} />);
    expect(screen.getAllByRole('listitem')).toHaveLength(2);
    expect(screen.getByRole('heading', { name: 'Needs' })).toBeVisible();
  });
});

describe('DetailsSection', () => {
  it('is collapsed by default and opens from the keyboard-friendly summary', () => {
    const { container } = wrap(
      <DetailsSection summary='More detail'>
        <p>hidden detail</p>
      </DetailsSection>
    );
    const details = container.querySelector('details');
    expect(details.open).toBe(false);
    expect(screen.getByText('More detail').tagName).toBe('SUMMARY');
  });

  it('can start open', () => {
    const { container } = wrap(
      <DetailsSection summary='Open' defaultOpen>
        <p>shown</p>
      </DetailsSection>
    );
    expect(container.querySelector('details').open).toBe(true);
  });
});

describe('CopyBlock as a command block', () => {
  beforeEach(() => {
    Object.assign(navigator, {
      clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
  });

  it('shows the command, copies it, and confirms', async () => {
    wrap(<CopyBlock label='Restart' text='sudo systemctl restart agent' />);
    expect(screen.getByText('sudo systemctl restart agent')).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Copy Restart' }));
    await waitFor(() =>
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
        'sudo systemctl restart agent'
      )
    );
  });

  it('can show a prompt prefix that is not copied', () => {
    wrap(<CopyBlock label='Run' text='ls -la' prompt />);
    fireEvent.click(screen.getByRole('button', { name: 'Copy Run' }));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('ls -la');
  });

  it('is a focusable group so a long command can be scrolled by keyboard', () => {
    wrap(<CopyBlock label='Run' text='ls' />);
    const group = screen.getByRole('group', { name: 'Run (command)' });
    expect(group).toHaveAttribute('tabindex', '0');
  });

  it('still refuses anything that looks like a credential', () => {
    wrap(<CopyBlock label='Token' text='ttboot_abc' />);
    expect(screen.getByTestId('copy-refused')).toBeVisible();
    expect(screen.queryByRole('button', { name: /Copy/ })).toBeNull();
  });
});
