import { render, screen, within } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it } from 'vitest';
import NextStepsList, {
  describeNextStep,
} from '../../src/components/onboarding/nextStepsList.jsx';
import {
  DoneCard,
  nextSteps,
} from '../../src/components/onboarding/OnboardingPage.jsx';
import { allGoals } from '../../src/components/onboarding/editionModules.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const docs = (key, label) =>
  key === 'certops.dns' ? [{ label, url: 'https://docs.example/dns' }] : [];

const show = (items, extra = {}) =>
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter>
          <NextStepsList items={items} docs={docs} {...extra} />
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );

describe('NextStepsList', () => {
  it('lists the sentences with a title, the full sentence and an action', () => {
    const issued = nextSteps('certops_automate', {
      issueJob: { status: 'succeeded', mode: 'real' },
    });
    show(issued);
    const list = screen.getByRole('list');
    const rows = within(list).getAllByRole('listitem');
    expect(rows).toHaveLength(issued.length);
    expect(
      within(rows[0]).getByText('Switch to a real domain and the production CA')
    ).toBeVisible();
    // No information is lost: the whole sentence stays as the description.
    expect(within(rows[0]).getByText(issued[0])).toBeVisible();
    expect(
      within(rows[0]).getByRole('link', { name: 'DNS providers' })
    ).toHaveAttribute('href', 'https://docs.example/dns');
    expect(
      within(rows[1]).getByRole('link', { name: 'Open Certificates' })
    ).toHaveAttribute('href', '/certops/certificates');
    expect(
      within(rows[2]).getByRole('link', { name: 'Workspace preferences' })
    ).toHaveAttribute('href', '/workspace-preferences');
  });

  it('has a heading, the All optional tag and list semantics', () => {
    show(['Install agents on more servers.']);
    expect(
      screen.getByRole('heading', { name: /Suggested next steps/ })
    ).toBeVisible();
    expect(screen.getByText('All optional')).toBeVisible();
    expect(screen.getByRole('region', { name: /Suggested next steps/ })).toBe(
      screen
        .getByRole('heading', { name: /Suggested next steps/ })
        .closest('section')
    );
    expect(screen.getByRole('list')).toBeVisible();
  });

  it('falls back to the text alone for an unknown sentence', () => {
    show(['Do something an edition thought of.']);
    const row = screen.getByRole('listitem');
    expect(row).toHaveTextContent('Do something an edition thought of.');
    expect(within(row).queryByRole('link')).toBeNull();
    expect(within(row).queryByRole('button')).toBeNull();
  });

  it('derives a title from "Title. Detail." for an unknown sentence', () => {
    expect(
      describeNextStep('Review the roles. Admins can edit.')
    ).toMatchObject({
      title: 'Review the roles',
      description: 'Admins can edit.',
      action: null,
    });
  });

  it('hides a docs action whose page does not resolve', () => {
    show(['Run a verified rollout once your agents declare the capabilities.']);
    expect(screen.queryByRole('link')).toBeNull();
  });

  it('renders nothing for an empty list', () => {
    show([null, '']);
    expect(screen.queryByText('Suggested next steps')).toBeNull();
  });
});

describe('every goal closing card uses the styled list', () => {
  const ctxFor = (goal, smtp = true) => ({
    session: { intent: { goal }, progress: {} },
    summary: { alerts: { smtpConfigured: smtp } },
    docs,
    refresh: () => {},
    controller: { update: () => {} },
  });

  it.each(Object.keys(allGoals()))('%s', goal => {
    render(
      <ChakraProvider>
        <DashboardThemeProvider>
          <MemoryRouter>
            <DoneCard ctx={ctxFor(goal)} />
          </MemoryRouter>
        </DashboardThemeProvider>
      </ChakraProvider>
    );
    expect(screen.getByText('All optional')).toBeVisible();
    expect(screen.queryByText(/Suggested next steps, all optional/)).toBeNull();
    const rows = within(screen.getByTestId('next-steps')).getAllByRole(
      'listitem'
    );
    expect(rows.length).toBe(nextSteps(goal, undefined, null).length);
  });

  it('puts the SMTP warning first when email is not confirmed', () => {
    render(
      <ChakraProvider>
        <DashboardThemeProvider>
          <MemoryRouter>
            <DoneCard ctx={ctxFor('monitor_https', false)} />
          </MemoryRouter>
        </DashboardThemeProvider>
      </ChakraProvider>
    );
    const rows = within(screen.getByTestId('next-steps')).getAllByRole(
      'listitem'
    );
    expect(rows[0]).toHaveTextContent('Confirm email delivery');
  });
});
