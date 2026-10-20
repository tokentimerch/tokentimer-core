import { render, screen, within } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { describe, expect, it } from 'vitest';
import LearnMorePanel from '../../src/components/LearnMorePanel.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

function renderPanel(props) {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <LearnMorePanel {...props} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

const LINKS = [{ label: 'Real page', url: 'https://tokentimer.ch/docs/x#y' }];

describe('LearnMorePanel', () => {
  it.each(['default', 'compact'])(
    'renders a named note with the links inside (%s)',
    variant => {
      renderPanel({ links: LINKS, variant });
      const panel = screen.getByRole('note', { name: 'Learn more' });
      expect(within(panel).getByText('Learn more')).toBeInTheDocument();
      expect(
        within(panel).getByRole('link', { name: 'Real page' })
      ).toHaveAttribute('href', 'https://tokentimer.ch/docs/x#y');
    }
  );

  it('opens links in a new tab without leaking the opener', () => {
    renderPanel({ links: LINKS });
    const link = screen.getByRole('link', { name: 'Real page' });
    expect(link).toHaveAttribute('target', '_blank');
    expect(link.getAttribute('rel')).toMatch(/noopener/);
    expect(link.getAttribute('rel')).toMatch(/noreferrer/);
  });

  it('accepts href as well as url and uses a custom title as the name', () => {
    renderPanel({
      title: 'Setup guides',
      links: [{ label: 'Guide', href: 'https://tokentimer.ch/docs/g' }],
    });
    const panel = screen.getByRole('note', { name: 'Setup guides' });
    expect(within(panel).getByRole('link', { name: 'Guide' })).toHaveAttribute(
      'href',
      'https://tokentimer.ch/docs/g'
    );
  });

  it('drops unresolved links and repeated URLs', () => {
    renderPanel({
      links: [
        { label: 'First', url: 'https://tokentimer.ch/docs/a' },
        { label: 'Same page', url: 'https://tokentimer.ch/docs/a' },
        { label: 'Missing', url: null },
        null,
      ],
    });
    expect(screen.getAllByRole('link')).toHaveLength(1);
    expect(screen.getByRole('link', { name: 'First' })).toBeInTheDocument();
  });

  it.each([undefined, [], [{ label: 'Missing', url: '' }]])(
    'renders nothing without a resolvable link (%j)',
    links => {
      const { container } = renderPanel({ links });
      expect(container.querySelector('[role="note"]')).toBeNull();
      expect(screen.queryByText('Learn more')).toBeNull();
    }
  );
});
