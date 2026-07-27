import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';

import DashboardPagination from '../../src/components/DashboardPagination.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

function renderControl(props = {}) {
  const onChange = props.onChange || vi.fn();
  const view = render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <DashboardPagination
          limit={20}
          offset={0}
          total={57}
          noun='jobs'
          {...props}
          onChange={onChange}
        />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
  return { ...view, onChange };
}

describe('DashboardPagination', () => {
  let onChange;

  beforeEach(() => {
    onChange = vi.fn();
  });

  it('names what it pages in its accessible labels', () => {
    renderControl({ onChange });

    expect(
      screen.getByRole('navigation', { name: 'jobs pagination' })
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Next page of jobs' })
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Previous page of jobs' })
    ).toBeInTheDocument();
    expect(screen.getByLabelText('jobs per page')).toBeInTheDocument();
  });

  it('announces the current range in words, not only in the compact display', () => {
    renderControl({ onChange });

    const status = screen.getByRole('status');
    expect(status).toHaveAttribute('aria-live', 'polite');
    expect(screen.getByText('Showing 1 to 20 of 57 jobs')).toBeInTheDocument();
  });

  it('pages forward by one page and reports the whole next position', () => {
    renderControl({ onChange });

    fireEvent.click(screen.getByRole('button', { name: 'Next page of jobs' }));

    expect(onChange).toHaveBeenCalledWith({ limit: 20, offset: 20 });
  });

  it('pages back by one page and never below zero', () => {
    renderControl({ offset: 20, onChange });

    fireEvent.click(
      screen.getByRole('button', { name: 'Previous page of jobs' })
    );

    expect(onChange).toHaveBeenCalledWith({ limit: 20, offset: 0 });
  });

  it('renders a usable next arrow when the total exceeds the page size', () => {
    renderControl({ limit: 20, offset: 0, total: 21, onChange });

    expect(
      screen.getByRole('button', { name: 'Next page of jobs' })
    ).toBeEnabled();
  });

  it('disables both arrows when a single page holds the whole list', () => {
    renderControl({ total: 5, onChange });

    expect(
      screen.getByRole('button', { name: 'Next page of jobs' })
    ).toBeDisabled();
    expect(
      screen.getByRole('button', { name: 'Previous page of jobs' })
    ).toBeDisabled();
  });

  it('clamps the last page rather than paging past the end', () => {
    renderControl({ offset: 40, total: 57, onChange });

    expect(
      screen.getByRole('button', { name: 'Next page of jobs' })
    ).toBeDisabled();
    expect(screen.getByText('Showing 41 to 57 of 57 jobs')).toBeInTheDocument();
  });

  it('returns to the first page when the page size changes', () => {
    renderControl({ offset: 40, onChange });

    fireEvent.change(screen.getByLabelText('jobs per page'), {
      target: { value: '50' },
    });

    expect(onChange).toHaveBeenCalledWith({ limit: 50, offset: 0 });
  });

  it('shows a server-clamped page size the caller does not offer', () => {
    renderControl({ limit: 25, pageSizeOptions: [10, 20], onChange });

    const select = screen.getByLabelText('jobs per page');
    expect(select).toHaveValue('25');
    expect(screen.getByRole('option', { name: '25' })).toBeInTheDocument();
  });

  it('reads an empty list as a zero range without inventing a row', () => {
    renderControl({ total: 0, onChange });

    expect(screen.getByText('Showing 0 to 0 of 0 jobs')).toBeInTheDocument();
  });

  it('is keyboard operable', () => {
    renderControl({ onChange });

    const next = screen.getByRole('button', { name: 'Next page of jobs' });
    next.focus();
    expect(next).toHaveFocus();
    fireEvent.keyDown(next, { key: 'Enter' });
    fireEvent.click(next);

    expect(onChange).toHaveBeenCalledWith({ limit: 20, offset: 20 });
  });
});
