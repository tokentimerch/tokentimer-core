import React, { lazy, Suspense } from 'react';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import ErrorBoundary from '../../src/components/ErrorBoundary.jsx';
import {
  hasRecentChunkRecovery,
  isChunkLoadError,
  refreshAfterChunkFailure,
} from '../../src/utils/chunkLoadRecovery.js';

vi.mock('../../src/utils/logger.js', () => ({ logger: { error: vi.fn() } }));

const chunkError = () =>
  new TypeError(
    'Failed to fetch dynamically imported module: /assets/Account-old.js'
  );

describe('chunk load recovery', () => {
  let reload;
  const handleExpectedError = event => {
    if (
      isChunkLoadError(event.error) ||
      event.error?.message === 'Application error'
    ) {
      event.preventDefault();
    }
  };

  beforeEach(() => {
    window.sessionStorage.clear();
    reload = vi.fn();
    vi.stubGlobal(
      'window',
      Object.create(window, {
        location: { value: { reload } },
      })
    );
    vi.spyOn(console, 'error').mockImplementation(() => {});
    window.addEventListener('error', handleExpectedError);
  });

  afterEach(() => {
    cleanup();
    window.removeEventListener('error', handleExpectedError);
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it.each([
    'Failed to fetch dynamically imported module: /assets/page.js',
    'error loading dynamically imported module: /assets/page.js',
    'Importing a module script failed.',
    'Unable to preload CSS for /assets/page.css',
  ])('recognizes loader failure: %s', message => {
    expect(isChunkLoadError(new TypeError(message))).toBe(true);
  });

  it.each([
    undefined,
    null,
    'Failed to fetch',
    new Error('Failed to fetch'),
    new Error('Application error'),
    new Error('Invalid module data'),
  ])('does not classify unrelated errors: %s', error => {
    expect(isChunkLoadError(error)).toBe(false);
  });

  it('offers explicit recovery for a rejected React lazy import', async () => {
    const Page = lazy(() => Promise.reject(chunkError()));
    render(
      <ErrorBoundary>
        <Suspense fallback='Loading'>
          <Page />
        </Suspense>
      </ErrorBoundary>
    );
    expect(
      await screen.findByText('Page files could not be loaded')
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Unsaved changes will be lost/)
    ).toBeInTheDocument();
    expect(reload).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Refresh Page' }));
    expect(reload).toHaveBeenCalledTimes(1);
    expect(hasRecentChunkRecovery()).toBe(true);
  });

  it('handles Vite preload failures without an unhandled rejection', () => {
    render(
      <ErrorBoundary>
        <p>Dashboard</p>
      </ErrorBoundary>
    );
    const event = new Event('vite:preloadError', { cancelable: true });
    event.payload = new Error('Unable to preload CSS for /assets/page.css');
    fireEvent(window, event);
    expect(event.defaultPrevented).toBe(true);
    expect(
      screen.getByText('Page files could not be loaded')
    ).toBeInTheDocument();
    expect(reload).not.toHaveBeenCalled();
  });

  it('leaves unrelated Vite errors to the existing error handling', () => {
    render(
      <ErrorBoundary>
        <p>Dashboard</p>
      </ErrorBoundary>
    );
    const event = new Event('vite:preloadError', { cancelable: true });
    event.payload = new Error('Application error');
    fireEvent(window, event);
    expect(event.defaultPrevented).toBe(false);
    expect(screen.getByText('Dashboard')).toBeInTheDocument();
  });

  it('keeps the recovery message when Vite suppresses a rejected lazy import', async () => {
    const Page = lazy(() =>
      Promise.reject(chunkError()).catch(error => {
        const event = new Event('vite:preloadError', { cancelable: true });
        event.payload = error;
        window.dispatchEvent(event);
        if (!event.defaultPrevented) throw error;
      })
    );
    render(
      <ErrorBoundary>
        <Suspense fallback='Loading'>
          <Page />
        </Suspense>
      </ErrorBoundary>
    );
    expect(
      await screen.findByText('Page files could not be loaded')
    ).toBeInTheDocument();
    expect(reload).not.toHaveBeenCalled();
  });

  it('retains the normal boundary message for application errors', () => {
    function BrokenPage() {
      throw new Error('Application error');
    }
    render(
      <ErrorBoundary>
        <BrokenPage />
      </ErrorBoundary>
    );
    expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    expect(
      screen.queryByText('Page files could not be loaded')
    ).not.toBeInTheDocument();
  });

  it('remembers a failed recovery across boundary mounts without reloading again', () => {
    refreshAfterChunkFailure();
    const first = render(
      <ErrorBoundary>
        <p>Dashboard</p>
      </ErrorBoundary>
    );
    first.unmount();
    function BrokenPage() {
      throw chunkError();
    }
    render(
      <ErrorBoundary>
        <BrokenPage />
      </ErrorBoundary>
    );
    expect(
      screen.getByText(/Refreshing did not resolve the problem/)
    ).toBeInTheDocument();
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('renders a current page after the user refreshes', async () => {
    const OldPage = lazy(() => Promise.reject(chunkError()));
    const view = render(
      <ErrorBoundary>
        <Suspense fallback='Loading'>
          <OldPage />
        </Suspense>
      </ErrorBoundary>
    );
    await screen.findByText('Page files could not be loaded');
    fireEvent.click(screen.getByRole('button', { name: 'Refresh Page' }));
    view.unmount();
    const CurrentPage = lazy(() =>
      Promise.resolve({ default: () => <p>Current page</p> })
    );
    render(
      <ErrorBoundary>
        <Suspense fallback='Loading'>
          <CurrentPage />
        </Suspense>
      </ErrorBoundary>
    );
    expect(await screen.findByText('Current page')).toBeInTheDocument();
    expect(
      screen.queryByText('Page files could not be loaded')
    ).not.toBeInTheDocument();
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('expires the recovery marker after one minute', () => {
    vi.useFakeTimers();
    refreshAfterChunkFailure();
    vi.advanceTimersByTime(60_000);
    expect(hasRecentChunkRecovery()).toBe(false);
  });

  it('can refresh explicitly when session storage is blocked', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('Blocked');
    });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('Blocked');
    });
    expect(hasRecentChunkRecovery()).toBe(false);
    refreshAfterChunkFailure();
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('removes the Vite listener when the boundary unmounts', () => {
    const view = render(
      <ErrorBoundary>
        <p>Dashboard</p>
      </ErrorBoundary>
    );
    view.unmount();
    const event = new Event('vite:preloadError', { cancelable: true });
    event.payload = chunkError();
    fireEvent(window, event);
    expect(event.defaultPrevented).toBe(false);
  });
});
