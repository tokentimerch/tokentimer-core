import React from 'react';
import { logger } from '../utils/logger.js';
import { reportDashboardError } from '../utils/apiClient.js';
import { primitives } from '../styles/colors.js';
import {
  hasRecentChunkRecovery,
  isChunkLoadError,
  refreshAfterChunkFailure,
} from '../utils/chunkLoadRecovery.js';

const CHUNK_RECOVERY_ADVICE =
  'Check your connection. If refreshing does not help, try again later or contact your administrator.';

function ErrorReference({ reference }) {
  if (!reference) return null;
  return (
    <p role='status'>
      Reference: <code>{reference}</code>. Include it if you contact your
      administrator.
    </p>
  );
}

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      preloadError: null,
      lastReport: null,
    };
    this.errorReports = new WeakMap();
    this.handlePreloadError = this.handlePreloadError.bind(this);
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidMount() {
    window.addEventListener('vite:preloadError', this.handlePreloadError);
  }

  componentWillUnmount() {
    window.removeEventListener('vite:preloadError', this.handlePreloadError);
  }

  handlePreloadError(event) {
    if (!isChunkLoadError(event.payload)) return;
    // Keep optional imports and their callers in control of their own errors.
    this.setState({ preloadError: event.payload });
    this.reportError('chunk-load', event.payload);
  }

  componentDidCatch(error, errorInfo) {
    if (!import.meta.env.PROD) {
      logger.error('Error caught by boundary:', error, errorInfo);
      return;
    }
    this.reportError(isChunkLoadError(error) ? 'chunk-load' : 'render', error);
  }

  reportError(kind, error) {
    if (!import.meta.env.PROD) return;
    // A Vite event and React's lazy import rejection can share one error.
    const canDeduplicate = typeof error === 'object' && error !== null;
    let report = canDeduplicate ? this.errorReports.get(error) : null;
    if (!report) {
      report = reportDashboardError(kind);
      if (canDeduplicate) this.errorReports.set(error, report);
    }
    void report.then(reference => {
      if (!reference) return;
      this.setState(state => {
        const visibleError = state.hasError ? state.error : state.preloadError;
        if (visibleError !== error) return null;
        return { lastReport: { error, reference } };
      });
    });
  }

  render() {
    const { error, hasError, preloadError, lastReport } = this.state;
    const visibleError = hasError ? error : preloadError;
    const reference =
      lastReport && lastReport.error === visibleError
        ? lastReport.reference
        : null;
    if (hasError) {
      const chunkFailure = isChunkLoadError(error);
      const recentRecovery = chunkFailure && hasRecentChunkRecovery();
      const darkMode =
        typeof document !== 'undefined' &&
        (document.documentElement.dataset.theme === 'dark' ||
          document.body?.classList.contains('chakra-ui-dark'));
      return (
        <div
          style={{
            minHeight: '100vh',
            backgroundColor: darkMode
              ? primitives.slate[950]
              : primitives.slate[50],
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '1rem',
          }}
        >
          <div
            style={{
              maxWidth: '28rem',
              width: '100%',
              backgroundColor: darkMode ? primitives.slate[800] : '#ffffff',
              borderRadius: '0.75rem',
              boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
              padding: '2rem',
              textAlign: 'center',
            }}
          >
            <h2
              style={{
                fontSize: '1.5rem',
                fontWeight: 'bold',
                color: darkMode ? primitives.red[300] : primitives.red[600],
                marginBottom: '1rem',
              }}
            >
              {chunkFailure
                ? 'Page files could not be loaded'
                : 'Something went wrong'}
            </h2>
            <p
              style={{
                color: darkMode ? primitives.slate[200] : primitives.slate[600],
                marginBottom: '1.5rem',
              }}
            >
              {chunkFailure
                ? recentRecovery
                  ? CHUNK_RECOVERY_ADVICE
                  : 'The dashboard may have been updated, or your connection may have been interrupted. Refresh to load the current version. Unsaved changes will be lost.'
                : 'We encountered an unexpected error. Please try refreshing the page.'}
            </p>
            <ErrorReference reference={reference} />
            <button
              onClick={() =>
                chunkFailure
                  ? refreshAfterChunkFailure()
                  : window.location.reload()
              }
              style={{
                backgroundColor: primitives.blue[600],
                color: '#ffffff',
                padding: '0.5rem 1rem',
                borderRadius: '0.375rem',
                border: 'none',
                cursor: 'pointer',
                fontSize: '0.875rem',
                fontWeight: '500',
              }}
            >
              Refresh Page
            </button>
          </div>
        </div>
      );
    }

    return (
      <>
        {this.props.children}
        {preloadError && (
          <div
            role='alert'
            style={{
              position: 'fixed',
              bottom: '1rem',
              left: '1rem',
              right: '1rem',
              zIndex: 1500,
              border: `1px solid ${primitives.slate[300]}`,
              borderRadius: '0.5rem',
              padding: '1rem',
              backgroundColor: primitives.slate[50],
              color: primitives.slate[900],
            }}
          >
            <h2>Page files could not be loaded</h2>
            <p>
              {hasRecentChunkRecovery()
                ? CHUNK_RECOVERY_ADVICE
                : 'The dashboard may have been updated, or your connection may have been interrupted. Save your work before refreshing.'}{' '}
              Unsaved changes will be lost when you refresh.
            </p>
            <ErrorReference reference={reference} />
            <button onClick={refreshAfterChunkFailure}>Refresh Page</button>
          </div>
        )}
      </>
    );
  }
}

export default ErrorBoundary;
