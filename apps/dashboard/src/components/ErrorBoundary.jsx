import React from 'react';
import { logger } from '../utils/logger.js';
import { primitives } from '../styles/colors.js';
import {
  hasRecentChunkRecovery,
  isChunkLoadError,
  refreshAfterChunkFailure,
} from '../utils/chunkLoadRecovery.js';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, preloadError: null };
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
  }

  componentDidCatch(error, errorInfo) {
    logger.error('Error caught by boundary:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      const chunkFailure = isChunkLoadError(this.state.error);
      const recoveryFailed = chunkFailure && hasRecentChunkRecovery();
      return (
        <div
          style={{
            minHeight: '100vh',
            backgroundColor: primitives.slate[50],
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
              backgroundColor: '#ffffff',
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
                color: primitives.red[600],
                marginBottom: '1rem',
              }}
            >
              {chunkFailure
                ? 'Page files could not be loaded'
                : 'Something went wrong'}
            </h2>
            <p
              style={{
                color: primitives.slate[600],
                marginBottom: '1.5rem',
              }}
            >
              {chunkFailure
                ? recoveryFailed
                  ? 'Refreshing did not resolve the problem. Check your connection and try again later. If it persists, contact your administrator.'
                  : 'The dashboard may have been updated, or your connection may have been interrupted. Refresh to load the current version. Unsaved changes will be lost.'
                : 'We encountered an unexpected error. Please try refreshing the page.'}
            </p>
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
        {this.state.preloadError && (
          <div
            role='alert'
            style={{
              position: 'fixed',
              bottom: '1rem',
              left: '1rem',
              right: '1rem',
              zIndex: 1500,
              border: '1px solid ' + primitives.slate[300],
              borderRadius: '0.5rem',
              padding: '1rem',
              backgroundColor: primitives.slate[50],
              color: primitives.slate[900],
            }}
          >
            <h2>Page files could not be loaded</h2>
            <p>
              {hasRecentChunkRecovery()
                ? 'Refreshing did not resolve the problem. Check your connection and try again later. If it persists, contact your administrator.'
                : 'The dashboard may have been updated, or your connection may have been interrupted. Save your work before refreshing.'}{' '}
              Unsaved changes will be lost when you refresh.
            </p>
            <button onClick={refreshAfterChunkFailure}>Refresh Page</button>
          </div>
        )}
      </>
    );
  }
}

export default ErrorBoundary;
