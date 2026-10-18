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
    this.state = { hasError: false, error: null };
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
    // Vite otherwise rethrows the preload error as an unhandled rejection.
    event.preventDefault();
    this.setState({ hasError: true, error: event.payload });
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

    return this.props.children;
  }
}

export default ErrorBoundary;
