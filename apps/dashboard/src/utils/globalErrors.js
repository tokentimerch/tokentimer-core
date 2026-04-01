/**
 * Global error handlers
 * Captures unhandled errors and rejections
 */

import { logger } from './logger.js';

function installGlobalHandlers() {
  if (typeof window === 'undefined') return;

  // Unhandled errors
  window.addEventListener('error', event => {
    try {
      const error = event.error || new Error(event.message);
      logger.error('Unhandled error:', error);

      // Prevent default browser error handling
      event.preventDefault();
    } catch (_) {}
  });

  // Unhandled promise rejections
  window.addEventListener('unhandledrejection', event => {
    try {
      const error =
        event.reason instanceof Error
          ? event.reason
          : new Error(String(event.reason));
      logger.error('Unhandled rejection:', error);

      // Prevent default browser handling
      event.preventDefault();
    } catch (_) {}
  });
}

// Install handlers on module load
installGlobalHandlers();
