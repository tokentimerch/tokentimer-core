// Browser-compatible logger that works across all environments
// Environment detection
const isDev =
  (typeof import.meta !== 'undefined' &&
    import.meta.env &&
    (import.meta.env.DEV ||
      import.meta.env.MODE === 'development' ||
      import.meta.env.MODE === 'test' ||
      import.meta.env.MODE === 'staging' ||
      import.meta.env.VITE_ENVIRONMENT === 'development' ||
      import.meta.env.VITE_ENVIRONMENT === 'test' ||
      import.meta.env.VITE_ENVIRONMENT === 'staging' ||
      import.meta.env.NODE_ENV === 'development' ||
      import.meta.env.NODE_ENV === 'test' ||
      import.meta.env.NODE_ENV === 'staging')) ||
  (typeof window !== 'undefined' &&
    (window.location.hostname.includes('localhost') ||
      window.location.hostname.includes('127.0.0.1') ||
      window.location.hostname.includes('staging')));

const LOG_SECRET_KEY =
  /password|passwd|secret|token|credential|authorization|cookie|role[-_]?id/i;

export function redactLogValue(value, depth = 0) {
  if (value == null || typeof value !== 'object' || depth > 8) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(item => redactLogValue(item, depth + 1));
  }
  const out = {};
  for (const [key, nested] of Object.entries(value)) {
    out[key] = LOG_SECRET_KEY.test(key)
      ? '[REDACTED]'
      : redactLogValue(nested, depth + 1);
  }
  return out;
}

// Store original console methods
const originalConsole = {
  log: console.log.bind(console),
  error: console.error.bind(console),
  warn: console.warn.bind(console),
  info: console.info.bind(console),
};

// Create browser-compatible logger
const createLogger = () => {
  if (isDev) {
    // Development/Staging/Test: Use original console methods
    return {
      log: (...args) => originalConsole.log('[INFO]', ...args),
      info: (...args) => originalConsole.log('[INFO]', ...args),
      error: (...args) => originalConsole.error('[ERROR]', ...args),
      warn: (...args) => originalConsole.warn('[WARN]', ...args),
      debug: (...args) => originalConsole.log('[DEBUG]', ...args),
    };
  }
  // Production: Suppress all logs in the browser (no console output)
  return {
    log: () => {},
    info: () => {},
    error: () => {},
    warn: () => {},
    debug: () => {},
  };
};

// Export logger for use throughout the app
export const logger = createLogger();
