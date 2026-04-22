import axios from 'axios';
import {
  showError as showGlobalError,
  showSuccess as showGlobalSuccess,
} from './toast.js';
import { logger } from './logger.js';
import { resetIdentity } from './analytics.js';

// Tracks whether the frontend has ever observed a logged-in session. A 401
// should only trigger the "session expired" toast + redirect when the user
// actually had a session that could expire. Without this, background 401s on
// public pages or 404s look like forced logouts.
let hasObservedLoggedInSession = false;

// API base URL resolution:
// - If runtime env.js defines API_URL, use it first
// - Otherwise if VITE_API_URL is set and not pointing to localhost when we're not on localhost, use it
// - If running on localhost, default to local backend
// - Otherwise, use relative paths so ingress can route /api and /auth
const resolveApiBaseUrl = () => {
  const runtimeUrl =
    typeof window !== 'undefined' && window.__ENV__
      ? window.__ENV__.API_URL
      : undefined;
  const viteUrl =
    typeof import.meta !== 'undefined' && import.meta.env
      ? import.meta.env.VITE_API_URL
      : undefined;
  const isBrowser = typeof window !== 'undefined';
  const isLocalHost =
    isBrowser &&
    (window.location.hostname === 'localhost' ||
      window.location.hostname === '127.0.0.1');

  const configuredUrl = runtimeUrl || viteUrl;

  if (configuredUrl) {
    const pointsToLocalhost = /(^http:\/\/localhost|127\.0\.0\.1)/i.test(
      String(configuredUrl)
    );
    if (!isLocalHost && pointsToLocalhost) {
      return '';
    }
    return configuredUrl;
  }

  if (isLocalHost) return 'http://localhost:4000';
  return '';
};

export const API_BASE_URL = resolveApiBaseUrl();

// Debug: Log environment variables only in development or on local/staging hosts
try {
  const env = typeof import.meta !== 'undefined' ? import.meta.env : null;
  const isDev = !!(env && env.DEV);
  const isLocalOrStaging =
    typeof window !== 'undefined' &&
    (window.location.hostname.includes('localhost') ||
      window.location.hostname.includes('127.0.0.1') ||
      window.location.hostname.includes('staging'));
  if ((isDev || isLocalOrStaging) && env) {
    logger.log('Environment variables:', {
      DEV: env.DEV,
      MODE: env.MODE,
      VITE_ENVIRONMENT: env.VITE_ENVIRONMENT,
      NODE_ENV: env.NODE_ENV,
    });
  }
} catch (_) {}

// Create axios instance with default configuration
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000, // 30 seconds default (can be overridden per request)
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Include cookies for session management
});

// CSRF token management
let csrfToken = null;

// Deduplicate identical error toasts within a short time window
// Keyed by message string to avoid spamming users with repeated identical errors
const recentlyShownErrorToasts = new Map(); // message -> timestamp
const ERROR_TOAST_DEDUP_WINDOW_MS = 4000;

const showErrorToastOnce = message => {
  try {
    const now = Date.now();
    const lastShownAt = recentlyShownErrorToasts.get(message) || 0;
    if (now - lastShownAt < ERROR_TOAST_DEDUP_WINDOW_MS) {
      return; // Suppress duplicate toast
    }
    recentlyShownErrorToasts.set(message, now);
    // Clean up this key after the window to prevent unbounded growth
    setTimeout(() => {
      // Only clear if untouched since scheduling
      const current = recentlyShownErrorToasts.get(message);
      if (current && current === now) recentlyShownErrorToasts.delete(message);
    }, ERROR_TOAST_DEDUP_WINDOW_MS + 500);
  } catch (_) {
    /* noop */
  }

  showGlobalError(message);
};

// Function to get CSRF token
const getCsrfToken = async () => {
  if (!csrfToken) {
    try {
      const response = await axios.get(`${API_BASE_URL}/api/csrf-token`, {
        withCredentials: true,
      });
      const { csrfToken: token } = response.data;
      csrfToken = token;
    } catch (error) {
      logger.warn('Failed to get CSRF token:', error);
    }
  }
  return csrfToken;
};

// Request interceptor for authentication and logging
apiClient.interceptors.request.use(
  async config => {
    // Add timestamp for debugging
    config.metadata = { startTime: new Date() };

    // Add CSRF token for state-changing requests
    if (
      ['post', 'put', 'delete', 'patch'].includes(config.method?.toLowerCase())
    ) {
      const token = await getCsrfToken();
      if (token) {
        config.headers['X-CSRF-Token'] = token;
      }
    }

    // Log request in development/staging (based on domain since env vars may are not available at runtime)
    const shouldLog =
      (typeof import.meta !== 'undefined' &&
        import.meta.env &&
        import.meta.env.DEV) ||
      (typeof window !== 'undefined' &&
        (window.location.hostname.includes('localhost') ||
          window.location.hostname.includes('127.0.0.1') ||
          window.location.hostname.includes('staging')));

    if (shouldLog && !config._suppressLog) {
      logger.info(
        `🚀 API Request: ${config.method?.toUpperCase()} ${config.url}`,
        {
          data: config.data,
          params: config.params,
          headers: config.headers,
          timeout: config.timeout, // Log timeout for debugging
        }
      );
    }

    return config;
  },
  error => {
    logger.error('❌ Request Error:', error);
    return Promise.reject(error);
  }
);

// Response interceptor for error handling and logging
apiClient.interceptors.response.use(
  response => {
    // Log response in development/staging (based on domain since env vars are not available at runtime)
    const shouldLog =
      (typeof import.meta !== 'undefined' &&
        import.meta.env &&
        import.meta.env.DEV) ||
      (typeof window !== 'undefined' &&
        (window.location.hostname.includes('localhost') ||
          window.location.hostname.includes('127.0.0.1') ||
          window.location.hostname.includes('staging')));

    if (shouldLog) {
      const duration = new Date() - response.config.metadata.startTime;

      logger.info(
        `✅ API Response: ${response.config.method?.toUpperCase()} ${response.config.url} (${duration}ms)`,
        {
          status: response.status,
          data: response.data,
        }
      );
    }

    return response;
  },
  async error => {
    // Log error in development/staging (based on domain since env vars are not available at runtime)
    const shouldLog =
      (typeof import.meta !== 'undefined' &&
        import.meta.env &&
        import.meta.env.DEV) ||
      (typeof window !== 'undefined' &&
        (window.location.hostname.includes('localhost') ||
          window.location.hostname.includes('127.0.0.1') ||
          window.location.hostname.includes('staging')));

    if (shouldLog && !error.config?._suppressLog) {
      const duration = error.config?.metadata
        ? new Date() - error.config.metadata.startTime
        : 'unknown';
      logger.error(
        `❌ API Error: ${error.config?.method?.toUpperCase()} ${error.config?.url} (${duration}ms)`,
        {
          status: error.response?.status,
          data: error.response?.data,
          message: error.message,
        }
      );
    }

    // Handle CSRF token expiration
    if (
      error.response?.status === 403 &&
      error.response?.data?.code === 'EBADCSRFTOKEN'
    ) {
      logger.info('CSRF token expired, refreshing...');
      csrfToken = null; // Reset token

      // Retry the request with new token
      const token = await getCsrfToken();
      if (token && error.config) {
        error.config.headers['X-CSRF-Token'] = token;
        return apiClient.request(error.config);
      }
    }

    return Promise.reject(error);
  }
);

// Lightweight GET caching and in-flight request de-duplication
const __inFlight = new Map(); // key -> Promise
const __cache = new Map(); // key -> { expiresAt, response }

const buildKey = (url, params) => {
  try {
    const p = params
      ? JSON.stringify(
          Object.keys(params)
            .sort()
            .reduce((o, k) => ((o[k] = params[k]), o), {})
        )
      : '';
    return `${url}::${p}`;
  } catch (_) {
    return String(url);
  }
};

const cacheTTLFor = url => {
  if (!url) return 0;
  // Endpoint-specific TTLs (ms)
  // Only cache the workspaces list; do NOT cache per-workspace settings like alert-settings
  // Coalesce duplicate initial session checks to avoid critical-chain duplication
  if (url === '/api/session') return 3000;
  if (url === '/api/v1/workspaces') return 30000; // list
  if (url.includes('/api/account/plan')) return 15000;
  if (url.includes('/api/organization/usage')) return 15000;
  if (url.includes('/api/audit-events')) return 8000;
  return 0;
};

const __origGet = apiClient.get.bind(apiClient);
apiClient.get = (url, config = {}) => {
  const params = config?.params;
  const key = buildKey(url, params);
  const ttl = cacheTTLFor(url);
  if (ttl > 0) {
    const now = Date.now();
    const hit = __cache.get(key);
    if (hit && hit.expiresAt > now) {
      return Promise.resolve(hit.response);
    }
    const inflight = __inFlight.get(key);
    if (inflight) return inflight;
    const p = __origGet(url, config)
      .then(res => {
        __cache.set(key, { expiresAt: now + ttl, response: res });
        __inFlight.delete(key);
        return res;
      })
      .catch(err => {
        __inFlight.delete(key);
        throw err;
      });
    __inFlight.set(key, p);
    return p;
  }
  return __origGet(url, config);
};

// Invalidate GET cache/in-flight entries for a URL prefix (used after mutations)
const invalidateCache = urlPrefix => {
  try {
    for (const key of Array.from(__cache.keys())) {
      if (key.startsWith(urlPrefix)) __cache.delete(key);
    }
    for (const key of Array.from(__inFlight.keys())) {
      if (key.startsWith(urlPrefix)) __inFlight.delete(key);
    }
  } catch (_) {
    /* noop */
  }
};

// Error handling utilities
export const handleApiError = (error, customMessage = null) => {
  let message = customMessage;
  let suppressToast = false;

  if (error.response) {
    // Server responded with error status
    const { status, data } = error.response;

    switch (status) {
      case 400: {
        // Prefer detailed validation messages when available
        const details = Array.isArray(data?.details)
          ? data.details.filter(Boolean)
          : null;
        const errors = Array.isArray(data?.errors)
          ? data.errors.filter(Boolean)
          : null;
        const list =
          details && details.length > 0
            ? details
            : errors && errors.length > 0
              ? errors
              : null;
        message =
          list && list.length > 0
            ? list.join('; ')
            : data.error || 'Invalid request. Please check your input.';
        break;
      }
      case 401: {
        const path =
          (typeof window !== 'undefined' &&
            window.location &&
            window.location.pathname) ||
          '';
        const requestUrl = error.config?.url || '';

        // Check if this is an integration scan endpoint (third-party token, not our session)
        const isIntegrationEndpoint =
          requestUrl.includes('/api/v1/integrations/') &&
          (requestUrl.includes('/scan') ||
            requestUrl.includes('/detect-regions'));

        if (isIntegrationEndpoint) {
          // Integration token is invalid/expired, not our session
          message =
            data.error ||
            'Authentication failed. The provided token is expired or invalid.';
          suppressToast = false; // Show error to user
          break;
        }

        // Do not disrupt public pages with toasts or redirects
        const publicRoots = [
          '/',
          '/login',
          '/register',
          '/docs',
          '/solutions',
          '/blog',
          '/compare',
          '/pricing',
          '/help',
          '/privacy-policy',
          '/terms-of-service',
          '/faq',
        ];
        const isPublic = publicRoots.some(
          p => p === path || (p !== '/' && path.startsWith(p))
        );
        if (isPublic) {
          suppressToast = true;
          message = null;
          break;
        }
        // If the user never had a logged-in session, there is no session to
        // expire. Skip the toast + redirect so background 401s on unknown
        // paths (e.g. a 404 URL hitting /api/v1/workspaces) don't masquerade
        // as a forced logout.
        if (!hasObservedLoggedInSession) {
          suppressToast = true;
          message = null;
          break;
        }
        message = 'Your session has expired. Please log in again.';
        // Secure redirect - don't expose authentication state details
        setTimeout(() => {
          try {
            if (window.location.pathname !== '/login') {
              window.location.href = '/login';
            }
          } catch (_) {}
        }, 800);
        break;
      }
      case 403:
        message =
          data.error ||
          "Access denied. You don't have permission for this action.";
        break;
      case 404:
        message = data.error || 'Resource not found.';
        break;
      case 429: {
        message =
          data.error ||
          'Too many requests. Please wait a moment and try again.';
        // Do not redirect/log out on rate limits; these are transient
        suppressToast = false;
        break;
      }
      case 500:
        message = data.error || 'Server error. Please try again later.';
        break;
      default:
        message = data.error || `Request failed with status ${status}.`;
    }
  } else if (error.request) {
    // Network error - check if backend provided a more specific message
    if (error.message && error.message !== 'Network Error') {
      // Use the error message from axios/backend if it's informative
      ({ message } = error);
    } else {
      // Generic network error fallback
      message = 'Network error. Please check your connection and try again.';
    }
  } else {
    // Other error
    message = error.message || 'An unexpected error occurred.';
  }

  // Show error toast (deduplicated) unless explicitly suppressed
  // For toast, show only short message (first sentence), full message goes to modal
  // Suppress toasts for integration scan endpoints since errors are displayed in the modal
  const requestUrl = error.config?.url || '';
  const isIntegrationScan =
    requestUrl.includes('/api/v1/integrations/') &&
    (requestUrl.includes('/scan') || requestUrl.includes('/detect-regions'));

  if (message && !suppressToast && !isIntegrationScan) {
    const shortMessage = `${
      message.split(
        /\. (Clear cache|Generate|If this persists|Reference:|Verify|Ensure|Wait)/
      )[0]
    }.`;
    showErrorToastOnce(shortMessage);
  }

  return message;
};

// Success notification utility
// Deduplicate identical success toasts within a short time window (avoid double-success popups)
const recentlyShownSuccessToasts = new Map(); // message -> timestamp
const SUCCESS_TOAST_DEDUP_WINDOW_MS = 2000;

export const showSuccessMessage = message => {
  try {
    const now = Date.now();
    const lastShownAt = recentlyShownSuccessToasts.get(message) || 0;
    if (now - lastShownAt < SUCCESS_TOAST_DEDUP_WINDOW_MS) return;
    recentlyShownSuccessToasts.set(message, now);
    setTimeout(() => {
      const current = recentlyShownSuccessToasts.get(message);
      if (current && current === now)
        recentlyShownSuccessToasts.delete(message);
    }, SUCCESS_TOAST_DEDUP_WINDOW_MS + 250);
  } catch (_) {}

  showGlobalSuccess(message);
};

// API endpoints
export const API_ENDPOINTS = {
  // Authentication
  LOGIN: '/auth/login',
  LOGOUT: '/api/logout',
  VERIFY_EMAIL: '/auth/verify-email',
  RESET_PASSWORD: '/auth/reset-password',

  // User management
  GET_SESSION: '/api/session',
  UPDATE_ACCOUNT: '/auth/account',
  DELETE_ACCOUNT: '/auth/account',

  // Token management
  GET_TOKENS: '/api/tokens',
  CREATE_TOKEN: '/api/tokens',
  UPDATE_TOKEN: id => `/api/tokens/${id}`,
  DELETE_TOKEN: id => `/api/tokens/${id}`,

  // Alerts
  ALERT_QUEUE: '/api/alert-queue',
  ALERT_REQUEUE: '/api/alert-queue/requeue',
  ALERT_STATS: '/api/alert-stats',
  ACCOUNT_PLAN: '/api/account/plan',
  TEST_WEBHOOK: '/api/test-webhook',
  AUDIT_EVENTS: '/api/audit-events',
  ALERT_RETRY: id => `/api/alert-queue/${id}/retry`,
  WORKSPACE_AUDIT_EVENTS: id => `/api/v1/workspaces/${id}/audit-events`,
  AUDIT_EXPORT: '/api/account/export-audit',

  // Workspaces & Sections
  WORKSPACES: '/api/v1/workspaces',
  WORKSPACE: id => `/api/v1/workspaces/${id}`,
  WORKSPACE_MEMBERS: id => `/api/v1/workspaces/${id}/members`,
  WORKSPACE_INVITE: id => `/api/v1/workspaces/${id}/members`,
  WORKSPACE_MEMBER: (id, userId) =>
    `/api/v1/workspaces/${id}/members/${userId}`,
  WORKSPACE_INVITATIONS: id => `/api/v1/workspaces/${id}/invitations`,
  WORKSPACE_INVITATION: (id, invitationId) =>
    `/api/v1/workspaces/${id}/invitations/${invitationId}`,
  WORKSPACE_ALERT_SETTINGS: id => `/api/v1/workspaces/${id}/alert-settings`,
  WORKSPACE_TRANSFER_TOKENS: id => `/api/v1/workspaces/${id}/transfer-tokens`,
  // Vault integration (workspace_id required for scan)
  VAULT_SCAN: workspaceId =>
    `/api/v1/integrations/vault/scan?workspace_id=${encodeURIComponent(workspaceId)}`,
  VAULT_MOUNTS: '/api/v1/integrations/vault/mounts',
  VAULT_IMPORT: id =>
    `/api/v1/integrations/vault/import?workspace_id=${encodeURIComponent(id)}`,
  // GitLab integration (workspace_id required for scan)
  GITLAB_SCAN: workspaceId =>
    `/api/v1/integrations/gitlab/scan?workspace_id=${encodeURIComponent(workspaceId)}`,
  // GitHub integration (workspace_id required for scan)
  GITHUB_SCAN: workspaceId =>
    `/api/v1/integrations/github/scan?workspace_id=${encodeURIComponent(workspaceId)}`,
  // AWS integration (workspace_id required for scan)
  AWS_DETECT_REGIONS: '/api/v1/integrations/aws/detect-regions',
  AWS_SCAN: workspaceId =>
    `/api/v1/integrations/aws/scan?workspace_id=${encodeURIComponent(workspaceId)}`,
  // Azure integration (workspace_id required for scan)
  AZURE_SCAN: workspaceId =>
    `/api/v1/integrations/azure/scan?workspace_id=${encodeURIComponent(workspaceId)}`,
  // Azure AD integration (workspace_id required for scan)
  AZURE_AD_SCAN: workspaceId =>
    `/api/v1/integrations/azure-ad/scan?workspace_id=${encodeURIComponent(workspaceId)}`,
  // GCP integration (workspace_id required for scan)
  GCP_SCAN: workspaceId =>
    `/api/v1/integrations/gcp/scan?workspace_id=${encodeURIComponent(workspaceId)}`,
  // Generic integration import
  INTEGRATION_IMPORT: id =>
    `/api/v1/integrations/import?workspace_id=${encodeURIComponent(id)}`,
  INTEGRATION_CHECK_DUPLICATES: id =>
    `/api/v1/integrations/check-duplicates?workspace_id=${encodeURIComponent(id)}`,
};

// Authentication API methods
export const authAPI = {
  // Login with email/password
  login: async credentials => {
    try {
      const response = await apiClient.post(API_ENDPOINTS.LOGIN, credentials);
      if (response?.data?.success || response?.data?.user) {
        hasObservedLoggedInSession = true;
      }
      return response.data;
    } catch (error) {
      throw new Error(handleApiError(error));
    }
  },

  // Logout
  logout: async () => {
    try {
      await apiClient.post(API_ENDPOINTS.LOGOUT);
      showSuccessMessage('Successfully logged out');
      // Reset analytics identity on logout (no-op in core)
      try {
        resetIdentity(true);
      } catch (_) {}
    } catch (error) {
      handleApiError(error);
    } finally {
      hasObservedLoggedInSession = false;
    }
  },

  // Get current session
  getSession: async () => {
    try {
      const response = await apiClient.get(API_ENDPOINTS.GET_SESSION);
      if (response?.data?.loggedIn) {
        hasObservedLoggedInSession = true;
      }
      return response.data;
    } catch (error) {
      // Don't show error for session check
      return null;
    }
  },

  // Verify that a session is properly established
  verifySession: async (maxAttempts = 5, delayMs = 200) => {
    let attempts = 0;

    while (attempts < maxAttempts) {
      try {
        const response = await apiClient.get(API_ENDPOINTS.GET_SESSION);

        if (response.data && response.data.loggedIn) {
          hasObservedLoggedInSession = true;
          logger.info('Session verified successfully');
          return true;
        }

        logger.info(
          `Session not ready, attempt ${attempts + 1}/${maxAttempts}`
        );
        attempts++;

        if (attempts < maxAttempts) {
          await new Promise(resolve => setTimeout(resolve, delayMs));
        }
      } catch (error) {
        logger.info(
          `Session check failed, attempt ${attempts + 1}/${maxAttempts}:`,
          error.message
        );
        attempts++;

        if (attempts < maxAttempts) {
          await new Promise(resolve => setTimeout(resolve, delayMs));
        }
      }
    }

    logger.warn('Session verification failed after all attempts');
    return false;
  },

  // Wait for session to be established with exponential backoff
  waitForSession: async (maxAttempts = 8, baseDelay = 100) => {
    let attempts = 0;

    while (attempts < maxAttempts) {
      try {
        const response = await apiClient.get(API_ENDPOINTS.GET_SESSION);

        if (response.data && response.data.loggedIn) {
          hasObservedLoggedInSession = true;
          logger.info('Session established successfully');
          return true;
        }

        attempts++;
        if (attempts < maxAttempts) {
          const delay = baseDelay * Math.pow(2, attempts - 1); // Exponential backoff
          logger.info(
            `Session not ready, retrying in ${delay}ms (attempt ${attempts}/${maxAttempts})`
          );
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      } catch (error) {
        attempts++;
        if (attempts < maxAttempts) {
          const delay = baseDelay * Math.pow(2, attempts - 1);
          logger.info(
            `Session check failed, retrying in ${delay}ms (attempt ${attempts}/${maxAttempts})`
          );
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }

    logger.warn('Session establishment failed after all attempts');
    return false;
  },

  // Check if user is currently authenticated
  isAuthenticated: async () => {
    try {
      const response = await apiClient.get(API_ENDPOINTS.GET_SESSION);
      return response.data && response.data.loggedIn;
    } catch (error) {
      logger.error('Authentication check failed:', error.message);
      return false;
    }
  },

  // Update account
  updateAccount: async accountData => {
    try {
      const response = await apiClient.put(
        API_ENDPOINTS.UPDATE_ACCOUNT,
        accountData
      );
      showSuccessMessage('Account updated successfully');
      return response.data;
    } catch (error) {
      throw new Error(handleApiError(error));
    }
  },

  // Delete account
  deleteAccount: async () => {
    try {
      await apiClient.delete(API_ENDPOINTS.DELETE_ACCOUNT);
      showSuccessMessage('Account deleted successfully');
    } catch (error) {
      throw new Error(handleApiError(error));
    }
  },

  // Get account plan info (including integration quota for workspace)
  getPlan: async (workspaceId = null) => {
    try {
      const url = workspaceId
        ? `${API_ENDPOINTS.ACCOUNT_PLAN}?workspace_id=${encodeURIComponent(workspaceId)}`
        : API_ENDPOINTS.ACCOUNT_PLAN;
      const response = await apiClient.get(url);
      return response.data;
    } catch (error) {
      throw new Error(handleApiError(error));
    }
  },
};

// Token API methods
export const tokenAPI = {
  // Get all tokens
  getTokens: async (params = {}) => {
    try {
      const response = await apiClient.get(API_ENDPOINTS.GET_TOKENS, {
        params,
      });
      return response.data; // { items, total, facets }
    } catch (error) {
      throw new Error(handleApiError(error));
    }
  },

  // Create new token
  createToken: async (tokenData, confirmDuplicate = false) => {
    try {
      const payload = { ...tokenData };
      if (confirmDuplicate) {
        payload.confirm_duplicate = true;
      }
      const response = await apiClient.post(
        API_ENDPOINTS.CREATE_TOKEN,
        payload
      );
      if (response.status === 200 && response.data.id) {
        // Token was updated (duplicate)
        showSuccessMessage('Token updated successfully');
      } else {
        showSuccessMessage('Token created successfully');
      }
      return response.data;
    } catch (error) {
      // Check if it's a duplicate error
      if (
        error.response?.status === 409 &&
        error.response?.data?.code === 'DUPLICATE_TOKEN'
      ) {
        throw error.response.data; // Throw the error data so we can handle it
      }
      throw new Error(handleApiError(error));
    }
  },

  // Update token
  updateToken: async (id, tokenData) => {
    try {
      const response = await apiClient.put(
        API_ENDPOINTS.UPDATE_TOKEN(id),
        tokenData
      );
      showSuccessMessage('Token updated successfully');
      return response.data;
    } catch (error) {
      throw new Error(handleApiError(error));
    }
  },

  // Delete token
  deleteToken: async id => {
    try {
      await apiClient.delete(API_ENDPOINTS.DELETE_TOKEN(id));
      showSuccessMessage('Token deleted successfully');
    } catch (error) {
      throw new Error(handleApiError(error));
    }
  },
};

// Alert API methods
export const alertAPI = {
  // Test generic/typed webhook
  testWebhook: async (url, kind = 'generic', opts = {}) => {
    try {
      const response = await apiClient.post(API_ENDPOINTS.TEST_WEBHOOK, {
        url,
        kind,
        ...opts,
      });
      showSuccessMessage('Webhook test message sent successfully');
      return response.data;
    } catch (error) {
      throw new Error(handleApiError(error));
    }
  },
  // Bulk requeue alerts (optionally by workspace)
  requeueAlerts: async ({ workspaceId = null } = {}) => {
    try {
      const payload = workspaceId ? { workspace_id: workspaceId } : {};
      const response = await apiClient.post(
        API_ENDPOINTS.ALERT_REQUEUE,
        payload
      );
      showSuccessMessage(`Requeued ${response?.data?.updated || 0} alerts`);
      return response.data;
    } catch (error) {
      throw new Error(handleApiError(error));
    }
  },
  // Fetch audit events
  getAuditEvents: async (
    limit = 100,
    offset = 0,
    { scope = 'user', workspaceId = null, action = null, query = null } = {}
  ) => {
    try {
      let response;
      const params = { limit, offset };
      if (action) params.action = action;
      if (query) params.query = query;

      if (scope === 'organization') {
        params.scope = 'organization';
        response = await apiClient.get(API_ENDPOINTS.AUDIT_EVENTS, { params });
      } else if (scope === 'workspace' && workspaceId) {
        response = await apiClient.get(
          API_ENDPOINTS.WORKSPACE_AUDIT_EVENTS(workspaceId),
          { params }
        );
      } else {
        response = await apiClient.get(API_ENDPOINTS.AUDIT_EVENTS, { params });
      }
      return response.data;
    } catch (error) {
      throw new Error(handleApiError(error));
    }
  },
  // Export audit events (JSON pretty or CSV) via server endpoint
  exportAudit: async ({
    scope = 'user',
    workspaceId = null,
    format = 'json',
    limit = 10000,
    since = null,
    action = null,
    query = null,
  } = {}) => {
    try {
      const params = { scope, format, limit };
      if (workspaceId) params.workspace_id = workspaceId;
      if (since) params.since = since;
      if (action) params.action = action;
      if (query) params.query = query;
      const response = await apiClient.get(API_ENDPOINTS.AUDIT_EXPORT, {
        params,
        responseType: 'blob',
        // Ensure no caching interferes
        headers: { Accept: format === 'csv' ? 'text/csv' : 'application/json' },
      });
      const disposition = response.headers['content-disposition'] || '';
      const match = /filename="?([^";]+)"?/i.exec(disposition);
      const filename = match
        ? match[1]
        : `tokentimer-audit-${new Date().toISOString().split('T')[0]}.${format === 'csv' ? 'csv' : 'json'}`;
      const contentType =
        response.headers['content-type'] ||
        (format === 'csv' ? 'text/csv' : 'application/json');
      return { blob: response.data, filename, contentType };
    } catch (error) {
      throw new Error(handleApiError(error));
    }
  },
  // Fetch alert queue (paginated)
  getAlertQueue: async (
    limit = 100,
    offset = 0,
    { workspaceId = null } = {}
  ) => {
    try {
      const params = { limit, offset };
      if (workspaceId) params.workspace_id = workspaceId;
      const response = await apiClient.get(API_ENDPOINTS.ALERT_QUEUE, {
        params,
      });
      return response.data;
    } catch (error) {
      throw new Error(handleApiError(error));
    }
  },
  // Manual retry a specific channel
  retryAlertChannel: async (id, channel) => {
    try {
      const response = await apiClient.post(API_ENDPOINTS.ALERT_RETRY(id), {
        channel,
      });
      showSuccessMessage('Retry queued');
      return response.data;
    } catch (error) {
      throw new Error(handleApiError(error));
    }
  },
};

// Workspace API methods
export const workspaceAPI = {
  list: async (limit = 50, offset = 0, options = {}) => {
    try {
      // Optionally bypass local GET cache and in-flight coalescing
      if (options && options.nocache) {
        try {
          invalidateCache(API_ENDPOINTS.WORKSPACES);
        } catch (_) {}
      }
      const res = await apiClient.get(API_ENDPOINTS.WORKSPACES, {
        params: {
          limit,
          offset,
          ...(options && options.nocache ? { t: Date.now() } : {}),
        },
      });
      return res.data;
    } catch (e) {
      throw new Error(handleApiError(e));
    }
  },
  create: async ({ name, plan }) => {
    try {
      const res = await apiClient.post(API_ENDPOINTS.WORKSPACES, {
        name,
        plan,
      });
      showSuccessMessage('Workspace created');
      // Bust cached workspace lists so new workspace appears immediately
      invalidateCache(API_ENDPOINTS.WORKSPACES);
      return res.data;
    } catch (e) {
      throw new Error(handleApiError(e));
    }
  },
  get: async id => {
    try {
      const res = await apiClient.get(API_ENDPOINTS.WORKSPACE(id));
      return res.data;
    } catch (e) {
      throw new Error(handleApiError(e));
    }
  },
  rename: async (id, name) => {
    try {
      const res = await apiClient.patch(API_ENDPOINTS.WORKSPACE(id), { name });
      showSuccessMessage('Workspace renamed');
      // Bust cached workspace lists/details so changes reflect immediately
      invalidateCache(API_ENDPOINTS.WORKSPACES);
      return res.data;
    } catch (e) {
      throw new Error(handleApiError(e));
    }
  },
  remove: async id => {
    try {
      await apiClient.delete(API_ENDPOINTS.WORKSPACE(id));
      showSuccessMessage('Workspace deleted');
      // Bust cached workspace lists/details so deletion reflects immediately
      invalidateCache(API_ENDPOINTS.WORKSPACES);
    } catch (e) {
      throw new Error(handleApiError(e));
    }
  },
  listMembers: async (id, limit = 100, offset = 0) => {
    try {
      const res = await apiClient.get(API_ENDPOINTS.WORKSPACE_MEMBERS(id), {
        params: { limit, offset },
      });
      return res.data;
    } catch (e) {
      throw new Error(handleApiError(e));
    }
  },
  inviteMember: async (id, { email, role }) => {
    try {
      const res = await apiClient.post(API_ENDPOINTS.WORKSPACE_INVITE(id), {
        email,
        role,
      });
      showSuccessMessage('Member invited');
      return res.data;
    } catch (e) {
      throw new Error(handleApiError(e));
    }
  },
  changeRole: async (id, userId, role) => {
    try {
      const res = await apiClient.patch(
        API_ENDPOINTS.WORKSPACE_MEMBER(id, userId),
        { role }
      );
      showSuccessMessage('Role updated');
      return res.data;
    } catch (e) {
      throw new Error(handleApiError(e));
    }
  },
  removeMember: async (id, userId) => {
    try {
      await apiClient.delete(API_ENDPOINTS.WORKSPACE_MEMBER(id, userId));
      showSuccessMessage('Member removed');
    } catch (e) {
      throw new Error(handleApiError(e));
    }
  },
  listInvitations: async (id, limit = 100, offset = 0) => {
    try {
      const res = await apiClient.get(
        API_ENDPOINTS.WORKSPACE_INVITATIONS(id),
        { params: { limit, offset } }
      );
      return res.data;
    } catch (e) {
      throw new Error(handleApiError(e));
    }
  },
  cancelInvitation: async (id, invitationId) => {
    try {
      await apiClient.delete(
        API_ENDPOINTS.WORKSPACE_INVITATION(id, invitationId)
      );
      showSuccessMessage('Invitation cancelled');
    } catch (e) {
      throw new Error(handleApiError(e));
    }
  },
  // Sections deprecated: previously section entities existed; now section is a token field.
  getAlertSettings: async id => {
    try {
      const res = await apiClient.get(
        API_ENDPOINTS.WORKSPACE_ALERT_SETTINGS(id)
      );
      return res.data;
    } catch (e) {
      throw new Error(handleApiError(e));
    }
  },
  updateAlertSettings: async (id, payload) => {
    try {
      const res = await apiClient.put(
        API_ENDPOINTS.WORKSPACE_ALERT_SETTINGS(id),
        payload
      );
      // Bust cached alert settings for this workspace so future loads are fresh
      invalidateCache(API_ENDPOINTS.WORKSPACE_ALERT_SETTINGS(id));
      return res.data;
    } catch (e) {
      throw new Error(handleApiError(e));
    }
  },
  transferTokens: async (toWorkspaceId, fromWorkspaceId, tokenIds) => {
    try {
      const res = await apiClient.post(
        API_ENDPOINTS.WORKSPACE_TRANSFER_TOKENS(toWorkspaceId),
        { from_workspace_id: fromWorkspaceId, token_ids: tokenIds }
      );
      showSuccessMessage('Tokens transferred');
      // Bust tokens list caches
      try {
        invalidateCache(API_ENDPOINTS.GET_TOKENS);
      } catch (_) {}
      return res.data;
    } catch (e) {
      throw new Error(handleApiError(e));
    }
  },
};

// Vault integration API
export const vaultAPI = {
  scan: async ({
    workspaceId,
    address,
    token,
    include = { kv: true, pki: true },
    mounts = [],
    maxItemsPerMount = 250,
    pathPrefix,
  }) => {
    if (!workspaceId) {
      throw new Error('workspaceId is required for integration scans');
    }
    try {
      const payload = {
        address,
        token,
        include,
        mounts: Array.isArray(mounts) ? mounts : [],
        maxItemsPerMount,
        pathPrefix,
      };
      const res = await apiClient.post(
        API_ENDPOINTS.VAULT_SCAN(workspaceId),
        payload,
        {
          _suppressLog: true,
          timeout: 150000, // 150 seconds timeout (longer than backend's 120s to receive error response)
        }
      );
      return res.data; // { items, summary, mounts }
    } catch (e) {
      const errorMessage = handleApiError(e, 'Vault scan failed');
      const err = new Error(errorMessage);
      err.code = e.response?.data?.code;
      err.quota = e.response?.data?.quota;
      throw err;
    }
  },
  listMounts: async ({ address, token }) => {
    try {
      const res = await apiClient.post(
        API_ENDPOINTS.VAULT_MOUNTS,
        { address, token },
        { _suppressLog: true }
      );
      return res.data?.mounts || [];
    } catch (e) {
      throw new Error(handleApiError(e, 'Failed to load mounts'));
    }
  },
  import: async ({ workspaceId, items, defaults = {} }) => {
    try {
      const payload = {
        items,
        default_category: defaults.category,
        default_type: defaults.type,
        contact_group_id: defaults.contact_group_id || null,
      };
      const res = await apiClient.post(
        API_ENDPOINTS.VAULT_IMPORT(workspaceId),
        payload
      );
      const createdCount = res?.data?.created_count || 0;
      const updatedCount = res?.data?.updated_count || 0;
      if (updatedCount > 0) {
        showSuccessMessage(
          `Imported ${createdCount} new items, updated ${updatedCount} existing items`
        );
      } else {
        showSuccessMessage(`Imported ${createdCount} items`);
      }
      return res.data;
    } catch (e) {
      throw new Error(handleApiError(e, 'Vault import failed'));
    }
  },
};

// GitLab integration API
export const gitlabAPI = {
  scan: async ({
    workspaceId,
    baseUrl,
    token,
    include = { tokens: true, keys: true },
    maxItems = 500,
    filters = {},
  }) => {
    if (!workspaceId) {
      throw new Error('workspaceId is required for integration scans');
    }
    try {
      const payload = {
        baseUrl,
        token,
        include,
        maxItems,
        filters,
      };

      // Use axios.request with explicit config to ensure timeout is applied
      // (instead of relying on config merging which might not work properly)
      const res = await apiClient.request({
        method: 'POST',
        url: API_ENDPOINTS.GITLAB_SCAN(workspaceId),
        data: payload,
        timeout: 150000, // 150 seconds timeout (longer than backend's 120s to receive error response)
        headers: {
          'Content-Type': 'application/json',
        },
        withCredentials: true,
        _suppressLog: true,
      });
      return res.data; // { items, summary }
    } catch (e) {
      // Use the error message from backend (already detailed)
      const errorMessage = handleApiError(e, 'GitLab scan failed');
      // Preserve response data for quota exceeded errors
      const err = new Error(errorMessage);
      err.code = e.response?.data?.code;
      err.quota = e.response?.data?.quota;
      throw err;
    }
  },
};

// GitHub integration API
export const githubAPI = {
  scan: async ({
    workspaceId,
    baseUrl,
    token,
    include = { tokens: true, sshKeys: true, deployKeys: true, secrets: true },
    maxItems = 500,
  }) => {
    if (!workspaceId) {
      throw new Error('workspaceId is required for integration scans');
    }
    try {
      const payload = {
        baseUrl,
        token,
        include,
        maxItems,
      };
      // Use axios.request with explicit config to ensure timeout is applied
      const res = await apiClient.request({
        method: 'POST',
        url: API_ENDPOINTS.GITHUB_SCAN(workspaceId),
        data: payload,
        timeout: 150000, // 150 seconds timeout (longer than backend's 120s to receive error response)
        headers: {
          'Content-Type': 'application/json',
        },
        withCredentials: true,
        _suppressLog: true,
      });
      return res.data; // { items, summary }
    } catch (e) {
      const errorMessage = handleApiError(e, 'GitHub scan failed');
      const err = new Error(errorMessage);
      err.code = e.response?.data?.code;
      err.quota = e.response?.data?.quota;
      throw err;
    }
  },
};

// AWS integration API
export const awsAPI = {
  detectRegions: async ({
    accessKeyId,
    secretAccessKey,
    sessionToken = null,
  }) => {
    try {
      const payload = {
        accessKeyId,
        secretAccessKey,
        sessionToken,
      };
      // Region detection can take 30-60 seconds (checking 26+ regions)
      // Note: detectRegions is a utility endpoint, no quota check required
      const res = await apiClient.post(
        API_ENDPOINTS.AWS_DETECT_REGIONS,
        payload,
        {
          _suppressLog: true,
          timeout: 150000, // 150 seconds timeout
        }
      );
      return res.data; // { regionsWithSecrets, regionsWithCertificates, iam, acm }
    } catch (e) {
      throw new Error(handleApiError(e, 'AWS region detection failed'));
    }
  },
  scan: async ({
    workspaceId,
    accessKeyId,
    secretAccessKey,
    sessionToken = null,
    region = 'us-east-1',
    include = { secrets: true, iam: true, certificates: true },
    maxItems = 500,
    isContinuation = false, // For multi-region scans, set true after first scan
  }) => {
    if (!workspaceId) {
      throw new Error('workspaceId is required for integration scans');
    }
    try {
      const payload = {
        accessKeyId,
        secretAccessKey,
        sessionToken,
        region,
        include,
        maxItems,
      };
      // Add is_continuation query param for multi-region scans
      const url = isContinuation
        ? `${API_ENDPOINTS.AWS_SCAN(workspaceId)}&is_continuation=true`
        : API_ENDPOINTS.AWS_SCAN(workspaceId);
      const res = await apiClient.post(url, payload, {
        _suppressLog: true,
        timeout: 150000, // 150 seconds timeout (longer than backend's 120s to receive error response)
      });
      return res.data; // { items, summary }
    } catch (e) {
      const errorMessage = handleApiError(e, 'AWS scan failed');
      const err = new Error(errorMessage);
      err.code = e.response?.data?.code;
      err.quota = e.response?.data?.quota;
      throw err;
    }
  },
};

// Azure integration API
export const azureAPI = {
  scan: async ({
    workspaceId,
    vaultUrl,
    token,
    include = { secrets: true, certificates: true, keys: true },
    maxItems = 500,
  }) => {
    if (!workspaceId) {
      throw new Error('workspaceId is required for integration scans');
    }
    try {
      const payload = {
        vaultUrl,
        token,
        include,
        maxItems,
      };
      const res = await apiClient.post(
        API_ENDPOINTS.AZURE_SCAN(workspaceId),
        payload,
        {
          _suppressLog: true,
          timeout: 150000, // 150 seconds timeout (longer than backend's 120s to receive error response)
        }
      );
      return res.data; // { items, summary }
    } catch (e) {
      const errorMessage = handleApiError(e, 'Azure scan failed');
      const err = new Error(errorMessage);
      err.code = e.response?.data?.code;
      err.quota = e.response?.data?.quota;
      throw err;
    }
  },
};

// GCP integration API
export const gcpAPI = {
  scan: async ({
    workspaceId,
    projectId,
    accessToken,
    include = { secrets: true },
    maxItems = 500,
  }) => {
    if (!workspaceId) {
      throw new Error('workspaceId is required for integration scans');
    }
    try {
      const payload = {
        projectId,
        accessToken,
        include,
        maxItems,
      };
      const res = await apiClient.post(
        API_ENDPOINTS.GCP_SCAN(workspaceId),
        payload,
        {
          _suppressLog: true,
          timeout: 150000, // 150 seconds timeout (longer than backend's 120s to receive error response)
        }
      );
      return res.data; // { items, summary }
    } catch (e) {
      const errorMessage = handleApiError(e, 'GCP scan failed');
      const err = new Error(errorMessage);
      err.code = e.response?.data?.code;
      err.quota = e.response?.data?.quota;
      throw err;
    }
  },
};

// Azure AD integration API
export const azureADAPI = {
  scan: async ({
    workspaceId,
    token,
    include = { applications: true, servicePrincipals: true },
    maxItems = 500,
  }) => {
    if (!workspaceId) {
      throw new Error('workspaceId is required for integration scans');
    }
    try {
      const payload = {
        token,
        include,
        maxItems,
      };
      const res = await apiClient.post(
        API_ENDPOINTS.AZURE_AD_SCAN(workspaceId),
        payload,
        {
          _suppressLog: true,
          timeout: 150000, // 150 seconds timeout (longer than backend's 120s to receive error response)
        }
      );
      return res.data; // { items, summary }
    } catch (e) {
      const errorMessage = handleApiError(e, 'Azure AD scan failed');
      const err = new Error(errorMessage);
      err.code = e.response?.data?.code;
      err.quota = e.response?.data?.quota;
      throw err;
    }
  },
};

// Generic integration import API (shared for all integrations)
export const integrationAPI = {
  import: async ({ workspaceId, items, defaults = {} }) => {
    try {
      const payload = {
        items,
        default_category: defaults.category,
        default_type: defaults.type,
        contact_group_id: defaults.contact_group_id || null,
      };
      const res = await apiClient.post(
        API_ENDPOINTS.INTEGRATION_IMPORT(workspaceId),
        payload
      );
      const createdCount = res?.data?.created_count || 0;
      const updatedCount = res?.data?.updated_count || 0;
      if (updatedCount > 0 && createdCount > 0) {
        showSuccessMessage(
          `Imported ${createdCount} new token${createdCount !== 1 ? 's' : ''}, updated ${updatedCount} existing token${updatedCount !== 1 ? 's' : ''}`
        );
      } else if (updatedCount > 0) {
        showSuccessMessage(
          `Updated ${updatedCount} existing token${updatedCount !== 1 ? 's' : ''}`
        );
      } else {
        showSuccessMessage(
          `Imported ${createdCount} token${createdCount !== 1 ? 's' : ''}`
        );
      }
      return res.data;
    } catch (e) {
      throw new Error(handleApiError(e, 'Integration import failed'));
    }
  },

  checkDuplicates: async ({ workspaceId, items }) => {
    try {
      const res = await apiClient.post(
        API_ENDPOINTS.INTEGRATION_CHECK_DUPLICATES(workspaceId),
        { items }
      );
      return res.data;
    } catch (e) {
      throw new Error(handleApiError(e, 'Duplicate check failed'));
    }
  },
};

// Utility functions
export const formatDate = dateString => {
  if (!dateString) return '-';

  try {
    const date = new Date(dateString);
    if (isNaN(date.getTime())) return '-';

    return new Intl.DateTimeFormat('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    }).format(date);
  } catch (error) {
    return 'Invalid Date';
  }
};

export const formatDateTime = dateString => {
  if (!dateString) return 'N/A';

  try {
    const date = new Date(dateString);
    if (isNaN(date.getTime())) return 'Invalid Date';

    return new Intl.DateTimeFormat('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }).format(date);
  } catch (error) {
    return 'Invalid Date';
  }
};

// Retry utility for network requests
export const retryRequest = async (requestFn, maxRetries = 3, delay = 1000) => {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await requestFn();
    } catch (error) {
      if (attempt === maxRetries) {
        throw error;
      }

      // Wait before retrying
      await new Promise(resolve => setTimeout(resolve, delay * attempt));
    }
  }
};

export default apiClient;
