/**
 * Resolve API base URL for browser requests (runtime env.js, Vite, local dev, ingress).
 */
export function resolveApiBaseUrl() {
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
    if (isLocalHost && pointsToLocalhost) {
      try {
        const parsed = new URL(String(configuredUrl));
        const port =
          parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
        return `${window.location.protocol}//${window.location.hostname}:${port}`;
      } catch {
        return configuredUrl;
      }
    }
    return configuredUrl;
  }

  if (isLocalHost) {
    return `${window.location.protocol}//${window.location.hostname}:4000`;
  }
  return '';
}
