/**
 * Simple utility to get the appropriate logo based on browser
 * Uses PNG for Chrome to avoid SVG zoom rendering issues
 */

// Cache the result to avoid repeated userAgent checks
let cachedLogoPath = null;
let cachedFaviconPath = null;

export function getLogoPath() {
  if (cachedLogoPath === null) {
    // Check if it's Chrome (any platform) - one-time check
    const isChrome = /Chrome/.test(navigator.userAgent);
    cachedLogoPath = isChrome ? '/Branding/logo.png' : '/Branding/logo.svg';
  }
  return cachedLogoPath;
}

/** Collapsed sidebar mark; PNG avoids Firefox/Linux SVG scaling artifacts. */
export function getFaviconPath() {
  if (cachedFaviconPath === null) {
    const ua = navigator.userAgent;
    const prefersPng = /Chrome/.test(ua) || /Firefox/.test(ua);
    cachedFaviconPath = prefersPng
      ? '/Branding/favicon.png'
      : '/Branding/favicon.svg';
  }
  return cachedFaviconPath;
}
