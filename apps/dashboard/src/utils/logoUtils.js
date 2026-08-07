/**
 * Simple utility to get the appropriate logo based on browser
 * Uses PNG for Chrome to avoid SVG zoom rendering issues
 */

// Cache the result to avoid repeated userAgent checks
let cachedLogoPath = null;
let cachedAppIconPath = null;
let cachedFaviconPath = null;

export function getLogoPath() {
  if (cachedLogoPath === null) {
    // Check if it's Chrome (any platform) - one-time check
    const isChrome = /Chrome/.test(navigator.userAgent);
    cachedLogoPath = isChrome ? '/Branding/logo.png' : '/Branding/logo.svg';
  }
  return cachedLogoPath;
}

/**
 * App mark (icon) paired with wordmark in navigation. Same Chrome-vs-SVG
 * rendering issue as the wordmark (see getLogoPath): Chrome redraws this
 * SVG's gradient fill and thin rim stroke with visibly different contrast
 * at non-integer zoom levels, so it uses the PNG there too.
 */
export function getAppIconPath() {
  if (cachedAppIconPath === null) {
    const isChrome = /Chrome/.test(navigator.userAgent);
    cachedAppIconPath = isChrome ? '/Branding/app-icon.png' : '/Branding/app-icon.svg';
  }
  return cachedAppIconPath;
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
