/**
 * Simple utility to get the appropriate logo based on browser
 * Uses PNG for Chrome to avoid SVG zoom rendering issues
 */

// Cache the result to avoid repeated userAgent checks
let cachedLogoPath = null;

export function getLogoPath() {
  if (cachedLogoPath === null) {
    // Check if it's Chrome (any platform) - one-time check
    const isChrome = /Chrome/.test(navigator.userAgent);
    cachedLogoPath = isChrome ? '/Branding/logo.png' : '/Branding/logo.svg';
  }
  return cachedLogoPath;
}
