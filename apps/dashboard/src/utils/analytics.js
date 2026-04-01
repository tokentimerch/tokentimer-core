/**
 * No-op analytics stubs for tokentimer-core.
 * These functions exist as override points for variant overlays.
 */

export function trackEvent() {}

export function sanitizePosthogProperties(_eventName, properties) {
  return properties;
}

export function resetIdentity() {}

export function identifyUser() {}

export function setDefaultEventProps() {}
