// Keep only display-safe location details when copying scan URLs into incidents.
export function sanitizeAutoSyncLocation(value) {
  if (typeof value !== "string") return null;
  const location = value.trim();
  if (!location || /^(undefined|null|n\/a|-)$/i.test(location)) return null;

  if (/^https?:/i.test(location)) {
    if (!/^https?:\/\//i.test(location)) return null;
    try {
      const url = new URL(location);
      if (!url.hostname || !["http:", "https:"].includes(url.protocol))
        return null;
      const authorityMatch = location.match(/^https?:\/\/([^/?#]*)/i);
      const authority = authorityMatch?.[1] || "";
      const hostAndPort = authority.slice(authority.lastIndexOf("@") + 1);
      const explicitPort = hostAndPort.match(/:(\d+)$/)?.[1];
      const hasPath = location.slice(authorityMatch[0].length).startsWith("/");
      const pathname = hasPath ? url.pathname : "";
      return `${url.protocol}//${url.hostname}${explicitPort ? `:${explicitPort}` : ""}${pathname}`;
    } catch {
      return null;
    }
  }

  // Other URL schemes and ambiguous parameterized values may contain secrets.
  if (/^[a-z][a-z\d+.-]*:\/\//i.test(location) || /[?#@]/.test(location))
    return null;
  return location;
}
