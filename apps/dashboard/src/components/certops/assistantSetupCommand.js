// Only emit a command when its address is safe to paste in supported shells.
// JSON quoting alone does not prevent PowerShell or Bash interpolation.
export function assistantSetupCommand(raw, origin) {
  try {
    if (/[`$%"'&|<>()\s]/.test(raw || origin)) return null;
    const url = new URL(raw || origin, origin);
    const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local))
      return null;
    if (url.username || url.password || url.search || url.hash) return null;
    const address = url.href.replace(/\/$/, '');
    if (
      !/^https?:\/\/[a-zA-Z0-9.:[\]-]+(?:\/[a-zA-Z0-9._~/-]*)?$/.test(address)
    )
      return null;
    return `node packages/mcp/bin/tokentimer-mcp.js enroll --api-url "${address}"`;
  } catch {
    return null;
  }
}
