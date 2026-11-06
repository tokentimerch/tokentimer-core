const UUID =
  /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;

export function mcpAuthorizationReturnTo(value) {
  if (typeof value !== 'string' || !value.startsWith('/mcp/authorize?'))
    return null;
  try {
    const url = new URL(value, 'https://tokentimer.invalid');
    const id = url.searchParams.get('request');
    if (
      url.origin !== 'https://tokentimer.invalid' ||
      url.pathname !== '/mcp/authorize' ||
      url.hash ||
      !UUID.test(id || '') ||
      [...url.searchParams.keys()].length !== 1
    )
      return null;
    return `/mcp/authorize?request=${id}`;
  } catch {
    return null;
  }
}

export function validMcpAuthorizationId(value) {
  return UUID.test(value || '');
}
