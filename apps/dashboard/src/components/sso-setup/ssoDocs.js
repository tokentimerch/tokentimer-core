// Use the authentication guide for the edition serving this onboarding flow.
export function ssoDocs(ctx) {
  const base = ctx?.capabilities?.docsBaseUrl;
  if (typeof base !== 'string' || !base.startsWith('https://')) return [];
  return [
    {
      label: 'SSO documentation',
      url: `${base.replace(/\/+$/, '')}/authentication`,
    },
  ];
}
