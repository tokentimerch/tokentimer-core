// Deep link that opens the New AD CS issuer dialog on the Renewals page:
//   /certops/renewals?workspace=<id>&action=new-adcs-issuer
// Optional agentId (agent row id), caConfig and template preselect the form.
// The page removes these parameters once the dialog has opened.

export const ADCS_ISSUER_ACTION = 'new-adcs-issuer';
export const ADCS_ISSUER_PARAMS = ['action', 'agentId', 'caConfig', 'template'];

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function clean(value, max) {
  const text = String(value || '').trim();
  return text && text.length <= max ? text : '';
}

/** Relative path of the deep link. Empty values are left out. */
export function adcsIssuerLink({
  workspaceId,
  agentId,
  caConfig,
  template,
} = {}) {
  const params = new URLSearchParams();
  if (workspaceId) params.set('workspace', workspaceId);
  params.set('action', ADCS_ISSUER_ACTION);
  if (agentId) params.set('agentId', agentId);
  if (caConfig) params.set('caConfig', caConfig);
  if (template) params.set('template', template);
  return `/certops/renewals?${params.toString()}`;
}

/**
 * The request in the URL, or null when it asks for nothing. Values the form
 * could not use (a malformed agent id, an overlong string) are dropped.
 */
export function parseAdcsIssuerRequest(searchParams) {
  if (searchParams?.get('action') !== ADCS_ISSUER_ACTION) return null;
  const agentId = String(searchParams.get('agentId') || '').trim();
  return {
    agentId: UUID_RE.test(agentId) ? agentId : '',
    caConfig: clean(searchParams.get('caConfig'), 200),
    template: clean(searchParams.get('template'), 64),
  };
}

/** The same search parameters without the request. */
export function withoutAdcsIssuerRequest(searchParams) {
  const next = new URLSearchParams(searchParams);
  for (const key of ADCS_ISSUER_PARAMS) next.delete(key);
  return next;
}
