import { useEffect, useState } from 'react';
import { Text, VStack } from '@chakra-ui/react';

export function preflightReadinessLabel(check, now = Date.now()) {
  if (check.state === 'fresh') {
    return new Date(check.expiresAt).getTime() >= now
      ? check.renewalReady === true
        ? 'Fresh preflight available'
        : 'Fresh preflight evidence; renewal eligibility not established'
      : 'Preflight required';
  }
  const failureLabels = {
    issuer_not_allowlisted: 'Local enrollment policy blocker',
    ADCS_TEMPLATE_UNSAFE: 'Unsafe certificate template',
    ADCS_CA_CONFIG_UNSAFE: 'Unsafe CA configuration',
    ADCS_CA_KEY_CHANGED: 'Changed CA key — explicit approval required',
    ADCS_CA_KEY_UNPINNED: 'CA key verification required',
    CERTOPS_ISSUER_REVALIDATION_REQUIRED:
      'CA approval or issuer revalidation required',
    CERTOPS_PREFLIGHT_RETRIES_EXHAUSTED:
      'Retries exhausted — operator action required',
  };
  if (check.state === 'blocked' && failureLabels[check.code])
    return failureLabels[check.code];
  return (
    {
      required: 'Preflight required',
      queued: 'Preflight queued',
      running: 'Preflight running',
      awaiting_approval: 'Preflight waiting for approval',
      agent_unavailable: 'Agent unavailable',
      agent_ineligible: 'Agent incompatible or missing required capability',
      retrying: 'Retrying after temporary failure',
      blocked: 'Blocked / operator action required',
    }[check.state] || 'Preflight required'
  );
}

export default function AdcsPreflightReadiness({ issuer }) {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 15000);
    return () => clearInterval(timer);
  }, []);
  const checks = issuer.renewalReadiness?.checks?.length
    ? issuer.renewalReadiness.checks
    : issuer.preflightRefresh || [];
  return (
    <VStack align='stretch' spacing={1} fontSize='xs' mt={2} ml={6}>
      <Text>
        {issuer.confirmedKeySha256 ? 'CA approved. ' : 'CA approval required. '}
        Approval of the same key persists; renewal readiness needs a safe check
        within 24 hours on the agent that will enroll.
      </Text>
      {checks.length ? (
        checks.map(check => (
          <Text
            key={
              check.certificateId ||
              `${check.agentId}:${check.code || check.state}`
            }
          >
            {preflightReadinessLabel(check, now)}
            {check.agentId
              ? ` — agent ${check.agentId}.`
              : '. No eligible renewal agent is available.'}
            {check.checkedAt
              ? ` Checked ${new Date(check.checkedAt).toLocaleString()}.`
              : ''}
            {check.nextRefreshAt
              ? ` Next attempt: ${new Date(check.nextRefreshAt).toLocaleString()} when renewal is due.`
              : ''}
            {check.code ? ` ${check.code}.` : ''}
            {check.failureCode ? ` Last failure: ${check.failureCode}.` : ''}
            {check.errorCode && check.errorCode !== check.code
              ? ` Recorded job code: ${check.errorCode}.`
              : ''}
            {check.eligibilityReason ? ` ${check.eligibilityReason}.` : ''}
            {check.action ? ` ${check.action}` : ''}
          </Text>
        ))
      ) : (
        <Text>
          Preflight required. A check is requested automatically when renewal is
          due.
        </Text>
      )}
    </VStack>
  );
}
