import { useEffect, useState } from 'react';
import { Text, VStack } from '@chakra-ui/react';

export function preflightReadinessLabel(check, now = Date.now()) {
  if (check.state === 'fresh') {
    return new Date(check.expiresAt).getTime() >= now
      ? 'Fresh preflight available'
      : 'Preflight required';
  }
  return (
    {
      required: 'Preflight required',
      queued: 'Preflight queued',
      running: 'Preflight running / waiting for approval',
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
  const checks = issuer.preflightRefresh || [];
  return (
    <VStack align='stretch' spacing={1} fontSize='xs' mt={2} ml={6}>
      <Text>
        {issuer.confirmedKeySha256 ? 'CA approved. ' : 'CA approval required. '}
        Approval of the same key persists; renewal readiness needs a safe check
        within 24 hours on the agent that will enroll.
      </Text>
      {checks.length ? (
        checks.map(check => (
          <Text key={check.agentId}>
            {preflightReadinessLabel(check, now)} — agent {check.agentId}.
            {check.checkedAt
              ? ` Checked ${new Date(check.checkedAt).toLocaleString()}.`
              : ''}
            {check.nextRefreshAt
              ? ` Next attempt: ${new Date(check.nextRefreshAt).toLocaleString()} when renewal is due.`
              : ''}
            {check.code ? ` ${check.code}.` : ''}
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
