import { useState } from 'react';
import { FiRefreshCw } from 'react-icons/fi';
import { HStack, ListItem, OrderedList, Text, VStack } from '@chakra-ui/react';
import { DashboardActionButton } from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import { certopsProgress } from './certopsSetupSteps.jsx';
import { ADCS_REMAINING_STEPS, buildCaConfig } from './adcsModel.js';
import {
  WORKER_NOTE,
  overdueEnrollmentsMessage,
} from './certopsWorkerMessages.js';
import WorkerWarning from './WorkerWarning.jsx';
import { JobTimelineList } from './JobActivity.jsx';
import { Callout, StatusPanel, StatusTag, StepCard } from './panels.jsx';

/**
 * Status of the part of AD CS setup the server can see. Enrollment itself
 * needs a real CA, so it is never reported as working from here.
 */
export function adcsStatus({ adcs, agentDeclares }) {
  const issuers = adcs?.issuers || [];
  const confirmed = issuers.filter(i => i.confirmed && i.safe);
  return {
    agent: Boolean(agentDeclares),
    issuer: confirmed.length > 0,
    unsafe: issuers.filter(i => i.confirmed === false && i.safe === false),
    profile: (adcs?.profiles || 0) > 0,
  };
}

function Row({ n, done, label, hint }) {
  const { muted } = useDashboardTheme();
  return (
    <StepCard n={n} title={label} status={done ? 'done' : undefined}>
      {done ? null : (
        <HStack align='start' spacing={2}>
          <StatusTag>To do</StatusTag>
          {hint ? (
            <Text fontSize='xs' color={muted}>
              {hint}
            </Text>
          ) : null}
        </HStack>
      )}
    </StepCard>
  );
}

export default function AdcsStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const saved = certopsProgress(ctx);
  const certops = ctx.summary?.certops;
  const agents = certops?.agents?.items || [];
  const status = adcsStatus({
    adcs: certops?.adcs,
    agentDeclares: agents.some(
      a =>
        a.livenessState === 'live' &&
        (a.declaredCapabilities || []).includes('adcs-enroll-v1')
    ),
  });
  const [checking, setChecking] = useState(false);
  const ca = buildCaConfig(saved.caHost, saved.caName);
  // The setup summary only carries each agent's last check-in.
  const agentEvents = agents
    .filter(a => a.lastSeenAt)
    .slice(0, 3)
    .map(a => ({
      id: `agent-${a.id}`,
      at: a.lastSeenAt,
      label: `Agent ${a.hostname || a.name || 'check-in'} last seen`,
      status: a.livenessState === 'live' ? 'done' : 'waiting',
    }));
  const overdueMessage = overdueEnrollmentsMessage(certops);

  const check = async () => {
    setChecking(true);
    try {
      await ctx.refresh();
    } finally {
      setChecking(false);
    }
  };

  return (
    <StepFrame
      kind='runbook'
      title='Connect your Microsoft CA'
      description='The agent authenticates as its computer account. TokenTimer never stores CA credentials.'
      docs={[
        ...ctx.docs('certops.adcs', 'Microsoft AD CS guide'),
        ...ctx.docs('certops.worker', 'Check the CertOps worker'),
      ]}
      actions={
        <DashboardActionButton
          leftIcon={<FiRefreshCw />}
          variant='outline'
          onClick={check}
          isLoading={checking}
        >
          Check again
        </DashboardActionButton>
      }
    >
      <VStack align='stretch' spacing={3}>
        <StatusPanel status='info' title='What this guide can see'>
          This guide prepares the agent rule and watches for the issuer and
          profile. It cannot verify enrollment against your CA: start the first
          enrollment from Certificate Management.
        </StatusPanel>
        {overdueMessage ? (
          <WorkerWarning testId='adcs-overdue-warning'>
            {overdueMessage}
          </WorkerWarning>
        ) : null}
        <Row
          n={1}
          done={status.agent}
          label='Agent connected and able to enroll'
          hint='Needs a live agent on a domain-joined Windows host that reports adcs-enroll-v1. If it was installed before the rule was saved, restart TokenTimerAgent.'
        />
        <Row
          n={2}
          done={status.issuer}
          label='Issuer created and CA certificate pinned'
          hint={
            ca.ok
              ? `Use exactly ${ca.caConfig} and template ${saved.template || 'WebServer'}. Open Certificate Management, Renewals, AD CS issuers, New issuer.`
              : 'Open Certificate Management, Renewals, AD CS issuers, New issuer.'
          }
        />
        {status.unsafe.length > 0 ? (
          <StatusPanel
            status='warning'
            title='An issuer did not pass the check'
          >
            {status.unsafe.map(i => i.name).join(', ')} did not pass the check
            and is not pinned. Fix the template or CA flags, then run the check
            again.
          </StatusPanel>
        ) : null}
        <Row
          n={3}
          done={status.profile}
          label='AD CS renewal profile created'
          hint='In Renewals, Renewal profiles, New AD CS profile. Pick the confirmed issuer, the HTTPS binding (IIS site) and the certificate name.'
        />
        {agentEvents.length > 0 ? (
          <JobTimelineList label='Agent timeline' events={agentEvents} />
        ) : null}
        <Callout kind='next' title='Still to do on your side'>
          <OrderedList fontSize='sm' spacing={1} pl={2}>
            {ADCS_REMAINING_STEPS.map(s => (
              <ListItem key={s}>{s}</ListItem>
            ))}
          </OrderedList>
          <Text fontSize='xs' color={muted} mt={2}>
            Attaching the profile to a certificate and the first enrollment
            happen in Certificate Management, where the real result is shown.
          </Text>
        </Callout>
        <Text fontSize='xs' color={muted} data-testid='adcs-worker-note'>
          {WORKER_NOTE}
        </Text>
      </VStack>
    </StepFrame>
  );
}
