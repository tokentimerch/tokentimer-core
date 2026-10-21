import { useState } from 'react';
import { FiRefreshCw } from 'react-icons/fi';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
  HStack,
  ListItem,
  OrderedList,
  Text,
  VStack,
} from '@chakra-ui/react';
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

function Row({ done, label, hint }) {
  const { muted } = useDashboardTheme();
  return (
    <HStack align='start'>
      <Badge colorScheme={done ? 'green' : 'gray'} mt='2px'>
        {done ? 'Done' : 'To do'}
      </Badge>
      <VStack align='start' spacing={0}>
        <Text fontSize='sm'>{label}</Text>
        {!done && hint ? (
          <Text fontSize='xs' color={muted}>
            {hint}
          </Text>
        ) : null}
      </VStack>
    </HStack>
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
        <Alert status='info' borderRadius='md'>
          <AlertIcon />
          <AlertDescription fontSize='sm'>
            This guide prepares the agent rule and watches for the issuer and
            profile. It cannot verify enrollment against your CA, and this
            guided setup has not been verified through a real enrollment yet.
          </AlertDescription>
        </Alert>
        {overdueMessage ? (
          <WorkerWarning testId='adcs-overdue-warning'>
            {overdueMessage}
          </WorkerWarning>
        ) : null}
        <Row
          done={status.agent}
          label='Agent connected and able to enroll'
          hint='Needs a live agent on a domain-joined Windows host that reports adcs-enroll-v1. If it was installed before the rule was saved, restart TokenTimerAgent.'
        />
        <Row
          done={status.issuer}
          label='Issuer created and CA certificate pinned'
          hint={
            ca.ok
              ? `Use exactly ${ca.caConfig} and template ${saved.template || 'WebServer'}. Open Certificate Management, Renewals, AD CS issuers, New issuer.`
              : 'Open Certificate Management, Renewals, AD CS issuers, New issuer.'
          }
        />
        {status.unsafe.length > 0 ? (
          <Text fontSize='xs' color='orange.400'>
            {status.unsafe.map(i => i.name).join(', ')} did not pass the check
            and is not pinned. Fix the template or CA flags, then run the check
            again.
          </Text>
        ) : null}
        <Row
          done={status.profile}
          label='AD CS renewal profile created'
          hint='In Renewals, Renewal profiles, New AD CS profile. Pick the confirmed issuer, the HTTPS binding (IIS site) and the certificate name.'
        />
        <Text fontSize='sm' fontWeight='semibold'>
          Still to do on your side
        </Text>
        <OrderedList fontSize='sm' spacing={1} pl={2}>
          {ADCS_REMAINING_STEPS.map(s => (
            <ListItem key={s}>{s}</ListItem>
          ))}
        </OrderedList>
        <Text fontSize='xs' color={muted}>
          Attaching the profile to a certificate and the first enrollment happen
          in Certificate Management, where the real result is shown.
        </Text>
        <Text fontSize='xs' color={muted} data-testid='adcs-worker-note'>
          {WORKER_NOTE}
        </Text>
      </VStack>
    </StepFrame>
  );
}
