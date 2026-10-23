import { useEffect, useState } from 'react';
import { FiRefreshCw } from 'react-icons/fi';
import { Link as RouterLink, useInRouterContext } from 'react-router';
import { HStack, ListItem, OrderedList, Text, VStack } from '@chakra-ui/react';
import { DashboardActionButton } from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';
import { certopsProgress } from './certopsSetupSteps.jsx';
import { agentOnPlatform, pickSetupAgent } from './certopsMatrix.js';
import {
  ADCS_REMAINING_STEPS,
  adcsFailureAdvice,
  adcsIssuerState,
  buildCaConfig,
} from './adcsModel.js';
import {
  WORKER_NOTE,
  overdueEnrollmentsMessage,
} from './certopsWorkerMessages.js';
import WorkerWarning from './WorkerWarning.jsx';
import { JobTimelineList } from './JobActivity.jsx';
import { Callout, StatusPanel, StatusTag, StepCard } from './panels.jsx';
import AdcsIssuerWizard from '../certops/AdcsIssuerWizard.jsx';
import AdcsProfileWizard from '../certops/AdcsProfileWizard.jsx';
import { listIssuers } from '../certops/certopsEnrollmentsApi.js';
import { getWorkspaceCertOpsPauseState } from '../certops/certopsApi.js';
import { listAllIssuers } from '../certops/certopsFormat.js';

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

// Capability states in which this person cannot add an issuer here.
const BLOCKED_STATES = new Set([
  'role_handoff',
  'upgrade',
  'hidden',
  'runbook',
]);

function adcsBlocker(capabilities) {
  const cap = (capabilities?.items || []).find(c => c.id === 'certops.adcs');
  if (!cap || !BLOCKED_STATES.has(cap.state)) return null;
  return (
    cap.blockers?.[0]?.remediation ||
    'Ask a workspace administrator to complete this step.'
  );
}

function Row({ n, done, label, hint, children }) {
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
      {children}
    </StepCard>
  );
}

// The router is absent in some isolated renders; the link is only a shortcut.
function PageLink({ to, children }) {
  const inRouter = useInRouterContext();
  if (!inRouter) return null;
  return (
    <DashboardActionButton as={RouterLink} to={to} variant='outline' size='sm'>
      {children}
    </DashboardActionButton>
  );
}

function IssuerBody({
  state,
  ready,
  ca,
  saved,
  agentName,
  disabledReason,
  onOpen,
}) {
  const { muted } = useDashboardTheme();
  if (ready) {
    const i = state.issuer;
    const pair =
      i.caConfig && i.template ? `${i.caConfig}, template ${i.template}` : '';
    return (
      <Text fontSize='sm' data-testid='adcs-issuer-ready'>
        {i.name} passed the CA check and its CA certificate is pinned.
        {pair ? ` ${pair}.` : ''}
      </Text>
    );
  }
  const advice =
    state.kind === 'failed' ? adcsFailureAdvice(state.issuer) : null;
  return (
    <VStack align='stretch' spacing={3}>
      {advice ? (
        <StatusPanel
          status='warning'
          title={`${state.issuer.name} did not pass the check`}
          testId='adcs-issuer-failed'
        >
          {advice.pair ? `${advice.pair}. ` : ''}
          {advice.reasons.length > 0
            ? `Reason: ${advice.reasons.join('; ')}. `
            : 'The agent gave no reason. '}
          {advice.action}
        </StatusPanel>
      ) : null}
      {state.kind === 'pending' ? (
        <StatusPanel
          status='info'
          title='Waiting for the check'
          testId='adcs-issuer-pending'
        >
          {state.issuer.name} has not reported a verdict. Make sure the agent is
          online and its enrollment rule names this CA and template, then add
          the issuer again.
        </StatusPanel>
      ) : null}
      {state.kind === 'unpinned' ? (
        <StatusPanel
          status='info'
          title='Check passed, CA certificate not chosen'
          testId='adcs-issuer-unpinned'
        >
          Add the issuer again and choose the CA certificate in the last step of
          the dialog.
        </StatusPanel>
      ) : null}
      <Callout
        kind='before'
        title='Have these ready'
        items={[
          ca.ok
            ? `CA: ${ca.caConfig}`
            : 'CA: the server name and CA name from the Certification Authority console',
          `Template: ${saved.template || 'WebServer'} (common name, with Enroll for the agent computer account)`,
          `Agent: ${agentName || 'the Windows agent from the previous step'}, with adcs-enroll-v1 and an enrollment rule for that CA and template`,
        ]}
      />
      <HStack justify='flex-end' flexWrap='wrap'>
        {disabledReason ? (
          <Text fontSize='xs' color={muted} data-testid='adcs-issuer-disabled'>
            {disabledReason}
          </Text>
        ) : null}
        <PrimaryButton
          onClick={onOpen}
          isDisabled={Boolean(disabledReason)}
          data-testid='adcs-add-issuer'
        >
          {state.kind === 'failed' ? 'Add the issuer again' : 'Add the issuer'}
        </PrimaryButton>
      </HStack>
    </VStack>
  );
}

export default function AdcsStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const saved = certopsProgress(ctx);
  const certops = ctx.summary?.certops;
  // Only agents on a Windows host can enroll; a Linux agent of the same
  // workspace is neither counted nor listed here.
  const agents = (certops?.agents?.items || []).filter(a =>
    agentOnPlatform(a, 'windows')
  );
  const status = adcsStatus({
    adcs: certops?.adcs,
    agentDeclares: agents.some(
      a =>
        a.livenessState === 'live' &&
        (a.declaredCapabilities || []).includes('adcs-enroll-v1')
    ),
  });
  const state = adcsIssuerState(certops?.adcs);
  const [checking, setChecking] = useState(false);
  const [issuerOpen, setIssuerOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [issuers, setIssuers] = useState([]);
  const [paused, setPaused] = useState(false);
  const ca = buildCaConfig(saved.caHost, saved.caName);
  const blocker = adcsBlocker(ctx.capabilities);
  // The agent from the earlier steps: the one that serves AD CS, or the
  // Windows agent whose gap the first row explains.
  const chosen = pickSetupAgent(agents, 'adcs', 'windows', saved.reusedAgentId);
  const agentName = chosen?.name || chosen?.hostname || '';
  const dialogAgents = agents.map(a => ({
    ...a,
    agentId: a.wireAgentId || a.agentId,
  }));

  // Same pause switch the Renewals page respects.
  useEffect(() => {
    if (!ctx.workspaceId) return undefined;
    let cancelled = false;
    getWorkspaceCertOpsPauseState(ctx.workspaceId)
      .then(data => {
        if (!cancelled) setPaused(Boolean(data?.certOpsPaused));
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [ctx.workspaceId]);

  // The profile dialog picks from the pinned issuers; load them before it
  // opens so it never flashes "no issuer".
  useEffect(() => {
    if (!(status.issuer || profileOpen) || !ctx.workspaceId) return undefined;
    let cancelled = false;
    listAllIssuers(listIssuers, ctx.workspaceId, { includeUnconfigured: false })
      .then(items => {
        if (!cancelled) setIssuers(items);
      })
      .catch(() => {
        if (!cancelled) setIssuers([]);
      });
    return () => {
      cancelled = true;
    };
  }, [status.issuer, profileOpen, ctx.workspaceId]);

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
  const refreshQuietly = () => Promise.resolve(ctx.refresh?.()).catch(() => {});

  const issuerDisabled = blocker
    ? blocker
    : paused
      ? 'Certificate operations are paused for this workspace. Resume them in CertOps settings first.'
      : !status.agent
        ? 'Waiting for the agent in row 1.'
        : '';
  const profileDisabled = blocker
    ? blocker
    : paused
      ? 'Certificate operations are paused for this workspace.'
      : '';

  return (
    <StepFrame
      kind='ui'
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
          Add the issuer and the renewal profile below; this guide watches the
          results. It cannot verify enrollment against your CA: start the first
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
        >
          <IssuerBody
            state={state}
            ready={status.issuer}
            ca={ca}
            saved={saved}
            agentName={agentName}
            disabledReason={issuerDisabled}
            onOpen={() => setIssuerOpen(true)}
          />
        </Row>
        <Row
          n={3}
          done={status.profile}
          label='AD CS renewal profile created'
          hint='Pick the confirmed issuer, the HTTPS binding (IIS site) and the certificate name. The last step of the dialog attaches it to the certificate.'
        >
          {status.profile ? null : (
            <HStack justify='flex-end' flexWrap='wrap'>
              {!status.issuer || profileDisabled ? (
                <Text
                  fontSize='xs'
                  color={muted}
                  data-testid='adcs-profile-disabled'
                >
                  {profileDisabled || 'Add the issuer first.'}
                </Text>
              ) : null}
              <PrimaryButton
                onClick={() => setProfileOpen(true)}
                isDisabled={!status.issuer || Boolean(profileDisabled)}
                data-testid='adcs-add-profile'
              >
                Create the renewal profile
              </PrimaryButton>
            </HStack>
          )}
        </Row>
        {agentEvents.length > 0 ? (
          <JobTimelineList label='Agent timeline' events={agentEvents} />
        ) : null}
        <Callout kind='next' title='Still to do on your side'>
          <OrderedList fontSize='sm' spacing={1} pl={2}>
            {ADCS_REMAINING_STEPS.map(s => (
              <ListItem key={s}>{s}</ListItem>
            ))}
          </OrderedList>
          <HStack mt={2} spacing={2} flexWrap='wrap'>
            <PageLink
              to={`/certops/renewals${ctx.workspaceId ? `?workspace=${encodeURIComponent(ctx.workspaceId)}` : ''}`}
            >
              Open Renewals
            </PageLink>
            <PageLink
              to={`/certops/certificates${ctx.workspaceId ? `?workspace=${encodeURIComponent(ctx.workspaceId)}` : ''}`}
            >
              Open Certificate Management
            </PageLink>
          </HStack>
        </Callout>
        <Text fontSize='xs' color={muted} data-testid='adcs-worker-note'>
          {WORKER_NOTE}
        </Text>
      </VStack>
      {issuerOpen ? (
        <AdcsIssuerWizard
          isOpen
          onClose={() => {
            setIssuerOpen(false);
            refreshQuietly();
          }}
          workspaceId={ctx.workspaceId}
          agents={dialogAgents}
          paused={paused}
          onChanged={ctx.refresh}
          initialName={ca.ok ? saved.caName : ''}
          initialAgentId={chosen?.id || ''}
          initialCaConfig={ca.ok ? ca.caConfig : ''}
          initialTemplate={saved.template || ''}
        />
      ) : null}
      {profileOpen ? (
        <AdcsProfileWizard
          isOpen
          onClose={() => {
            setProfileOpen(false);
            refreshQuietly();
          }}
          workspaceId={ctx.workspaceId}
          issuers={issuers}
          onCreated={ctx.refresh}
        />
      ) : null}
    </StepFrame>
  );
}
