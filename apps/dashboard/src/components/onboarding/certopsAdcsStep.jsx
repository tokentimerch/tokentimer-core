import { useEffect, useState } from 'react';
import { FiRefreshCw } from 'react-icons/fi';
import { Link as RouterLink, useInRouterContext } from 'react-router';
import { HStack, Text, VStack } from '@chakra-ui/react';
import { DashboardActionButton } from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';
import { certopsProgress, saveCertops } from './certopsSetupSteps.jsx';
import { WAIT_POLL_MS, useSummaryPolling } from './useSummaryPolling.js';
import { chooseIssuer } from './certopsScope.js';
import { CopyBlock } from './blocks.jsx';
import { agentConfigPathFor, agentRestartCommandFor } from './certopsConfig.js';
import ExistingIssuerPick, { reusableIssuers } from './ExistingIssuerPick.jsx';
import { agentOnPlatform, pickSetupAgent } from './certopsMatrix.js';
import {
  ADCS_REAL_ENROLLMENT_BLOCK,
  adcsFailureAdvice,
  adcsIssuerState,
  buildCaConfig,
  issuerNeedsRecheck,
  scopeAdcs,
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
import { adcsRecheckLink } from '../certops/adcsIssuerLink.js';
import AdcsPostPinCheck from './AdcsPostPinCheck.jsx';

/**
 * Status of the part of AD CS setup the server can see. Enrollment itself
 * needs a real CA, so it is never reported as working from here.
 */
export function adcsStatus({ adcs, agentDeclares }) {
  const issuers = adcs?.issuers || [];
  const confirmed = issuers.filter(
    i => i.confirmed && i.safe && !issuerNeedsRecheck(i)
  );
  return {
    agent: Boolean(agentDeclares),
    issuer: confirmed.length > 0,
    unsafe: issuers.filter(i => i.confirmed === false && i.safe === false),
    profile: (adcs?.profiles || 0) > 0,
    // Whether a profile of these issuers is attached to a certificate. Null
    // when the server does not say, so nothing is claimed either way.
    attached: typeof adcs?.attached === 'number' ? adcs.attached > 0 : null,
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
    'Ask a workspace manager or owner to complete this step.'
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
    <DashboardActionButton
      as={RouterLink}
      to={to}
      variant='outline'
      size='sm'
      mt={2}
    >
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
  workspaceId,
  agent,
  onChanged,
}) {
  const { muted } = useDashboardTheme();
  if (ready) {
    const i = state.issuer;
    const pair =
      i.caConfig && i.template ? `${i.caConfig}, template ${i.template}` : '';
    return (
      <VStack align='stretch' spacing={3}>
        <Text fontSize='sm' data-testid='adcs-issuer-ready'>
          {i.name} passed the CA check and its CA certificate is pinned.
          {pair ? ` ${pair}.` : ''}
        </Text>
        {issuerNeedsRecheck(i) ? (
          <AdcsPostPinCheck
            key={`${workspaceId}:${i.id}:${agent?.id || ''}`}
            workspaceId={workspaceId}
            issuer={i}
            agent={agent}
            disabledReason={disabledReason}
            onChanged={onChanged}
          />
        ) : null}
      </VStack>
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
          the dialog, or open it in Renewals, run Check again and choose Use
          this certificate.
          <PageLink
            to={adcsRecheckLink({
              workspaceId,
              issuerId: state.issuer.id,
            })}
          >
            Open {state.issuer.name} in Renewals
          </PageLink>
        </StatusPanel>
      ) : null}
      <Callout
        kind='before'
        title='Have these ready'
        items={[
          ca.ok
            ? `CA: ${ca.caConfig}`
            : 'CA: the server name and CA name from the Certification Authority console',
          `Template: ${saved.template || 'WebServer'} (common name)`,
          `Agent: ${agentName || 'the Windows agent from the previous step'}, joined to the domain (not a domain controller), with adcs-enroll-v1, an enrollment rule for that CA and template, and Enroll on the template for its computer account`,
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
  // Only an issuer made in this session counts, or the one the operator
  // chose with "My Microsoft CA issuer is already set up".
  const chosenIssuerId = saved.chosenIssuerId || '';
  const adcs = scopeAdcs(certops?.adcs, chosenIssuerId);
  const status = adcsStatus({
    adcs,
    agentDeclares: agents.some(
      a =>
        a.livenessState === 'live' &&
        (a.declaredCapabilities || []).includes('adcs-enroll-v1')
    ),
  });
  const reusable = reusableIssuers(certops?.adcs);
  const [reuseTicked, setReuseTicked] = useState(Boolean(chosenIssuerId));
  const [choiceError, setChoiceError] = useState('');
  const state = adcsIssuerState(adcs);
  const [checking, setChecking] = useState(false);
  const [issuerOpen, setIssuerOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [issuers, setIssuers] = useState([]);
  const [paused, setPaused] = useState(false);
  const ca = buildCaConfig(saved.caHost, saved.caName);
  const blocker = adcsBlocker(ctx.capabilities);
  // The agent from the earlier steps: the one that serves AD CS, or the
  // Windows agent whose gap the first row explains.
  const chosen = pickSetupAgent(agents, 'adcs', 'windows', saved.chosenAgentId);
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

  // The agent, the CA check and the attachment all show up on the server
  // without a click here: keep reading until every row is done. Dialogs read
  // on their own when they close.
  useSummaryPolling(
    ctx.refresh,
    !issuerOpen &&
      !profileOpen &&
      (!(status.agent && status.issuer && status.profile) ||
        status.attached === false),
    WAIT_POLL_MS
  );
  const check = async () => {
    setChecking(true);
    try {
      await ctx.refresh();
    } finally {
      setChecking(false);
    }
  };
  const refreshQuietly = () => Promise.resolve(ctx.refresh?.()).catch(() => {});

  // Reusing an issuer is the operator's choice; Continue confirms it.
  const saveIssuerChoice = async id => {
    setChoiceError('');
    try {
      await ctx.controller.update(session => ({
        progress: {
          ...session.progress,
          certops: chooseIssuer(session.progress?.certops, 'adcs', id),
        },
      }));
      await ctx.refresh();
    } catch (e) {
      setChoiceError(e.message || 'Could not save your choice.');
    }
  };
  const confirmIssuer = async () => {
    setChoiceError('');
    try {
      await saveCertops(ctx, { chosenIssuerConfirmed: chosenIssuerId });
    } catch (e) {
      setChoiceError(e.message || 'Could not save your progress.');
    }
  };
  const confirmed =
    Boolean(chosenIssuerId) && saved.chosenIssuerConfirmed === chosenIssuerId;
  const scopedIds = new Set((adcs?.issuers || []).map(i => i.id));
  const certificatesPath = `/certops/certificates${ctx.workspaceId ? `?workspace=${encodeURIComponent(ctx.workspaceId)}` : ''}`;

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
        <>
          <DashboardActionButton
            leftIcon={<FiRefreshCw />}
            variant='outline'
            onClick={check}
            isLoading={checking}
          >
            Check again
          </DashboardActionButton>
          {chosenIssuerId && !confirmed ? (
            <PrimaryButton
              onClick={confirmIssuer}
              isDisabled={!(status.issuer && status.profile)}
              data-testid='adcs-use-issuer'
            >
              Continue
            </PrimaryButton>
          ) : null}
        </>
      }
    >
      <VStack align='stretch' spacing={3}>
        <StatusPanel status='info' title='What this guide can see'>
          Add the issuer and the renewal profile below; this guide watches the
          results and checks again every 10 seconds. It cannot verify enrollment
          against your CA: start the first enrollment from Certificate
          Management.
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
          label={
            chosenIssuerId
              ? 'Issuer chosen and CA certificate pinned'
              : 'Issuer created and CA certificate pinned'
          }
        >
          {choiceError ? (
            <StatusPanel status='error' testId='adcs-choice-error'>
              {choiceError}
            </StatusPanel>
          ) : null}
          <ExistingIssuerPick
            issuers={reusable}
            ticked={reuseTicked && reusable.length > 0}
            issuerId={chosenIssuerId}
            onTick={on => {
              setReuseTicked(on);
              if (!on) saveIssuerChoice(null);
            }}
            onIssuer={saveIssuerChoice}
          />
          {!reuseTicked && reusable.length > 0 ? (
            <Text
              fontSize='xs'
              color={muted}
              data-testid='existing-issuers-note'
            >
              {reusable.length === 1
                ? '1 issuer is already in this workspace. Add a new one below, or tick the box to use it.'
                : `${reusable.length} issuers are already in this workspace. Add a new one below, or tick the box to use one.`}
            </Text>
          ) : null}
          <IssuerBody
            workspaceId={ctx.workspaceId}
            state={state}
            ready={state.kind === 'ready'}
            ca={ca}
            saved={saved}
            agentName={agentName}
            disabledReason={issuerDisabled}
            onOpen={() => setIssuerOpen(true)}
            agent={chosen}
            onChanged={ctx.refresh}
          />
        </Row>
        <Row
          n={3}
          done={status.profile}
          label='AD CS renewal profile created'
          hint='Pick the confirmed issuer, the HTTPS binding (IIS site) and the certificate name. The last step of the dialog attaches it to the site certificate.'
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
        {status.profile && status.attached !== null ? (
          <Row
            n={4}
            done={status.attached}
            label='Profile attached to the site certificate'
            hint='The profile dialog attaches it in its last step. If it could not, open the certificate in Certificate Management and attach the profile there. Then watch the first enrollment on that page.'
          >
            {status.attached ? (
              <Text fontSize='sm' data-testid='adcs-attached'>
                Attached. Watch the first enrollment in Certificate Management.
              </Text>
            ) : null}
            <HStack>
              <PageLink to={certificatesPath}>
                Open Certificate Management
              </PageLink>
            </HStack>
          </Row>
        ) : null}
        {status.issuer ? (
          <Callout
            kind='next'
            title='Turn on real enrollment'
            testId='adcs-real-enrollment'
          >
            <VStack align='stretch' spacing={2}>
              <Text fontSize='sm'>
                The agent starts in dry run: the CA check works, but real
                enrollment is refused. Now that the issuer has passed its check,
                merge this into the execution block of{' '}
                <code>{agentConfigPathFor('windows')}</code> and restart the
                agent.
              </Text>
              <CopyBlock
                label='execution block (merge into config.json, do not replace the file)'
                text={ADCS_REAL_ENROLLMENT_BLOCK}
                language='json'
              />
              <CopyBlock
                label='Restart the agent'
                text={agentRestartCommandFor('windows')}
                prompt
              />
            </VStack>
          </Callout>
        ) : null}
        {agentEvents.length > 0 ? (
          <JobTimelineList label='Agent timeline' events={agentEvents} />
        ) : null}
        <Text fontSize='xs' color={muted} data-testid='adcs-worker-note'>
          {WORKER_NOTE}
        </Text>
      </VStack>
      {issuerOpen ? (
        <AdcsIssuerWizard
          isOpen
          setupGuide
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
          issuers={issuers.filter(i => scopedIds.has(i.id))}
          onCreated={ctx.refresh}
        />
      ) : null}
    </StepFrame>
  );
}
