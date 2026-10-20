import { useCallback, useEffect, useRef, useState } from 'react';
import { FiRefreshCw } from 'react-icons/fi';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
  HStack,
  Text,
  VStack,
} from '@chakra-ui/react';
import {
  DashboardActionButton,
  DashboardErrorAlert,
} from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';
import { CopyBlock } from './blocks.jsx';
import {
  INFRASTRUCTURES,
  capabilityGap,
  commandProfileFor,
} from './certopsMatrix.js';
import {
  REGISTRATION_NOTES,
  buildControllerSecretCommand,
  buildControllerValues,
  buildInstallCommand,
} from './certopsConfig.js';
import {
  certopsObjectiveFor,
  certopsProgress,
  saveCertops,
} from './certopsSetupSteps.jsx';
import { createBootstrapToken } from '../certops/certopsAgentsApi.js';

const POLL_MS = 5000;

/** Plain-language reading of one agent row, with the reason when unhealthy. */
export function describeAgent(agent, gap = []) {
  const problems = [];
  if (agent.livenessState !== 'live')
    problems.push('It has not checked in recently.');
  if (agent.compatibilityState && agent.compatibilityState !== 'compatible') {
    problems.push(`Its version is ${agent.compatibilityState}. Upgrade it.`);
  }
  if (
    agent.clockDriftState &&
    !['ok', 'in_sync', 'none'].includes(agent.clockDriftState)
  ) {
    problems.push('Its clock is drifting. Fix time synchronisation (NTP).');
  }
  if (gap.length) problems.push(`Missing capabilities: ${gap.join(', ')}.`);
  return { healthy: problems.length === 0, problems };
}

export function AgentStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const saved = certopsProgress(ctx);
  const infra = saved.infrastructure || 'linux';
  const os = INFRASTRUCTURES[infra]?.platform === 'win32' ? 'windows' : 'linux';
  const [token, setToken] = useState(null); // shown once, never persisted
  const [clusterId, setClusterId] = useState(saved.clusterId || '');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [deferred, setDeferred] = useState(false);
  const timer = useRef(null);

  const agents = ctx.summary?.certops?.agents;
  const items = agents?.items || [];
  const target =
    items.find(a => a.platform === (os === 'windows' ? 'win32' : 'linux')) ||
    items[0];

  const issueToken = async () => {
    setBusy(true);
    setError('');
    try {
      const expiresAt = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
      const res = await createBootstrapToken(ctx.workspaceId, {
        name: `Setup wizard ${new Date().toISOString().slice(0, 16)}`,
        expiresAt,
      });
      setToken({ plaintext: res.plaintextToken, expiresAt });
      await saveCertops(ctx, { tokenCreatedAt: new Date().toISOString() });
    } catch (e) {
      setError(
        e?.response?.data?.error || e.message || 'Could not create a token.'
      );
    } finally {
      setBusy(false);
    }
  };

  // Progress is saved with every step; this records the choice so the step
  // can say so on return. It never counts the step as done.
  const installLater = async () => {
    setError('');
    try {
      await saveCertops(ctx, { agentLaterAt: new Date().toISOString() });
      setDeferred(true);
    } catch (e) {
      setError(e.message || 'Could not save your progress.');
    }
  };

  const poll = useCallback(() => ctx.refresh().catch(() => {}), [ctx]);
  // Same rule as the planner: keep watching until a usable agent exists.
  const wantedProfile = commandProfileFor(saved.objective, infra);
  const usableAgent =
    (agents?.live || 0) > 0 &&
    (!wantedProfile ||
      items.some(
        a =>
          a.livenessState === 'live' &&
          (a.commandProfiles || []).includes(wantedProfile)
      ));
  useEffect(() => {
    if (infra === 'kubernetes' || usableAgent) return undefined;
    timer.current = setInterval(poll, POLL_MS);
    return () => clearInterval(timer.current);
  }, [poll, infra, usableAgent]);

  if (ctx.summary?.certops === 'unknown' || ctx.summary?.certops == null) {
    return (
      <StepFrame
        kind='handoff'
        title='Certificate management is not available'
        description='It is turned off on this deployment, or you do not have permission to see agents.'
        docs={ctx.docs('certops.enable', 'Turning it on')}
      >
        <VStack align='stretch' spacing={2}>
          <Text fontSize='sm'>
            An operator must set CERTOPS_ENABLED and the two encryption keys on
            the API, and run the certificate worker. Workspace managers can then
            install agents.
          </Text>
          <DashboardActionButton
            leftIcon={<FiRefreshCw />}
            variant='outline'
            onClick={poll}
          >
            Check again
          </DashboardActionButton>
        </VStack>
      </StepFrame>
    );
  }

  if (infra === 'kubernetes') {
    let values = '';
    let valuesError = '';
    try {
      values = buildControllerValues({
        apiUrl: ctx.apiUrl,
        workspaceId: ctx.workspaceId,
        clusterId,
      });
    } catch (e) {
      valuesError = clusterId ? e.message : '';
    }
    return (
      <StepFrame
        kind='runbook'
        title='Install the Kubernetes controller'
        description='Observe mode only reads cert-manager resources. It never changes the cluster.'
        docs={ctx.docs('certops.controller', 'Controller install')}
        actions={
          <PrimaryButton
            isDisabled={!values}
            onClick={() =>
              saveCertops(ctx, { clusterId, configReviewed: true })
            }
          >
            I installed it
          </PrimaryButton>
        }
      >
        <VStack align='stretch' spacing={3}>
          <Text fontSize='sm'>
            Create a machine token in Certificate Management, Settings, with the
            observations scope and a cluster id, then store it in the cluster:
          </Text>
          <CopyBlock
            label='Create the secret (token read from stdin)'
            text={buildControllerSecretCommand({})}
          />
          <input
            aria-label='Cluster id'
            placeholder='prod-eu'
            value={clusterId}
            onChange={e => setClusterId(e.target.value)}
          />
          {valuesError ? (
            <Text color='red.400' fontSize='xs'>
              {valuesError}
            </Text>
          ) : null}
          {values ? <CopyBlock label='Helm values' text={values} /> : null}
        </VStack>
      </StepFrame>
    );
  }

  let command = '';
  let commandError = '';
  try {
    command = buildInstallCommand({
      os,
      apiUrl: ctx.apiUrl,
      workspaceId: ctx.workspaceId,
    });
  } catch (e) {
    commandError = e.message;
  }
  const gap = target
    ? capabilityGap(saved.objective, infra, target.declaredCapabilities)
    : [];
  const verdict = target ? describeAgent(target, gap) : null;
  // Automation needs the certbot profile, which is only reported at
  // registration. A discovery-only agent is connected but cannot be used.
  const wantedProfileName = commandProfileFor(saved.objective, infra);
  const lacksProfile =
    Boolean(wantedProfileName) &&
    Boolean(target) &&
    !(target.commandProfiles || []).includes(wantedProfileName);
  const healthy = Boolean(verdict?.healthy) && !lacksProfile;

  return (
    <StepFrame
      kind='runbook'
      title='Install the agent'
      description='Run the command on the server that holds the certificates. This page watches for the agent to appear.'
      docs={[
        ...ctx.docs(
          os === 'windows' ? 'certops.installWindows' : 'certops.installLinux',
          'Full install guide'
        ),
      ]}
      actions={
        <>
          {healthy ? null : (
            <DashboardActionButton variant='outline' onClick={installLater}>
              I will install it later
            </DashboardActionButton>
          )}
          <PrimaryButton
            onClick={issueToken}
            isLoading={busy}
            isDisabled={Boolean(token)}
          >
            {token ? 'Token created' : 'Create a one-time token'}
          </PrimaryButton>
        </>
      }
    >
      <VStack align='stretch' spacing={3}>
        {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
        {deferred ? (
          <Alert status='info' borderRadius='md' data-testid='install-later'>
            <AlertIcon />
            <VStack align='start' spacing={2}>
              <AlertDescription fontSize='sm'>
                Saved. This step stays open until an agent that can do this goal
                connects. To come back, use the setup banner on Certificate
                Management (shown while nothing is set up there), open
                /onboarding?area=certops, or choose Open setup guide in
                Preferences.
              </AlertDescription>
              {ctx.leaveGuide ? (
                <DashboardActionButton size='sm' onClick={ctx.leaveGuide}>
                  Go to Certificate Management
                </DashboardActionButton>
              ) : null}
            </VStack>
          </Alert>
        ) : saved.agentLaterAt ? (
          <Text fontSize='xs' color={muted}>
            You paused here earlier. This page keeps watching for the agent.
          </Text>
        ) : null}
        {certopsObjectiveFor(ctx) === 'adcs' ? (
          <Alert status='info' borderRadius='md' data-testid='adcs-host-note'>
            <AlertIcon />
            <AlertDescription fontSize='sm'>
              Install the agent on a domain-joined Windows Server member that
              can reach your CA. A domain controller is not supported.
            </AlertDescription>
          </Alert>
        ) : null}
        {REGISTRATION_NOTES.map(n => (
          <Text key={n} fontSize='xs' color={muted}>
            {n}
          </Text>
        ))}
        {token ? (
          <>
            <Text fontSize='sm' fontWeight='semibold'>
              Paste this when the installer asks for the token. It is shown only
              once and expires in 24 hours.
            </Text>
            <CopyBlock
              label='One-time bootstrap token'
              text={token.plaintext}
              allowSecret
            />
          </>
        ) : null}
        {commandError ? (
          <DashboardErrorAlert>{commandError}</DashboardErrorAlert>
        ) : (
          <CopyBlock
            label='Install command (run as administrator)'
            text={command}
          />
        )}
        <HStack>
          <Text fontSize='sm' fontWeight='semibold'>
            Agent status
          </Text>
          {!target ? (
            <Badge>Waiting for an agent</Badge>
          ) : healthy ? (
            <Badge colorScheme='green'>Connected</Badge>
          ) : (
            <Badge colorScheme='orange'>Needs attention</Badge>
          )}
        </HStack>
        {target ? (
          <VStack align='stretch' spacing={1}>
            <Text fontSize='sm'>
              {target.hostname || target.name} ({target.platform}, version{' '}
              {target.agentVersion})
            </Text>
            {lacksProfile ? (
              <Text fontSize='xs' color='orange.400'>
                This agent was registered without the {wantedProfileName}{' '}
                command profile, usually because it was set up for discovery
                only. Profiles are reported only when an agent registers, so it
                cannot place orders. Save the configuration above, create a
                one-time token and register the agent again, then retire the old
                entry in Certificate Management.
              </Text>
            ) : null}
            {verdict.problems.map(p => (
              <Text key={p} fontSize='xs' color='orange.400'>
                {p}
              </Text>
            ))}
          </VStack>
        ) : (
          <Text fontSize='xs' color={muted}>
            Nothing has registered yet. Checking every few seconds. If it stays
            empty: check outbound HTTPS to this address, that the token has not
            expired, and the service log.
          </Text>
        )}
      </VStack>
    </StepFrame>
  );
}
