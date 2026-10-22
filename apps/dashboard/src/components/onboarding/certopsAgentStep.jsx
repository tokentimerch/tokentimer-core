import { useCallback, useEffect, useRef, useState } from 'react';
import { FiRefreshCw } from 'react-icons/fi';
import {
  Flex,
  FormControl,
  FormLabel,
  HStack,
  Input,
  Text,
  VisuallyHidden,
  VStack,
} from '@chakra-ui/react';
import {
  DashboardActionButton,
  DashboardErrorAlert,
} from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame, { DocsLink } from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';
import { CopyBlock, ErrorText, WarnText } from './blocks.jsx';
import {
  INFRASTRUCTURES,
  capabilityGap,
  commandProfileFor,
} from './certopsMatrix.js';
import {
  registrationNotesFor,
  buildControllerSecretCommand,
  buildControllerOnlyValues,
  buildControllerUpgradeCommand,
  buildControllerValues,
  buildInstallCommand,
  buildPackageCommand,
  agentConfigPathFor,
  agentRestartCommandFor,
  installerOptionsFor,
  installerOptionsKey,
  isLoopbackHttp,
} from './certopsConfig.js';
import {
  certopsObjectiveFor,
  certopsProgress,
  saveCertops,
} from './certopsSetupSteps.jsx';
import { createBootstrapToken } from '../certops/certopsAgentsApi.js';
import AgentCheckIn from './AgentCheckIn.jsx';
import { JobTimelineList } from './JobActivity.jsx';
import { Callout, StatusPanel, StatusTag } from './panels.jsx';

const POLL_MS = 5000;

function agentsSummaryControllers(ctx) {
  const certops = ctx.summary?.certops;
  return certops && certops !== 'unknown' ? certops.controllers?.clusters : [];
}

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

/** One numbered instruction with the block it refers to right under it. */
function InstallStep({ n, text, children }) {
  const { border, muted } = useDashboardTheme();
  return (
    <Flex gap={3} align='flex-start'>
      <Flex
        aria-hidden
        flexShrink={0}
        w='24px'
        h='24px'
        mt='1px'
        borderRadius='full'
        borderWidth='2px'
        borderColor={border}
        align='center'
        justify='center'
        fontSize='xs'
        fontWeight='bold'
        color={muted}
        _light={{ color: muted }}
      >
        {n}
      </Flex>
      <VStack align='stretch' spacing={2} flex='1' minW={0}>
        <Text fontSize='sm'>
          <VisuallyHidden>{n}. </VisuallyHidden>
          {text}
        </Text>
        {children}
      </VStack>
    </Flex>
  );
}

export function AgentStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const saved = certopsProgress(ctx);
  const infra = saved.infrastructure || 'linux';
  const os = INFRASTRUCTURES[infra]?.platform === 'win32' ? 'windows' : 'linux';
  const notes = registrationNotesFor(os);
  const configPath = agentConfigPathFor(os);
  const [token, setToken] = useState(null); // shown once, never persisted
  const [clusterId, setClusterId] = useState(saved.clusterId || '');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [deferred, setDeferred] = useState(false);
  const timer = useRef(null);

  // A token belongs to the setup it was made for. Switching goals in the same
  // page must not keep showing a used token or a disabled button.
  useEffect(() => {
    setToken(null);
    setDeferred(false);
  }, [saved.objective, infra]);

  const agents = ctx.summary?.certops?.agents;
  const items = agents?.items || [];
  const target =
    items.find(a => a.platform === (os === 'windows' ? 'win32' : 'linux')) ||
    items[0];

  // Only Linux issuing needs installer options (the Vault issuer publishes to
  // Vault and writes no certificate file).
  const installerOptions = installerOptionsFor({
    objective: saved.objective,
    infrastructure: infra,
    certPath: saved.certPath,
    reloadService: saved.reloadService,
  });
  const neededKey = installerOptionsKey(installerOptions);
  // The agent was installed with other options than this setup needs: the
  // installer has to run again, and only the operator can say it did.
  const needsRerun =
    Boolean(target) && Boolean(neededKey) && saved.installerKey !== neededKey;

  const issueToken = async () => {
    setBusy(true);
    setError('');
    try {
      const expiresAt = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
      const res = await createBootstrapToken(ctx.workspaceId, {
        name: `Setup guide ${new Date().toISOString().slice(0, 16)}`,
        expiresAt,
      });
      setToken({ plaintext: res.plaintextToken, expiresAt });
      await saveCertops(ctx, {
        tokenCreatedAt: new Date().toISOString(),
        // A first install runs the command shown here. With an agent already
        // registered, the operator confirms the second run explicitly.
        ...(target ? {} : { installerKey: neededKey }),
      });
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

  const confirmRerun = async () => {
    setError('');
    try {
      await saveCertops(ctx, { installerKey: neededKey });
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
  const clusterReported = (agentsSummaryControllers(ctx) || []).some(
    c => !clusterId || c.clusterId === clusterId
  );
  useEffect(() => {
    // The controller is not an agent: keep watching until it has reported.
    const settled = infra === 'kubernetes' ? clusterReported : usableAgent;
    if (settled) return undefined;
    timer.current = setInterval(poll, POLL_MS);
    return () => clearInterval(timer.current);
  }, [poll, infra, usableAgent, clusterReported]);

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
            onClick={() => saveCertops(ctx, { clusterId })}
          >
            I installed it
          </PrimaryButton>
        }
      >
        <VStack align='stretch' spacing={3}>
          <FormControl>
            <FormLabel fontSize='sm'>1. Choose a cluster id</FormLabel>
            <Input
              size='sm'
              aria-label='Cluster id'
              placeholder='prod-eu'
              value={clusterId}
              onChange={e => setClusterId(e.target.value)}
            />
          </FormControl>
          {valuesError ? <ErrorText>{valuesError}</ErrorText> : null}
          <Text fontSize='sm'>
            2. Create a machine token: in Certificate Management, open Settings
            and add a token with the scope{' '}
            <code>certops:observations:write</code> and that same cluster id
            (the token is bound to it). Then store it in the cluster:
          </Text>
          <CopyBlock
            label='Create the secret (token read from stdin)'
            text={buildControllerSecretCommand({})}
          />
          {values ? (
            <>
              <Text fontSize='sm'>
                3. Save these values as controller-values.yaml, then upgrade
                your TokenTimer Helm release with them, in the same namespace.
                cert-manager must already be installed in the cluster.
              </Text>
              <CopyBlock label='Helm values' text={values} />
              <Text fontSize='sm'>
                If this cluster does not run TokenTimer, add these lines to the
                same file too. The chart otherwise installs the whole
                application and asks for an admin email and a database, and only
                the controller is wanted here.
              </Text>
              <CopyBlock
                label='Only if the cluster has no TokenTimer release'
                text={buildControllerOnlyValues()}
              />
              <CopyBlock
                label='Apply the values'
                text={buildControllerUpgradeCommand({})}
              />
              {isLoopbackHttp(ctx.apiUrl) ? (
                <Text fontSize='xs' color={muted}>
                  This API address is localhost, which a pod cannot reach. Use
                  an address the cluster can resolve for api.url.
                </Text>
              ) : null}
            </>
          ) : null}
          <VStack align='stretch' spacing={2} data-testid='controller-status'>
            <HStack>
              <Text as='h3' fontSize='sm' fontWeight='semibold'>
                Controller status
              </Text>
              {clusterReported ? (
                <StatusTag tone='green'>Reporting</StatusTag>
              ) : (
                <StatusTag>Waiting for the controller</StatusTag>
              )}
            </HStack>
            <JobTimelineList
              label='Controller timeline'
              events={(agentsSummaryControllers(ctx) || [])
                .filter(c => !clusterId || c.clusterId === clusterId)
                .filter(c => c.lastReportedAt)
                .map(c => ({
                  id: `cluster-${c.clusterId}`,
                  at: c.lastReportedAt,
                  label: `Last report from cluster ${c.clusterId}`,
                  status: 'done',
                }))}
            />
          </VStack>
          <Text fontSize='xs' color={muted}>
            {clusterReported
              ? 'The controller has reported certificates from this cluster.'
              : 'This page checks every few seconds and turns to Reporting once the controller sends its first cert-manager Certificate, so the cluster needs at least one. If it stays empty, read the controller pod logs and confirm the token is bound to this cluster id.'}
          </Text>
        </VStack>
      </StepFrame>
    );
  }

  let command = '';
  let commandError = '';
  // The hardened service can only write where --write-path says and reload
  // only what --reload-service allows, so the choices made in the
  // configuration step have to reach the installer.
  try {
    command = buildInstallCommand({
      os,
      apiUrl: ctx.apiUrl,
      workspaceId: ctx.workspaceId,
      writePaths: installerOptions.writePaths,
      reloadServices: installerOptions.reloadServices,
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
          <StatusPanel status='info' title='Saved' testId='install-later'>
            <VStack align='start' spacing={2}>
              <Text fontSize='sm'>
                Saved. This step stays open until a suitable agent connects. To
                come back, use the setup banner on Certificate Management (shown
                while nothing is set up there) or Preferences, Setup guide, Open
                setup guide.
              </Text>
              {ctx.leaveGuide ? (
                <DashboardActionButton size='sm' onClick={ctx.leaveGuide}>
                  Go to Certificate Management
                </DashboardActionButton>
              ) : null}
            </VStack>
          </StatusPanel>
        ) : saved.agentLaterAt ? (
          <Text fontSize='xs' color={muted}>
            You paused here earlier. This page keeps watching for the agent.
          </Text>
        ) : null}
        {needsRerun ? (
          <StatusPanel
            status='warning'
            title='Run the installer again'
            testId='reinstall-needed'
          >
            <VStack align='start' spacing={2}>
              <Text fontSize='sm'>
                This goal needs different installer options. Run the command
                below again on the server. The installer asks for a bootstrap
                token again: create another one with the button at the bottom of
                this card.
              </Text>
              <DashboardActionButton size='sm' onClick={confirmRerun}>
                I ran the command again
              </DashboardActionButton>
            </VStack>
          </StatusPanel>
        ) : null}
        {certopsObjectiveFor(ctx) === 'adcs' ? (
          <StatusPanel
            status='info'
            title='Where to install it'
            testId='adcs-host-note'
          >
            Install the agent on a domain-joined Windows Server member that can
            reach your CA. A domain controller is not supported.
          </StatusPanel>
        ) : null}
        {os === 'linux' && ['automate', 'vault'].includes(saved.objective) ? (
          <Callout kind='before' title='Install certbot first'>
            <Text fontSize='sm' data-testid='certbot-note'>
              The agent places orders with /usr/bin/certbot on the issuing
              server, so install it first (for example sudo apt install
              certbot).
            </Text>
          </Callout>
        ) : null}
        {isLoopbackHttp(ctx.apiUrl) ? (
          <StatusPanel
            status='warning'
            title='This address is localhost'
            testId='loopback-note'
          >
            This API address is localhost, so it only works when the agent runs
            on this same machine. For a server elsewhere, open the dashboard
            through the address that server can reach.
          </StatusPanel>
        ) : null}
        <VStack align='stretch' spacing={3} data-testid='install-steps'>
          <InstallStep n={1} text={notes[0]}>
            <CopyBlock
              label='Download, verify and extract the agent package (replace <version>)'
              text={buildPackageCommand(os)}
            />
            <HStack data-testid='package-doc-links'>
              {ctx
                .docs('certops.agentPackage', 'Where to get the package')
                .map(link => (
                  <DocsLink key={link.url} href={link.url}>
                    {link.label}
                  </DocsLink>
                ))}
            </HStack>
          </InstallStep>
          <InstallStep n={2} text={notes[1]} />
          <InstallStep
            n={3}
            text='Create a one-time bootstrap token with the button at the bottom of this card. It is shown once and expires in 24 hours. If you lose it or it expires, create another.'
          >
            {token ? (
              <CopyBlock
                label='One-time bootstrap token'
                text={token.plaintext}
                allowSecret
              />
            ) : null}
          </InstallStep>
          <InstallStep n={4} text={notes[2]}>
            {commandError ? (
              <DashboardErrorAlert>{commandError}</DashboardErrorAlert>
            ) : (
              <CopyBlock
                label='Install command (run as administrator)'
                text={command}
              />
            )}
          </InstallStep>
          <InstallStep n={5} text={notes[3]} />
          <Text fontSize='xs' color={muted} data-testid='keep-config-note'>
            The installer keeps a config.json that already exists ({configPath}
            ), so the file you saved in the previous step stays as it is.
          </Text>
          {notes.slice(4).map(n => (
            <Text key={n} fontSize='xs' color={muted}>
              {n}
            </Text>
          ))}
        </VStack>
        <HStack>
          <Text as='h3' fontSize='sm' fontWeight='semibold'>
            Agent status
          </Text>
          {!target ? (
            <StatusTag>Waiting for an agent</StatusTag>
          ) : healthy ? (
            <StatusTag tone='green'>Connected</StatusTag>
          ) : (
            <StatusTag tone='orange'>Needs attention</StatusTag>
          )}
        </HStack>
        {target ? (
          <VStack align='stretch' spacing={2}>
            <Text fontSize='sm'>
              {target.hostname || target.name} ({target.platform}, version{' '}
              {target.agentVersion})
            </Text>
            <AgentCheckIn workspaceId={ctx.workspaceId} agent={target} />
            {lacksProfile ? (
              <WarnText data-testid='lacks-profile-note'>
                This agent has not reported the {wantedProfileName} command
                profile yet, usually because it was set up for discovery only.
                Save the configuration above on the server, keeping the agentId
                line already in config.json, then restart the agent with{' '}
                {agentRestartCommandFor(os)}. The agent publishes its command
                profiles when it checks in, so it does not need to register
                again. An older agent build reports them only when it registers:
                upgrade it, or create a one-time token, register it again and
                retire the old entry in Certificate Management.
              </WarnText>
            ) : null}
            {verdict.problems.map(p => (
              <WarnText key={p}>{p}</WarnText>
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
