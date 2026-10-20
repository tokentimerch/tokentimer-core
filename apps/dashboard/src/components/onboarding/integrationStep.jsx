import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Badge,
  Box,
  HStack,
  Radio,
  RadioGroup,
  SimpleGrid,
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
import ImportTokensModal from '../ImportTokensModal.jsx';
import { INTEGRATIONS } from './modules.js';
import {
  MODE_COPY,
  defaultMode,
  describeSync,
  diffImport,
  providerModes,
  syncFor,
} from './integrationModes.js';

const POLL_MS = 4000;
const POLL_LIMIT_MS = 5 * 60 * 1000;

/**
 * Hosts the existing import modal and keeps watching the server, because what
 * the modal starts does not end when it closes: an auto-sync connection is
 * saved and runs in the background, and a manual import can finish late.
 * Everything shown comes from the server summary, never from the modal.
 */
function useIntegrationHost(ctx, provider) {
  const [open, setOpen] = useState(false);
  const [error, setError] = useState('');
  const [before, setBefore] = useState(null);
  const [result, setResult] = useState(null);
  const [watching, setWatching] = useState(false);
  const startedAt = useRef(0);
  const recorded = useRef(false);

  const start = useCallback(async () => {
    setError('');
    setResult(null);
    recorded.current = false;
    try {
      const summary = await ctx.refresh();
      setBefore(summary);
      startedAt.current = Date.now();
      setOpen(true);
      setWatching(true);
    } catch (e) {
      setError(e.message || 'Could not start.');
    }
  }, [ctx]);

  // While the modal is open or a sync is running, read the server.
  useEffect(() => {
    if (!watching || !before) return undefined;
    let stopped = false;
    const tick = async () => {
      try {
        const now = await ctx.refresh();
        if (stopped || !now) return;
        const diff = diffImport(before, now);
        const running = (now.autoSync?.items || []).some(
          c => c.provider === provider && c.running
        );
        setResult({ ...diff, running });
        const settled =
          !open &&
          !running &&
          (diff.assets > 0 ||
            diff.newConnections.length > 0 ||
            diff.ranSince.length > 0);
        const expired = Date.now() - startedAt.current > POLL_LIMIT_MS;
        if (settled || (!open && expired)) setWatching(false);
      } catch (e) {
        if (!stopped) setError(e.message || 'Could not read the result.');
      }
    };
    tick();
    const t = setInterval(tick, POLL_MS);
    return () => {
      stopped = true;
      clearInterval(t);
    };
  }, [watching, before, open, ctx, provider]);

  const close = useCallback(() => {
    setOpen(false);
    // Keep watching: a manual import may still be finishing and a new
    // connection may be mid-run.
    setWatching(true);
  }, []);

  // Record what arrived once, with its mode, after the server shows it.
  useEffect(() => {
    if (!result || recorded.current) return;
    if (!(result.assets > 0 || result.newConnections.length > 0)) return;
    recorded.current = true;
    ctx.controller
      .update(session => ({
        progress: {
          ...session.progress,
          imported: [
            ...(session.progress?.imported || []).filter(
              i => !(i.step === 'integration' && i.provider === provider)
            ),
            {
              step: 'integration',
              provider,
              count: result.assets,
              mode: result.newConnections.length ? 'sync' : 'once',
              at: new Date().toISOString(),
            },
          ],
        },
      }))
      .then(() => ctx.refresh())
      .catch(() => {});
  }, [result, ctx, provider]);

  return { open, start, close, error, result, watching };
}

function ModeCard({ id, mode, selected, muted }) {
  const copy = MODE_COPY[id];
  const blocked = !mode.available;
  return (
    <Box
      borderWidth='1px'
      borderRadius='md'
      p={3}
      borderColor={selected ? 'blue.400' : undefined}
      opacity={blocked ? 0.6 : 1}
      data-testid={`mode-${id}`}
    >
      <Radio value={id} isDisabled={blocked} size='sm'>
        <Text fontSize='sm' fontWeight='semibold'>
          {copy.label}
        </Text>
      </Radio>
      <Text fontSize='xs' color={muted} mt={1}>
        {copy.summary}
      </Text>
      <Text fontSize='xs' color={muted} mt={1}>
        Needs: {copy.needs}
      </Text>
      {blocked ? (
        <Text fontSize='xs' color='orange.400' mt={1}>
          {mode.blocker?.remediation || 'Not available on this deployment.'}
        </Text>
      ) : null}
    </Box>
  );
}

function SyncList({ items }) {
  const { muted } = useDashboardTheme();
  if (!items.length) return null;
  return (
    <VStack align='stretch' spacing={2} data-testid='sync-list'>
      <Text fontSize='sm' fontWeight='semibold'>
        Connections already saved
      </Text>
      {items.map(c => {
        const d = describeSync(c);
        return (
          <HStack
            key={c.id}
            justify='space-between'
            borderWidth='1px'
            borderRadius='md'
            p={2}
          >
            <Box minW={0}>
              <Text fontSize='sm'>{c.name}</Text>
              <Text fontSize='xs' color={muted}>
                {d.detail || ' '}
              </Text>
            </Box>
            <Badge colorScheme={d.tone}>{d.label}</Badge>
          </HStack>
        );
      })}
    </VStack>
  );
}

function Outcome({ result, mode, watching, muted }) {
  if (!result) return null;
  const parts = [];
  if (result.assets > 0)
    parts.push(
      `${result.assets} asset${result.assets === 1 ? '' : 's'} added to this workspace.`
    );
  result.newConnections.forEach(c =>
    parts.push(`Connection "${c.name}" saved and scheduled ${c.frequency}.`)
  );
  if (result.running)
    parts.push('A scan is running now. This updates by itself.');
  if (!parts.length) {
    return (
      <Text fontSize='sm' color={muted} data-testid='outcome'>
        {watching
          ? 'Waiting for the server to report a result...'
          : mode === 'sync'
            ? 'No connection was saved. If you closed the dialog early, start again.'
            : 'Nothing new was added. If the assets already existed they were left as they were.'}
      </Text>
    );
  }
  return (
    <VStack align='start' spacing={1} data-testid='outcome'>
      {parts.map(p => (
        <Text key={p} fontSize='sm'>
          {p}
        </Text>
      ))}
    </VStack>
  );
}

export function IntegrationStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const [provider, setProvider] = useState(ctx.session.intent?.provider || '');
  const [mode, setMode] = useState('');
  const host = useIntegrationHost(ctx, provider);

  const modes = provider ? providerModes(ctx.capabilities, provider) : null;
  useEffect(() => {
    if (modes && !mode) setMode(defaultMode(modes));
  }, [modes, mode]);

  const choose = id => {
    setProvider(id);
    setMode('');
  };

  const begin = async () => {
    await ctx.controller.update(session => ({
      intent: { ...session.intent, provider },
    }));
    await host.start();
  };

  const existing = provider ? syncFor(ctx.summary, provider) : [];
  const providerIds = Object.keys(INTEGRATIONS);
  const usable = modes && modes[mode]?.available;

  return (
    <StepFrame
      kind='ui'
      title='Connect a service'
      description='Pick a service, then decide whether to import once or keep it in sync. Both use the same scan and preview; they differ in what is kept afterwards.'
      docs={[
        ...ctx.docs('integrations.overview', 'How integrations work'),
        ...(provider
          ? ctx.docs(
              `integrations.${provider}`,
              `${INTEGRATIONS[provider]?.label} permissions`
            )
          : []),
      ]}
      actions={
        <>
          <DashboardActionButton
            variant='outline'
            onClick={() => ctx.skip('integration')}
          >
            Skip for now
          </DashboardActionButton>
          <PrimaryButton onClick={begin} isDisabled={!provider || !usable}>
            {mode === 'sync' ? 'Connect and keep in sync' : 'Scan and import'}
          </PrimaryButton>
        </>
      }
    >
      <VStack align='stretch' spacing={4}>
        {host.error ? (
          <DashboardErrorAlert>{host.error}</DashboardErrorAlert>
        ) : null}

        <Box>
          <Text fontSize='sm' fontWeight='semibold' mb={2}>
            Service
          </Text>
          <SimpleGrid columns={{ base: 1, sm: 2 }} spacing={2}>
            {providerIds.map(id => {
              const m = providerModes(ctx.capabilities, id);
              const selected = provider === id;
              return (
                <Box
                  as='button'
                  type='button'
                  key={id}
                  onClick={() => m.once.available && choose(id)}
                  textAlign='left'
                  borderWidth='1px'
                  borderRadius='md'
                  p={2}
                  borderColor={selected ? 'blue.400' : undefined}
                  opacity={m.once.available ? 1 : 0.5}
                  aria-pressed={selected}
                  aria-label={INTEGRATIONS[id].label}
                >
                  <HStack justify='space-between'>
                    <Text fontSize='sm' fontWeight='semibold'>
                      {INTEGRATIONS[id].label}
                    </Text>
                    {m.sync ? (
                      <Badge colorScheme='purple'>Can sync</Badge>
                    ) : (
                      <Badge>Import only</Badge>
                    )}
                  </HStack>
                  <Text fontSize='xs' color={muted}>
                    {INTEGRATIONS[id].hint}
                  </Text>
                </Box>
              );
            })}
          </SimpleGrid>
        </Box>

        {modes ? (
          <Box>
            <Text fontSize='sm' fontWeight='semibold' mb={2}>
              What should happen
            </Text>
            <RadioGroup value={mode} onChange={setMode}>
              <SimpleGrid
                columns={{ base: 1, md: modes.sync ? 2 : 1 }}
                spacing={2}
              >
                <ModeCard
                  id='once'
                  mode={modes.once}
                  selected={mode === 'once'}
                  muted={muted}
                />
                {modes.sync ? (
                  <ModeCard
                    id='sync'
                    mode={modes.sync}
                    selected={mode === 'sync'}
                    muted={muted}
                  />
                ) : null}
              </SimpleGrid>
            </RadioGroup>
            {!modes.sync ? (
              <Text fontSize='xs' color={muted} mt={2}>
                {INTEGRATIONS[provider].label} supports one-time import only on
                this deployment.
              </Text>
            ) : null}
          </Box>
        ) : null}

        <SyncList items={existing} />
        <Outcome
          result={host.result}
          mode={mode}
          watching={host.watching}
          muted={muted}
        />
      </VStack>

      <ImportTokensModal
        isOpen={host.open}
        onClose={host.close}
        onImported={() => {}}
        openRequest={host.open ? { provider } : null}
        onOpenRequestHandled={() => {}}
      />
    </StepFrame>
  );
}
