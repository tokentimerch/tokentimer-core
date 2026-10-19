import { useCallback, useEffect, useState } from 'react';
import {
  Badge,
  HStack,
  Radio,
  RadioGroup,
  Stack,
  Text,
  VStack,
} from '@chakra-ui/react';
import {
  DashboardActionButton,
  DashboardErrorAlert,
} from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import ImportTokensModal from '../ImportTokensModal.jsx';
import { INTEGRATIONS } from './modules.js';
import { availableProviders } from './journeyPlanner.js';

/**
 * Hosts the existing import modal. The modal does the scanning, preview,
 * selection and import; the wizard only chooses the source and then proves
 * what arrived by counting assets in the workspace, so a modal that closes
 * early or an import that partly failed is never recorded as done.
 */
function useImportHost(ctx, stepId, provider) {
  const [open, setOpen] = useState(false);
  const [error, setError] = useState('');
  const [baseline, setBaseline] = useState(null);
  const [outcome, setOutcome] = useState(null);

  const start = useCallback(async () => {
    setError('');
    setOutcome(null);
    try {
      const summary = await ctx.refresh();
      setBaseline(summary?.assets?.total ?? 0);
      setOpen(true);
    } catch (e) {
      setError(e.message || 'Could not start the import.');
    }
  }, [ctx]);

  const close = useCallback(async () => {
    setOpen(false);
    try {
      const summary = await ctx.refresh();
      const total = summary?.assets?.total ?? 0;
      const added = Math.max(0, total - (baseline ?? total));
      if (added > 0) {
        // Rescan-safe: the count comes from the server, and the identity of
        // what was imported is held by the server (source identity), so a
        // later rescan cannot import the same assets twice.
        await ctx.controller.update(session => ({
          progress: {
            ...session.progress,
            imported: [
              ...(session.progress?.imported || []).filter(
                i => !(i.step === stepId && i.provider === (provider || null))
              ),
              {
                step: stepId,
                provider: provider || null,
                count: added,
                at: new Date().toISOString(),
              },
            ],
          },
        }));
        await ctx.refresh();
      }
      setOutcome({ added });
    } catch (e) {
      setError(e.message || 'Could not confirm the import.');
    }
  }, [baseline, ctx, provider, stepId]);

  return { open, start, close, error, outcome };
}

function ImportOutcome({ outcome }) {
  const { muted } = useDashboardTheme();
  if (!outcome) return null;
  return outcome.added > 0 ? (
    <Text fontSize='sm'>
      {outcome.added} asset{outcome.added === 1 ? '' : 's'} added to this
      workspace.
    </Text>
  ) : (
    <Text fontSize='sm' color={muted}>
      Nothing new was added. If you cancelled, you can start again. If the
      assets already existed, they were left untouched.
    </Text>
  );
}

export function FileImportStep({ ctx }) {
  const host = useImportHost(ctx, 'file_import', null);
  return (
    <StepFrame
      kind='ui'
      title='Import assets from a file'
      description='Upload a CSV, spreadsheet, JSON or YAML file. You review every row before anything is created.'
      docs={[
        ...ctx.docs('tokens.import', 'File format and columns'),
        ...ctx.docs('tokens.adding', 'Adding assets'),
      ]}
      actions={
        <>
          <DashboardActionButton
            variant='ghost'
            onClick={() => ctx.skip('file_import')}
          >
            Skip for now
          </DashboardActionButton>
          <DashboardActionButton colorScheme='blue' onClick={host.start}>
            Choose a file
          </DashboardActionButton>
        </>
      }
    >
      <VStack align='stretch' spacing={3}>
        {host.error ? (
          <DashboardErrorAlert>{host.error}</DashboardErrorAlert>
        ) : null}
        <Text fontSize='sm'>
          Rows without a name, category, type and expiry date are left out of
          the preview, so compare the preview count with your file. Importing
          the same file again updates existing rows instead of duplicating them
          when a location is present.
        </Text>
        <ImportOutcome outcome={host.outcome} />
      </VStack>
      <ImportTokensModal
        isOpen={host.open}
        onClose={host.close}
        onImported={() => {}}
        openRequest={host.open ? { provider: 'file' } : null}
        onOpenRequestHandled={() => {}}
      />
    </StepFrame>
  );
}

export function IntegrationStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const providers = availableProviders(ctx.capabilities, INTEGRATIONS);
  const [provider, setProvider] = useState(ctx.session.intent?.provider || '');
  const host = useImportHost(ctx, 'integration', provider);

  useEffect(() => {
    if (ctx.session.intent?.provider) setProvider(ctx.session.intent.provider);
  }, [ctx.session.intent?.provider]);

  const begin = async () => {
    await ctx.controller.update(session => ({
      intent: { ...session.intent, provider },
    }));
    await host.start();
  };

  return (
    <StepFrame
      kind='ui'
      title='Import from an integration'
      description='Connect once, preview what was found and pick what to import. Credentials are used for this scan only and are not stored.'
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
            variant='ghost'
            onClick={() => ctx.skip('integration')}
          >
            Skip for now
          </DashboardActionButton>
          <DashboardActionButton
            colorScheme='blue'
            onClick={begin}
            isDisabled={!provider}
          >
            Connect and scan
          </DashboardActionButton>
        </>
      }
    >
      <VStack align='stretch' spacing={3}>
        {host.error ? (
          <DashboardErrorAlert>{host.error}</DashboardErrorAlert>
        ) : null}
        <RadioGroup value={provider} onChange={setProvider}>
          <Stack spacing={2}>
            {providers.map(p => (
              <HStack key={p.id} align='start'>
                <Radio value={p.id} isDisabled={Boolean(p.blocker)}>
                  <Text fontSize='sm' fontWeight='semibold'>
                    {p.label}
                  </Text>
                </Radio>
                <Text fontSize='xs' color={muted}>
                  {p.blocker?.remediation || p.hint}
                </Text>
                {p.blocker ? <Badge>Not available</Badge> : null}
              </HStack>
            ))}
          </Stack>
        </RadioGroup>
        <Text fontSize='xs' color={muted}>
          A scan is read-only. Cleanup of assets that disappeared is off unless
          you turn it on in the preview, and it permanently deletes.
        </Text>
        <ImportOutcome outcome={host.outcome} />
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
