import { useCallback, useState } from 'react';
import { Box, Code, Text, VStack } from '@chakra-ui/react';
import {
  DashboardActionButton,
  DashboardErrorAlert,
} from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';
import ImportTokensModal from '../ImportTokensModal.jsx';

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

// The file goal stays on the file source; other sources belong to other goals.
const FILE_SOURCES = ['file'];

// The repo ships no sample file, so the header row is shown inline.
const FILE_EXAMPLE =
  'name,category,type,expiresAt,location\nProduction API key,key_secret,api_key,2030-01-31,vault/prod';

export function FileImportStep({ ctx, reviewing = false }) {
  const { muted } = useDashboardTheme();
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
          {reviewing ? null : (
            <DashboardActionButton
              variant='outline'
              onClick={() => ctx.skip('file_import')}
            >
              Skip for now
            </DashboardActionButton>
          )}
          <PrimaryButton onClick={host.start}>Choose a file</PrimaryButton>
        </>
      }
    >
      <VStack align='stretch' spacing={3}>
        {host.error ? (
          <DashboardErrorAlert>{host.error}</DashboardErrorAlert>
        ) : null}
        <Text fontSize='sm'>
          Required fields per row: name, category, type, expiresAt. Dates look
          like 2030-01-31. Rows missing any of them are left out of the preview,
          so compare the preview count with your file. Importing the same file
          again updates existing rows instead of duplicating them when a
          location is present.
        </Text>
        <Box>
          <Text fontSize='xs' color={muted} mb={1}>
            Example CSV (header row, then one asset). Category is cert,
            key_secret, license or general.
          </Text>
          <Code
            display='block'
            whiteSpace='pre'
            overflowX='auto'
            p={2}
            borderRadius='md'
            fontSize='xs'
            data-testid='csv-example'
          >
            {FILE_EXAMPLE}
          </Code>
        </Box>
        <ImportOutcome outcome={host.outcome} />
      </VStack>
      <ImportTokensModal
        hideDocs
        sourceChoices={FILE_SOURCES}
        isOpen={host.open}
        onClose={host.close}
        onImported={() => {}}
        openRequest={host.open ? { provider: 'file' } : null}
        onOpenRequestHandled={() => {}}
      />
    </StepFrame>
  );
}

export { IntegrationStep } from './integrationStep.jsx';
