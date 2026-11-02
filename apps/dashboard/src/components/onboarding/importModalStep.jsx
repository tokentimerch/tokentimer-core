import { useCallback, useEffect, useRef, useState } from 'react';
import { Text, VStack } from '@chakra-ui/react';
import { DashboardActionButton } from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';
import ImportTokensModal from '../ImportTokensModal.jsx';
import { STEP_DEFS } from './modules.js';

// Import dialog settings per step. File opens on the File source; the
// integration step hides File and Certificate (PEM), which belong to other goals.
export const IMPORT_MODAL_PROPS = {
  file_import: { initialSource: 'file' },
  integration: { hiddenSources: ['file', 'cert-pem'] },
};

const COPY = {
  file_import: {
    description:
      'The import dialog opens on File. Upload a CSV, spreadsheet, JSON or YAML file and review every row before anything is created.',
    docs: [['tokens.import', 'File format and columns']],
    reopen: 'Open the import dialog',
  },
  integration: {
    description:
      'The import dialog lists your services. Scan one, choose what to bring in, and optionally keep it in sync on a schedule.',
    docs: [['integrations.overview', 'How integrations work']],
    reopen: 'Open the import dialog',
  },
};

/**
 * Runs an import goal through the regular import dialog. The dialog is the
 * same component the dashboard uses; only its props differ. The step is done
 * when an import succeeded, which is recorded in the session and checked
 * against the real asset count by the planner.
 */
export function ImportModalStep({ ctx, stepId, reviewing = false }) {
  const { muted } = useDashboardTheme();
  const copy = COPY[stepId];
  const [open, setOpen] = useState(!reviewing);
  const [imported, setImported] = useState(0);
  const ctxRef = useRef(ctx);
  ctxRef.current = ctx;

  const onImported = useCallback(
    async rows => {
      const count = Array.isArray(rows) ? rows.length : 0;
      if (count === 0) return;
      setImported(n => n + count);
      try {
        await ctxRef.current.controller.update(session => ({
          progress: {
            ...session.progress,
            imported: [
              ...(session.progress?.imported || []).filter(
                i => i.step !== stepId
              ),
              {
                step: stepId,
                provider: null,
                count:
                  count +
                  (session.progress?.imported || [])
                    .filter(i => i.step === stepId)
                    .reduce((sum, i) => sum + (i.count || 0), 0),
                at: new Date().toISOString(),
              },
            ],
          },
        }));
        await ctxRef.current.refresh();
      } catch (_) {
        // The count above still shows; the planner re-checks against the server.
      }
    },
    [stepId]
  );

  const done = imported > 0;
  // Keep the finished step on screen until the person chooses to continue,
  // so the dialog is never pulled away mid-flow.
  useEffect(() => {
    if (done && !reviewing) ctxRef.current.hold?.(stepId);
  }, [done, reviewing, stepId]);

  return (
    <StepFrame
      kind='ui'
      title={STEP_DEFS[stepId].title}
      description={copy.description}
      docs={copy.docs.flatMap(([key, label]) => ctx.docs(key, label))}
      actions={
        <>
          {reviewing ? null : (
            <DashboardActionButton
              variant='outline'
              onClick={() => ctx.skip(stepId)}
            >
              Skip for now
            </DashboardActionButton>
          )}
          <DashboardActionButton
            variant='outline'
            onClick={() => setOpen(true)}
          >
            {copy.reopen}
          </DashboardActionButton>
          {reviewing ? null : (
            <PrimaryButton
              onClick={() => ctx.release?.()}
              isDisabled={!done}
              data-testid='import-continue'
            >
              Continue
            </PrimaryButton>
          )}
        </>
      }
    >
      <VStack align='stretch' spacing={2}>
        {done ? (
          <Text fontSize='sm' data-testid='import-done'>
            {imported} asset{imported === 1 ? '' : 's'} imported in this
            session. You can import more or continue.
          </Text>
        ) : (
          <Text fontSize='sm' color={muted}>
            Nothing imported yet. Close the dialog any time and reopen it with
            the button below.
          </Text>
        )}
      </VStack>
      <ImportTokensModal
        hideDocs
        embeddedWorkspaceId={ctx.workspaceId}
        {...IMPORT_MODAL_PROPS[stepId]}
        isOpen={open}
        onClose={() => setOpen(false)}
        onImported={onImported}
        openRequest={null}
        onOpenRequestHandled={() => {}}
      />
    </StepFrame>
  );
}

export const FileImportModalStep = props => (
  <ImportModalStep stepId='file_import' {...props} />
);

export const IntegrationModalStep = props => (
  <ImportModalStep stepId='integration' {...props} />
);
