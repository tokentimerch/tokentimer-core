import { useCallback, useEffect, useRef, useState } from 'react';
import { DashboardActionButton } from '../DashboardPrimitives';
import { StatusPanel } from './panels.jsx';
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
  const copy = COPY[stepId];
  const [open, setOpen] = useState(!reviewing);
  const [imported, setImported] = useState(0);
  const [confirmed, setConfirmed] = useState(0);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState('');
  const target = useRef(0);
  const queue = useRef(Promise.resolve());
  const ctxRef = useRef(ctx);
  ctxRef.current = ctx;

  const saveProgress = useCallback(() => {
    setSaving(true);
    const next = queue.current.then(async () => {
      try {
        const summary = await ctxRef.current.refresh();
        const total = summary?.assets?.total;
        if (!Number.isInteger(total) || total < 1)
          throw new Error('missing asset count');
        const requested = target.current;
        const count = Math.min(requested, total);
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
                count: Math.min(
                  total,
                  Math.max(
                    count,
                    (session.progress?.imported || [])
                      .filter(i => i.step === stepId)
                      .reduce((sum, i) => sum + (i.count || 0), 0)
                  )
                ),
                at: new Date().toISOString(),
              },
            ],
          },
        }));
        await ctxRef.current.refresh();
        if (target.current === requested) {
          target.current = count;
          setImported(count);
        }
        setConfirmed(count);
        setSaveError('');
      } catch {
        setSaveError(
          'The import completed, but setup progress could not be confirmed. Retry to continue.'
        );
      }
    });
    queue.current = next;
    next.finally(() => {
      if (queue.current === next) setSaving(false);
    });
    return next;
  }, [stepId]);

  const onImported = useCallback(
    rows => {
      const count = Array.isArray(rows) ? rows.length : 0;
      if (!count) return;
      const saved = (ctxRef.current.session?.progress?.imported || [])
        .filter(item => item.step === stepId)
        .reduce((sum, item) => sum + (item.count || 0), 0);
      target.current = Math.max(target.current, saved) + count;
      setImported(target.current);
      return saveProgress();
    },
    [saveProgress, stepId]
  );

  const savedCount = (ctx.session?.progress?.imported || [])
    .filter(item => item.step === stepId)
    .reduce((sum, item) => sum + (item.count || 0), 0);
  const importedCount = Math.max(imported, savedCount);
  const done = Math.max(confirmed, savedCount) > 0 && !saveError && !saving;
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
      {done ? (
        <StatusPanel
          status='success'
          title='Import complete'
          testId='import-done'
        >
          {importedCount} asset{importedCount === 1 ? '' : 's'} imported in this
          setup. You can import more or continue.
        </StatusPanel>
      ) : (
        <StatusPanel status='info' title='Ready to import'>
          Nothing imported yet. You can reopen the import dialog using the
          button below.
        </StatusPanel>
      )}
      {saveError ? (
        <StatusPanel status='warning' title='Setup progress not confirmed'>
          {saveError}{' '}
          <DashboardActionButton onClick={saveProgress} isLoading={saving}>
            Retry
          </DashboardActionButton>
        </StatusPanel>
      ) : null}
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
