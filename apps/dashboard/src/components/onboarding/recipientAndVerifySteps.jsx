import { useCallback, useEffect, useRef, useState } from 'react';
import { FiRefreshCw } from 'react-icons/fi';
import { Badge, HStack, Link, Spinner, Text, VStack } from '@chakra-ui/react';
import {
  DashboardActionButton,
  DashboardErrorAlert,
} from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';

import { evaluateVerification, CHECK_STATUS } from './verification.js';
import { certopsProgress } from './certopsSetupSteps.jsx';
import { SUMMARY_POLL_MS, verifyNeedsPolling } from './useSummaryPolling.js';
import { existingAssetStepIds } from './assetRefs.js';
import { onboardingActions } from '../../utils/onboardingActions.js';

export { RecipientsStep } from './alertRecipientsStep.jsx';

const CHECK_BADGE = {
  [CHECK_STATUS.PASS]: { label: 'OK', colorScheme: 'green' },
  [CHECK_STATUS.FAIL]: { label: 'Needs attention', colorScheme: 'red' },
  [CHECK_STATUS.WARN]: { label: 'Follow up', colorScheme: 'orange' },
};

export function VerifyStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const [state, setState] = useState({ loading: true });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const goal = ctx.session.intent?.goal;

  const run = useCallback(
    async silent => {
      // A background read must not blank the screen or replace what is shown
      // with an error.
      if (silent !== true) setState(s => ({ ...s, loading: true }));
      try {
        await ctx.refresh();
        const summary = await ctx.fetchSummary();
        const refs = ctx.session.operationRefs || {};
        // Every website created in this session, not only the last batch's
        // first address, so one unreadable site cannot hide behind another.
        const sessionIds = new Set(refs.monitorIds || []);
        const sessionUrl = refs.monitorUrl
          ? String(refs.monitorUrl).toLowerCase()
          : null;
        const monitors =
          goal === 'monitor_https'
            ? summary.monitors.items.filter(
                m =>
                  sessionIds.has(m.id) ||
                  (sessionUrl && m.url?.toLowerCase() === sessionUrl)
              )
            : [];
        // The summary lists a limited number of monitors; say so rather than
        // silently skipping the rest.
        const listedIds = new Set(monitors.map(m => m.id));
        const unlistedMonitors =
          goal === 'monitor_https'
            ? (summary.references?.monitorIds?.existing || []).filter(
                id => !listedIds.has(id)
              ).length
            : 0;
        const tokenId =
          monitors.find(m => m.certificateExpiresAt && m.tokenId)?.tokenId ||
          monitors.find(m => m.tokenId)?.tokenId ||
          (goal === 'track_asset'
            ? existingAssetStepIds(refs, summary.references)
            : summary.references.tokenIds.existing || [])[0] ||
          null;
        let token = tokenId ? await onboardingActions.getToken(tokenId) : null;
        // Imports and discovery return no ids. Sample the asset closest to
        // expiry, which is the one most likely to alert first, and use the
        // list row's own alert state so one request is enough. The asset goal
        // checks the asset it created, unless the person skipped that step.
        const skippedAsset = (ctx.session.progress?.skipped || []).includes(
          'asset'
        );
        if (
          !token &&
          (goal !== 'track_asset' || skippedAsset) &&
          (summary.assets?.total || 0) > 0
        ) {
          token = await onboardingActions.soonestToken(ctx.workspaceId);
        }
        const certopsSaved = certopsProgress(ctx);
        setState({
          loading: false,
          result: evaluateVerification({
            goal,
            monitors,
            unlistedMonitors,
            token,
            summary,
            infrastructure: certopsSaved.infrastructure,
            clusterId: certopsSaved.clusterId,
            agentId: certopsSaved.chosenAgentId,
            issuerId: certopsSaved.chosenIssuerId,
          }),
        });
      } catch (e) {
        if (silent !== true) setState({ loading: false, error: e.message });
      }
    },
    [ctx, goal]
  );

  useEffect(() => {
    run();
    // Only on mount: the user re-checks explicitly.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Newest run without restarting the timer on every render.
  const runRef = useRef(run);
  runRef.current = run;
  const polling = verifyNeedsPolling(state.result);
  useEffect(() => {
    if (!polling) return undefined;
    const timer = setInterval(() => {
      if (typeof document === 'undefined' || !document.hidden) {
        runRef.current(true);
      }
    }, SUMMARY_POLL_MS);
    return () => clearInterval(timer);
  }, [polling]);

  const finish = async () => {
    setBusy(true);
    setError('');
    try {
      await ctx.controller.update(session => ({
        progress: { ...session.progress, verified: true },
        status: 'completed',
      }));
      await ctx.refresh();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const { result } = state;
  return (
    <StepFrame
      kind='verify'
      title='Check that it is working'
      description='These checks read the real state of your workspace. They do not send an alert.'
      docs={[
        ...ctx.docs('quickstart.verifyAlert', 'Verifying an alert'),
        ...ctx.docs('alerts.troubleshooting', 'If alerts do not arrive'),
      ]}
      actions={
        <>
          <DashboardActionButton
            leftIcon={<FiRefreshCw />}
            variant='outline'
            onClick={run}
            isLoading={state.loading}
          >
            Check again
          </DashboardActionButton>
          <PrimaryButton
            onClick={finish}
            isLoading={busy}
            isDisabled={!result?.ok}
          >
            Finish setup
          </PrimaryButton>
        </>
      }
    >
      <VStack align='stretch' spacing={3}>
        {state.error ? (
          <DashboardErrorAlert>{state.error}</DashboardErrorAlert>
        ) : null}
        {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
        {state.loading && !result ? <Spinner size='sm' /> : null}
        {(result?.checks || []).map(check => (
          <HStack key={check.id} align='start' spacing={3}>
            <Badge colorScheme={CHECK_BADGE[check.status].colorScheme}>
              {CHECK_BADGE[check.status].label}
            </Badge>
            <VStack align='start' spacing={0}>
              <Text fontSize='sm' fontWeight='semibold'>
                {check.label}
              </Text>
              {check.detail ? (
                <Text fontSize='xs' color={muted}>
                  {check.detail}
                </Text>
              ) : null}
            </VStack>
          </HStack>
        ))}
        {(result?.notes || []).map(note => (
          <Text
            key={note}
            fontSize='xs'
            color={muted}
            data-testid='verify-note'
          >
            {note}
          </Text>
        ))}
        {result ? (
          <Text fontSize='xs' color={muted} data-testid='verify-test-hint'>
            To test delivery, send a test email from System Settings, Email
            (SMTP).{' '}
            {ctx.isSystemAdmin === true ? (
              <Link href='/system-settings' color='blue.500'>
                Open System Settings
              </Link>
            ) : (
              'An administrator can do this.'
            )}
          </Text>
        ) : null}
      </VStack>
    </StepFrame>
  );
}
