import { useCallback, useEffect, useState } from 'react';
import { Badge, HStack, Spinner, Text, VStack } from '@chakra-ui/react';
import {
  DashboardActionButton,
  DashboardErrorAlert,
} from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';

import { evaluateVerification, CHECK_STATUS } from './verification.js';
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

  const run = useCallback(async () => {
    setState(s => ({ ...s, loading: true }));
    try {
      await ctx.refresh();
      const summary = await ctx.fetchSummary();
      const refs = ctx.session.operationRefs || {};
      const monitor =
        goal === 'monitor_https'
          ? summary.monitors.items.find(
              m =>
                m.url?.toLowerCase() === String(refs.monitorUrl).toLowerCase()
            ) || null
          : null;
      const tokenId =
        monitor?.tokenId ||
        (summary.references.tokenIds.existing || [])[0] ||
        null;
      let token = tokenId ? await onboardingActions.getToken(tokenId) : null;
      // Imports and discovery return no ids. Sample the asset closest to
      // expiry, which is the one most likely to alert first, and use the
      // list row's own alert state so one request is enough.
      if (!token && (summary.assets?.total || 0) > 0) {
        token = await onboardingActions.soonestToken(ctx.workspaceId);
      }
      setState({
        loading: false,
        result: evaluateVerification({ goal, monitor, token, summary }),
      });
    } catch (e) {
      setState({ loading: false, error: e.message });
    }
  }, [ctx, goal]);

  useEffect(() => {
    run();
    // Only on mount: the user re-checks explicitly.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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
      description='These checks read the real state of your workspace.'
      docs={[
        ...ctx.docs('quickstart.verifyAlert', 'Verifying an alert'),
        ...ctx.docs('alerts.troubleshooting', 'If alerts do not arrive'),
      ]}
      actions={
        <>
          <DashboardActionButton
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
      </VStack>
    </StepFrame>
  );
}
