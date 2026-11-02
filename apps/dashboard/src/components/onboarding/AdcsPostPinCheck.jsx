import { useEffect, useRef, useState } from 'react';
import { Text, VStack } from '@chakra-ui/react';
import { DashboardActionButton } from '../DashboardPrimitives';
import {
  dispatchIssuerPreflight,
  listIssuers,
} from '../certops/certopsEnrollmentsApi.js';
import { findListedIssuer } from '../certops/certopsFormat.js';
import { getJob } from '../certops/certopsJobsApi.js';
import { failedPreflightMessage } from '../certops/adcsPreflightJob.js';
import { jobStatusLabel } from '../certops/certopsJobsFormat.js';
import { StatusPanel } from './panels.jsx';
import { isJobFinal } from './jobTimeline.js';

/** Recheck the already pinned issuer on the setup agent without leaving the guide. */
export default function AdcsPostPinCheck({
  workspaceId,
  issuer,
  agent,
  disabledReason,
  onChanged,
}) {
  const [jobId, setJobId] = useState('');
  const [waiting, setWaiting] = useState(false);
  const [dispatching, setDispatching] = useState(false);
  const [error, setError] = useState('');
  const [status, setStatus] = useState('');
  const dispatchRef = useRef(false);
  const changedRef = useRef(onChanged);
  changedRef.current = onChanged;
  const eligible =
    agent?.platform === 'win32' &&
    agent?.livenessState === 'live' &&
    (agent?.declaredCapabilities || []).includes('adcs-enroll-v1');
  const blocked =
    disabledReason ||
    (!eligible ? 'Choose a connected Windows enrollment agent first.' : '') ||
    (!issuer.caConfig || !issuer.template
      ? 'The issuer must report its CA configuration and template first.'
      : '');

  useEffect(() => {
    if (!waiting || !jobId) return undefined;
    let cancelled = false;
    let timer;
    const poll = async () => {
      try {
        const result = await getJob(workspaceId, jobId);
        if (cancelled) return;
        const job = result?.job || result;
        setStatus(jobStatusLabel(job?.status));
        const failure = failedPreflightMessage(job);
        if (
          failure ||
          (isJobFinal(job?.status) && job?.status !== 'succeeded')
        ) {
          setError(
            failure ||
              'The CA check did not succeed. Review its result before retrying.'
          );
          setWaiting(false);
          return;
        }
        if (job?.status === 'succeeded') {
          const current = await findListedIssuer(
            listIssuers,
            workspaceId,
            issuer.id
          );
          if (cancelled) return;
          // Never mistake a previous verdict or another issuer/CA pair for this job.
          if (current?.lastPreflightJobId === jobId) {
            const preflight = current.lastPreflight;
            const safe =
              preflight?.caConfig === issuer.caConfig &&
              preflight?.template === issuer.template &&
              preflight?.caCheck?.verdict === 'safe' &&
              preflight?.templateCheck?.verdict === 'safe' &&
              current.revalidationRequired !== true;
            if (!safe) {
              setError(
                'The CA or template check is not safe for the pinned issuer. Review the issuer before continuing.'
              );
              setWaiting(false);
              return;
            }
            await changedRef.current?.();
            if (cancelled) return;
            setStatus('Post-pin CA and template checks passed.');
            setWaiting(false);
            return;
          }
        }
        timer = setTimeout(poll, 3000);
      } catch (e) {
        if (cancelled) return;
        setError(
          e?.response?.data?.error ||
            e.message ||
            'Could not read the CA check result.'
        );
        setWaiting(false);
      }
    };
    poll();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [
    waiting,
    jobId,
    workspaceId,
    issuer.id,
    issuer.caConfig,
    issuer.template,
  ]);

  const run = async () => {
    if (blocked || dispatchRef.current || waiting) return;
    dispatchRef.current = true;
    setDispatching(true);
    setError('');
    try {
      const result = await dispatchIssuerPreflight(workspaceId, issuer.id, {
        agentId: agent.id,
        caConfig: issuer.caConfig,
        template: issuer.template,
      });
      if (!result?.job?.id)
        throw new Error('The CA check did not return a job.');
      setJobId(result.job.id);
      setStatus(jobStatusLabel(result.job.status));
      setWaiting(true);
    } catch (e) {
      setError(
        e?.response?.data?.error || e.message || 'Could not start the CA check.'
      );
    } finally {
      dispatchRef.current = false;
      setDispatching(false);
    }
  };

  return (
    <StatusPanel
      status='info'
      title='Check the pinned CA'
      testId='adcs-issuer-recheck'
    >
      <VStack align='stretch' spacing={2}>
        <Text fontSize='sm'>
          Renewal needs a CA check taken after the CA certificate was pinned.
          Run it here on{' '}
          {agent?.name || agent?.hostname || 'the selected Windows agent'}. This
          checks the CA and template; it does not issue a certificate.
        </Text>
        {blocked ? <Text fontSize='sm'>{blocked}</Text> : null}
        <DashboardActionButton
          onClick={run}
          isDisabled={Boolean(blocked) || waiting}
          isLoading={dispatching}
        >
          Run post-pin check
        </DashboardActionButton>
        {status ? (
          <Text fontSize='sm' role='status'>
            {status}
          </Text>
        ) : null}
        {error ? (
          <>
            <Text fontSize='sm' role='alert'>
              {error}
            </Text>
            {jobId ? (
              <DashboardActionButton
                onClick={() => {
                  setError('');
                  setWaiting(true);
                }}
              >
                Refresh check result
              </DashboardActionButton>
            ) : null}
          </>
        ) : null}
      </VStack>
    </StatusPanel>
  );
}
