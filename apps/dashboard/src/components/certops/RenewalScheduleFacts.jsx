import { Tooltip, VStack } from '@chakra-ui/react';
import CertOpsBadge from './CertOpsBadge.jsx';
import { jobStatusLabel, jobStatusScheme } from './certopsJobsFormat';

/**
 * Capacity wait and the latest renewal job. The renewal badge already says
 * whether automatic renewal can run. The last attempt uses the job status
 * color and names that job, so it does not read as a second certificate status.
 */
const DEFERRED_REASONS = {
  ca_capacity: {
    label: 'At CA capacity',
    scheme: 'yellow',
    tooltip:
      'Renewal is waiting because this CA already has as many renewals in flight as it allows. It continues on its own when an earlier renewal for that CA finishes. A job waiting on approval can still need attention.',
  },
};

const DEFERRED_FALLBACK = {
  label: 'Deferred',
  scheme: 'gray',
  tooltip:
    'Renewal is waiting on a temporary condition. It is not a missing profile or a missing key.',
};

const NEVER_RENEWED_STATES = new Set(['auto', 'disabled', 'not-configured']);

function deferredDescriptor(reason) {
  return DEFERRED_REASONS[reason] || DEFERRED_FALLBACK;
}

function AttemptBadge({ children, scheme = 'gray', label }) {
  return (
    <CertOpsBadge colorScheme={scheme} aria-label={label || children}>
      {children}
    </CertOpsBadge>
  );
}

export default function RenewalScheduleFacts({ renewal, placement = 'row' }) {
  if (!renewal || typeof renewal !== 'object') return null;

  const { deferredReason, lastRenewJobStatus } = renewal;
  const deferred =
    typeof deferredReason === 'string' && deferredReason.trim()
      ? deferredDescriptor(deferredReason)
      : null;

  const hasLastAttempt = Object.prototype.hasOwnProperty.call(
    renewal,
    'lastRenewJobStatus'
  );
  const jobStatus =
    typeof lastRenewJobStatus === 'string' ? lastRenewJobStatus.trim() : '';
  const showNeverRenewed =
    hasLastAttempt && !jobStatus && NEVER_RENEWED_STATES.has(renewal.state);
  const attemptText = jobStatus
    ? `Last renewal: ${jobStatusLabel(jobStatus)}`
    : showNeverRenewed
      ? placement === 'detail'
        ? 'No renewal job has run yet.'
        : 'Never renewed'
      : '';

  if (!deferred && !attemptText) return null;

  return (
    <VStack align='flex-start' spacing={1}>
      {deferred ? (
        <Tooltip
          label={deferred.tooltip}
          hasArrow
          placement='top'
          openDelay={250}
        >
          <CertOpsBadge
            colorScheme={deferred.scheme}
            aria-label={`${deferred.label}. ${deferred.tooltip}`}
          >
            {deferred.label}
          </CertOpsBadge>
        </Tooltip>
      ) : null}
      {attemptText ? (
        <AttemptBadge
          scheme={jobStatus ? jobStatusScheme(jobStatus) : 'gray'}
          label={attemptText}
        >
          {attemptText}
        </AttemptBadge>
      ) : null}
    </VStack>
  );
}
