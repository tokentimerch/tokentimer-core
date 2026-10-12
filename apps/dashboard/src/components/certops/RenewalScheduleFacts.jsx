import { Text, Tooltip } from '@chakra-ui/react';
import CertOpsBadge from './CertOpsBadge.jsx';
import JobStatusBadge from './JobStatusBadge.jsx';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';

/**
 * Schedule facts that used to live only on the upcoming-renewals list:
 * a capacity deferral, and the latest renew job (or that there has never
 * been one). Renewal state badges stay on RenewalBadge.
 */
const DEFERRED_REASONS = {
  ca_capacity: {
    label: 'At CA capacity',
    scheme: 'yellow',
    tooltip:
      'This certificate is due for renewal, but its issuing CA already has as many renewals in flight as the per-CA limit allows. The capacity constraint itself clears automatically once earlier renewals for that CA finish; it does not mean nothing here needs attention, since one of those in-flight jobs could be waiting on something else, such as an approval.',
  },
};

const DEFERRED_FALLBACK = {
  label: 'Deferred',
  scheme: 'gray',
  tooltip:
    'Renewal is temporarily deferred. It will proceed once the underlying condition clears.',
};

const NEVER_RENEWED_STATES = new Set(['auto', 'disabled', 'not-configured']);

function deferredDescriptor(reason) {
  return DEFERRED_REASONS[reason] || DEFERRED_FALLBACK;
}

export default function RenewalScheduleFacts({ renewal }) {
  const { muted } = useDashboardTheme();
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

  if (!deferred && !jobStatus && !showNeverRenewed) return null;

  return (
    <>
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
      {jobStatus ? (
        <JobStatusBadge status={jobStatus} />
      ) : showNeverRenewed ? (
        <Text fontSize='xs' color={muted}>
          Never renewed
        </Text>
      ) : null}
    </>
  );
}
