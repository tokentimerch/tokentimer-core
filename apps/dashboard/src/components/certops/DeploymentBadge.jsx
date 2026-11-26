import {
  Box,
  Button,
  HStack,
  Tooltip,
  useColorModeValue,
} from '@chakra-ui/react';
import {
  CheckCircle2,
  CircleDashed,
  Clock3,
  Layers,
  Minus,
  ShieldAlert,
  XCircle,
} from 'lucide-react';
import { deploymentStates } from './distributionFormat.js';

const icons = {
  installed: CheckCircle2,
  completed: CheckCircle2,
  verified: CheckCircle2,
  partial: ShieldAlert,
  failed: XCircle,
  uncertain: ShieldAlert,
  stale: Clock3,
  pending: CircleDashed,
  not_deployed: Minus,
  inactive: Minus,
  not_distributed: Minus,
  unavailable: Clock3,
};

const ATTENTION_STATUSES = new Set([
  'partial',
  'failed',
  'uncertain',
  'stale',
  'pending',
  'unavailable',
]);

function countOf(summary, key) {
  return Number(summary?.[key] || 0);
}

/** One sentence for the cell tooltip. The visible label stays short. */
function distributionTooltip(summary, status, { stale, error } = {}) {
  if (error && !summary) {
    return 'Distribution status is unavailable. Open the certificate to try again.';
  }
  const total = countOf(summary, 'total');
  const verified = countOf(summary, 'verified');
  const installed = countOf(summary, 'installed');
  const pending = countOf(summary, 'pending');
  const failed = countOf(summary, 'failed');
  const known = stale && summary?.status ? summary.status : status;
  let sentence;
  switch (known) {
    case 'verified':
      sentence =
        total === 1
          ? 'This consumer is serving the published version.'
          : `${verified} of ${total} ${verified === 1 ? 'consumer is' : 'consumers are'} serving the published version.`;
      break;
    case 'installed':
      sentence =
        total === 1
          ? 'The published version is installed on this consumer. Live use is not checked.'
          : `The published version is installed on ${installed || total} of ${total} consumers. Live use is not checked.`;
      break;
    case 'completed':
      sentence = `${verified + installed} of ${total} consumers have the published version. Live checks vary.`;
      break;
    case 'partial':
      sentence = verified
        ? `${verified} of ${total} ${verified === 1 ? 'consumer is' : 'consumers are'} serving the published version.`
        : `The published version is installed on ${installed} of ${total} consumers. Live use is not checked.`;
      break;
    case 'failed':
      sentence = failed
        ? `The published version failed on ${failed} of ${total} consumers.`
        : 'The published version failed on these consumers.';
      break;
    case 'uncertain':
      sentence =
        'TokenTimer could not confirm whether these consumers are serving the published version.';
      break;
    case 'stale':
      sentence = 'Verification is out of date for these consumers.';
      break;
    case 'pending': {
      const waiting = pending || total;
      sentence = `${waiting} of ${total} ${waiting === 1 ? 'consumer has' : 'consumers have'} not finished installing the published version.`;
      break;
    }
    case 'unavailable':
      sentence = 'Distribution status needs a refresh.';
      break;
    default:
      sentence = 'Distribution status is unavailable.';
  }
  if (stale) return `Last known: ${sentence} The current state is unconfirmed.`;
  return sentence;
}

/** Short list copy. Details keep the verified/total ratio via showVerified. */
function deploymentScanLabel(summary, status) {
  const total = Number(summary?.total || 0);
  if (
    !total ||
    status === 'not_distributed' ||
    status === 'not_deployed' ||
    status === 'inactive'
  ) {
    return null;
  }
  const verified = Number(summary?.verified || 0);
  const installed = Number(summary?.installed || 0);
  const pending = Number(summary?.pending || 0);
  const failed = Number(summary?.failed || 0);
  switch (status) {
    case 'verified':
      return total === 1 ? 'Live' : `${verified} live`;
    case 'installed':
      return total === 1 ? 'Installed' : `${installed || total} installed`;
    case 'completed':
      return `${verified + installed} of ${total} delivered`;
    case 'partial':
      return `${verified} of ${total} live`;
    case 'failed':
      return failed > 0 ? `${failed} failed` : 'Failed';
    case 'uncertain':
      return 'Uncertain';
    case 'stale':
      return 'Outdated';
    case 'pending':
      return `${pending || total} pending`;
    case 'unavailable':
      return 'Needs refresh';
    default:
      return null;
  }
}

export default function DeploymentBadge({
  summary,
  loading,
  error,
  onClick,
  certificateCount,
  showVerified = false,
  attentionOnly = false,
}) {
  const stale = summary?.staleData || Boolean(error && summary);
  const status =
    stale || error ? 'unavailable' : summary?.status || 'not_distributed';
  const descriptor =
    deploymentStates[status] || deploymentStates.not_distributed;
  const fileCompletion = ['installed', 'completed'].includes(status);
  const completedCount = fileCompletion
    ? Number(summary?.installed || 0) + Number(summary?.verified || 0)
    : summary?.verified;
  const count = summary?.total
    ? `${status === 'unavailable' && !stale ? '—' : completedCount}/${summary.total}`
    : '—';
  const detailedLabel = certificateCount
    ? `${certificateCount} certs`
    : `${count}${showVerified && summary?.total ? (status === 'completed' ? ' complete' : fileCompletion ? ' installed' : ' verified') : ''}`;
  const scanLabel =
    !showVerified && !certificateCount
      ? error && !summary
        ? 'Unavailable'
        : loading && !summary
          ? null
          : deploymentScanLabel(summary, status)
      : null;
  const showScan =
    Boolean(scanLabel) &&
    (!attentionOnly || ATTENTION_STATUSES.has(status) || (error && !summary));
  if (!showVerified && !certificateCount && !showScan) return null;
  const label = showVerified || certificateCount ? detailedLabel : scanLabel;
  const description = certificateCount
    ? `${certificateCount} certificates are linked. Select one to see its distribution.${error ? ' The current state is unconfirmed.' : ''}`
    : loading && !summary
      ? 'Loading distribution status'
      : distributionTooltip(summary, status, { stale, error });
  const Icon = certificateCount
    ? Layers
    : loading && !summary
      ? CircleDashed
      : icons[status] || Minus;
  const color = useColorModeValue(
    `${descriptor.scheme}.700`,
    `${descriptor.scheme}.300`
  );
  const indicator = (
    <HStack
      as='span'
      role='img'
      tabIndex={onClick ? undefined : 0}
      display='inline-flex'
      spacing={1}
      h='20px'
      minW='48px'
      whiteSpace='nowrap'
      verticalAlign='middle'
      fontSize='xs'
      fontWeight='medium'
      color={certificateCount && !error ? undefined : color}
      aria-label={description}
    >
      <Icon size={13} aria-hidden='true' style={{ flexShrink: 0 }} />
      <Box as='span' fontVariantNumeric='tabular-nums'>
        {label}
      </Box>
    </HStack>
  );
  return (
    <Tooltip label={description} hasArrow>
      {onClick ? (
        <Button
          variant='unstyled'
          display='inline-flex'
          h='20px'
          minW='48px'
          fontSize='xs'
          aria-label={`Open distribution: ${description}`}
          onClick={event => {
            event.stopPropagation();
            onClick();
          }}
        >
          {indicator}
        </Button>
      ) : (
        indicator
      )}
    </Tooltip>
  );
}
