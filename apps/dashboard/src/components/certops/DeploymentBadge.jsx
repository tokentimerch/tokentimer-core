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
  const ratio = summary?.total
    ? `${Number(summary.verified || 0)}/${summary.total} verified. `
    : '';
  const description = certificateCount
    ? `${certificateCount} distributed certificates. Select a certificate in details.${error ? ' Refresh unavailable. Current state is unconfirmed.' : ''}`
    : showVerified
      ? stale
        ? `Last known: ${summary.total ? `${summary.verified}/${summary.total} verified` : deploymentStates[summary.status]?.label || 'Unavailable'}. Refresh unavailable. Current state is unconfirmed.`
        : error
          ? 'Deployment status unavailable. Open details to try again.'
          : loading && !summary
            ? 'Loading deployment status'
            : status === 'unavailable'
              ? `${descriptor.label}. ${summary?.total ? `Last known: ${summary.verified}/${summary.total} verified. ` : ''}Current state is unconfirmed.`
              : `${summary?.total ? (summary.installed ? `${summary.verified}/${summary.total} live verified; ${summary.installed} file-only installations. ` : `${summary.verified}/${summary.total} verified. `) : ''}${descriptor.label}`
      : error && !summary
        ? 'Deployment status unavailable. Open details to try again.'
        : stale
          ? `Last known: ${label}. Refresh unavailable. Current state is unconfirmed.`
          : `${label}. ${ratio}${descriptor.label}`;
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
          aria-label={`Open certificate deployments: ${description}`}
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
