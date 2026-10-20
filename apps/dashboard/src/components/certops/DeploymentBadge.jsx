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

export default function DeploymentBadge({
  summary,
  loading,
  error,
  onClick,
  certificateCount,
  showVerified = false,
}) {
  const stale = summary?.staleData || Boolean(error && summary);
  const status =
    stale || error ? 'unavailable' : summary?.status || 'not_distributed';
  const descriptor =
    deploymentStates[status] || deploymentStates.not_distributed;
  const count = summary?.total
    ? `${status === 'unavailable' && !stale ? '—' : summary.verified}/${summary.total}`
    : '—';
  const label = certificateCount
    ? `${certificateCount} certs`
    : `${count}${showVerified && summary?.total ? ' verified' : ''}`;
  const description = certificateCount
    ? `${certificateCount} distributed certificates. Select a certificate in details.${error ? ' Refresh unavailable. Current state is unconfirmed.' : ''}`
    : stale
      ? `Last known: ${summary.total ? `${summary.verified}/${summary.total} verified` : deploymentStates[summary.status]?.label || 'Unavailable'}. Refresh unavailable. Current state is unconfirmed.`
      : error
        ? 'Deployment status unavailable. Open details to try again.'
        : loading && !summary
          ? 'Loading deployment status'
          : status === 'unavailable'
            ? `${descriptor.label}. ${summary?.total ? `Last known: ${summary.verified}/${summary.total} verified. ` : ''}Current state is unconfirmed.`
            : `${summary?.total ? `${summary.verified}/${summary.total} verified. ` : ''}${descriptor.label}`;
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
