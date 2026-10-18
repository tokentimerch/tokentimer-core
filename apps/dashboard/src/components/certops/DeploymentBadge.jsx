import { Button, Tooltip } from '@chakra-ui/react';
import CertOpsBadge from './CertOpsBadge.jsx';
import { deploymentStates } from './distributionFormat.js';

export default function DeploymentBadge({ summary, loading, error, onClick }) {
  const descriptor =
    deploymentStates[summary?.status] || deploymentStates.not_distributed;
  const label =
    error ||
    (loading
      ? 'Loading deployments…'
      : summary?.total
        ? `${summary.verified}/${summary.total} verified · ${descriptor.label}`
        : descriptor.label);
  const badge = (
    <CertOpsBadge
      colorScheme={error ? 'orange' : descriptor.scheme}
      textTransform='none'
      whiteSpace='normal'
    >
      {label}
    </CertOpsBadge>
  );
  return onClick ? (
    <Tooltip label='Open certificate deployments'>
      <Button
        variant='unstyled'
        h='auto'
        minW={0}
        textAlign='left'
        whiteSpace='normal'
        onClick={event => {
          event.stopPropagation();
          onClick();
        }}
      >
        {badge}
      </Button>
    </Tooltip>
  ) : (
    badge
  );
}
