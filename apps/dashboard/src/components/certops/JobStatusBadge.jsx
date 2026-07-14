import { Badge } from '@chakra-ui/react';
import { jobStatusLabel, jobStatusScheme } from './certopsJobsFormat';

/**
 * Subtle status chip for a CertOps job.
 *
 * @param {{ status?: string, fontSize?: string }} props
 */
export default function JobStatusBadge({ status, fontSize = 'xs' }) {
  return (
    <Badge
      colorScheme={jobStatusScheme(status)}
      variant='subtle'
      textTransform='none'
      fontWeight='medium'
      fontSize={fontSize}
    >
      {jobStatusLabel(status)}
    </Badge>
  );
}
