import CertOpsBadge from './CertOpsBadge.jsx';
import { jobStatusLabel, jobStatusScheme } from './certopsJobsFormat';

/**
 * Subtle status chip for a CertOps job.
 *
 * @param {{ status?: string }} props
 */
export default function JobStatusBadge({ status }) {
  return (
    <CertOpsBadge colorScheme={jobStatusScheme(status)}>
      {jobStatusLabel(status)}
    </CertOpsBadge>
  );
}
