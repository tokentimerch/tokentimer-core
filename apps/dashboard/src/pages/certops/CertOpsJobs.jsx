import { useOutletContext } from 'react-router';
import ExecutorJobsPanel from '../../components/certops/ExecutorJobsPanel.jsx';

/**
 * Jobs tab: the executor job list with its evidence timelines expanded inline
 * under a row, since reading evidence is why an operator opens this list.
 */
export default function CertOpsJobs() {
  const { certOpsPaused } = useOutletContext() || {};

  return <ExecutorJobsPanel certOpsPaused={Boolean(certOpsPaused)} />;
}
