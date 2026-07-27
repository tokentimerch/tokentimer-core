import { useState } from 'react';
import { SimpleGrid } from '@chakra-ui/react';
import { useOutletContext } from 'react-router';
import AgentFleetPanel from '../../components/certops/AgentFleetPanel.jsx';
import DeployAgentPanel from '../../components/certops/DeployAgentPanel.jsx';
import { DashboardPanel } from '../../components/DashboardPrimitives';

/**
 * Agents tab: the fleet, plus the install flow and the bootstrap tokens that
 * feed it.
 */
export default function CertOpsAgents() {
  const { certOpsPaused } = useOutletContext() || {};
  // Bumped when DeployAgentPanel detects a freshly registered agent, so the
  // fleet panel refetches immediately instead of waiting on its own poll.
  const [fleetRefreshSignal, setFleetRefreshSignal] = useState(0);

  return (
    <SimpleGrid columns={{ base: 1 }} spacing={3}>
      <DashboardPanel>
        <AgentFleetPanel refreshSignal={fleetRefreshSignal} />
      </DashboardPanel>
      <DashboardPanel>
        <DeployAgentPanel
          certOpsPaused={Boolean(certOpsPaused)}
          onAgentRegistered={() => setFleetRefreshSignal(tick => tick + 1)}
        />
      </DashboardPanel>
    </SimpleGrid>
  );
}
