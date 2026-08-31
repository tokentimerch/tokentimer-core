import { useState } from 'react';
import { Stack } from '@chakra-ui/react';
import { useOutletContext } from 'react-router';
import AgentFleetPanel from '../../components/certops/AgentFleetPanel.jsx';
import BootstrapTokenList from '../../components/certops/BootstrapTokenList.jsx';
import DeployAgentModal from '../../components/certops/DeployAgentModal.jsx';
import TrustAnchorsPanel from '../../components/certops/TrustAnchorsPanel.jsx';
import { useCertOpsCanManage } from '../../components/certops/useCertOps.js';
import {
  DashboardActionButton,
  DashboardPanel,
} from '../../components/DashboardPrimitives';

/**
 * Agents tab: the fleet, plus bootstrap-token inventory. The install flow
 * itself (U4) is a modal (DeployAgentModal), launched from the fleet
 * panel's header action, since it is a one-time task rather than page
 * furniture; the fleet table and the token list stay inline because they
 * are ongoing state an operator scans repeatedly.
 */
export default function CertOpsAgents() {
  const { certOpsPaused } = useOutletContext() || {};
  const canManage = useCertOpsCanManage();
  const [deployOpen, setDeployOpen] = useState(false);
  // Bumped when DeployAgentModal detects a freshly registered agent, so the
  // fleet panel refetches immediately instead of waiting on its own poll.
  const [fleetRefreshSignal, setFleetRefreshSignal] = useState(0);

  return (
    <Stack spacing={3} align='stretch'>
      <DashboardPanel>
        <AgentFleetPanel
          refreshSignal={fleetRefreshSignal}
          headerAction={
            canManage ? (
              <DashboardActionButton
                colorScheme='blue'
                onClick={() => setDeployOpen(true)}
              >
                Deploy an agent
              </DashboardActionButton>
            ) : null
          }
        />
      </DashboardPanel>
      <DashboardPanel>
        <BootstrapTokenList />
      </DashboardPanel>
      <DashboardPanel>
        <TrustAnchorsPanel />
      </DashboardPanel>

      <DeployAgentModal
        isOpen={deployOpen}
        onClose={() => setDeployOpen(false)}
        certOpsPaused={Boolean(certOpsPaused)}
        onAgentRegistered={() => setFleetRefreshSignal(tick => tick + 1)}
      />
    </Stack>
  );
}
