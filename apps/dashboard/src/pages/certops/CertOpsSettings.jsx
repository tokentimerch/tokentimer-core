import { useState } from 'react';
import { Stack } from '@chakra-ui/react';
import { useOutletContext } from 'react-router';
import ApiTokenList from '../../components/certops/ApiTokenList.jsx';
import CertOpsWorkspaceControls from '../../components/certops/CertOpsWorkspaceControls.jsx';
import ApiTokenModal from '../../components/certops/ApiTokenModal.jsx';
import WorkspaceKillSwitchPanel from '../../components/certops/WorkspaceKillSwitchPanel.jsx';
import CertopsQuickstartCard from '../../components/onboarding/CertopsQuickstartCard.jsx';
import { useCertOpsCanManage } from '../../components/certops/useCertOps.js';
import {
  DashboardActionButton,
  DashboardPanel,
  DashboardPanelHeader,
} from '../../components/DashboardPrimitives';

/**
 * Settings tab: workspace-level certificate operations configuration. The
 * kill switch stays in the banner above every tab. Approval policy and
 * machine credentials live here.
 */
export default function CertOpsSettings() {
  const { certOpsPaused, killSwitch } = useOutletContext() || {};
  const canManage = useCertOpsCanManage();
  const [createOpen, setCreateOpen] = useState(false);

  return (
    <Stack spacing={3} align='stretch'>
      <CertOpsWorkspaceControls>
        <WorkspaceKillSwitchPanel
          controller={killSwitch}
          mode='row'
          showDivider
        />
      </CertOpsWorkspaceControls>

      <CertopsQuickstartCard />

      <DashboardPanel>
        <DashboardPanelHeader
          title='Machine API tokens'
          description='Machine tokens are for external executors (certbot hooks, ACME clients, cert-manager controllers, CI).'
          action={
            canManage ? (
              <DashboardActionButton
                colorScheme='blue'
                onClick={() => setCreateOpen(true)}
              >
                Create token
              </DashboardActionButton>
            ) : null
          }
        />
        <ApiTokenList />
      </DashboardPanel>

      <ApiTokenModal
        isOpen={createOpen}
        onClose={() => setCreateOpen(false)}
        certOpsPaused={Boolean(certOpsPaused)}
      />
    </Stack>
  );
}
