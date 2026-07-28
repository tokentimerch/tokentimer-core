import { useState } from 'react';
import { Stack } from '@chakra-ui/react';
import { useOutletContext } from 'react-router';
import ApiTokenList from '../../components/certops/ApiTokenList.jsx';
import ApiTokenModal from '../../components/certops/ApiTokenModal.jsx';
import { useCertOpsCanManage } from '../../components/certops/useCertOps.js';
import {
  DashboardActionButton,
  DashboardPanel,
  DashboardPanelHeader,
} from '../../components/DashboardPrimitives';

/**
 * Settings tab: workspace-level certificate operations configuration. The
 * kill switch lives in the banner above every tab, so what remains here is
 * the machine credential surface. Token creation is a modal (U11), same
 * split as the Agents tab: a one-time task behind a button, an ongoing
 * inventory (ApiTokenList) inline on the page.
 */
export default function CertOpsSettings() {
  const { certOpsPaused } = useOutletContext() || {};
  const canManage = useCertOpsCanManage();
  const [createOpen, setCreateOpen] = useState(false);

  return (
    <Stack spacing={3} align='stretch'>
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
