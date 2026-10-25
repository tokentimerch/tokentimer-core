import CertOpsBadge from '../../components/certops/CertOpsBadge.jsx';
import { useState } from 'react';
import { Stack, Switch } from '@chakra-ui/react';
import { useOutletContext } from 'react-router';
import ApiTokenList from '../../components/certops/ApiTokenList.jsx';
import ApiTokenModal from '../../components/certops/ApiTokenModal.jsx';
import WorkspaceKillSwitchPanel from '../../components/certops/WorkspaceKillSwitchPanel.jsx';
import CertopsQuickstartCard from '../../components/onboarding/CertopsQuickstartCard.jsx';
import {
  SettingsActionList,
  SettingsActionRow,
} from '../../components/SettingsPageShell.jsx';
import {
  useCertOpsCanManage,
  useCertOpsIsWorkspaceAdmin,
  useCertOpsWorkspaceKillSwitch,
} from '../../components/certops/useCertOps.js';
import {
  DashboardActionButton,
  DashboardPanel,
  DashboardPanelHeader,
} from '../../components/DashboardPrimitives';
import { showError, showSuccess } from '../../utils/toast.js';

function JobApprovalPolicyRow() {
  const isAdmin = useCertOpsIsWorkspaceAdmin();
  const {
    certOpsRequireApprovalAlways,
    loading,
    error,
    saving,
    setRequireApprovalAlways,
  } = useCertOpsWorkspaceKillSwitch();

  const handleToggle = async event => {
    const next = event.target.checked;
    try {
      await setRequireApprovalAlways(next);
      showSuccess(
        next
          ? 'Every new job in this workspace now requires approval'
          : 'Jobs in this workspace no longer require approval by default'
      );
    } catch (err) {
      showError(
        err?.response?.data?.error ||
          'Could not update the approval policy. Please try again.'
      );
    }
  };

  const resolved =
    !loading && !error && certOpsRequireApprovalAlways !== undefined;

  return (
    <SettingsActionRow
      label='Job approval'
      status={
        !isAdmin || !resolved ? (
          <CertOpsBadge
            colorScheme={certOpsRequireApprovalAlways ? 'purple' : 'gray'}
          >
            {certOpsRequireApprovalAlways ? 'Always required' : 'Not required'}
          </CertOpsBadge>
        ) : null
      }
      description='Require approval before every new job can run, regardless of the per-job setting.'
      note={
        isAdmin
          ? 'Applies to manual jobs, scheduled renewals, Vault rollouts and their deployment jobs, and trust-anchor distribution or removal. When enabled, scheduled jobs wait for another manager: renewal is not unattended. Leave this off for unattended execution; individual requests can still require approval.'
          : 'Only workspace admins can enable or disable job approval.'
      }
    >
      {isAdmin && resolved ? (
        <Switch
          size='md'
          isChecked={certOpsRequireApprovalAlways === true}
          isDisabled={saving}
          onChange={handleToggle}
          aria-label='Require approval for every new job'
        />
      ) : null}
    </SettingsActionRow>
  );
}

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
      <DashboardPanel>
        <DashboardPanelHeader
          title='Workspace controls'
          description='Incident and approval controls for certificate operations in this workspace. A pause shows on every tab.'
        />
        <SettingsActionList>
          <WorkspaceKillSwitchPanel
            controller={killSwitch}
            mode='row'
            showDivider
          />
          <JobApprovalPolicyRow />
        </SettingsActionList>
      </DashboardPanel>

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
