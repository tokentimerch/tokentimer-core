import { useState } from 'react';
import { Badge, HStack, Stack, Switch, Text } from '@chakra-ui/react';
import { useOutletContext } from 'react-router';
import ApiTokenList from '../../components/certops/ApiTokenList.jsx';
import ApiTokenModal from '../../components/certops/ApiTokenModal.jsx';
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
import { useDashboardThemeColors } from '../../hooks/useDashboardTheme';

function JobApprovalPolicyPanel() {
  const isAdmin = useCertOpsIsWorkspaceAdmin();
  const {
    certOpsRequireApprovalAlways,
    loading,
    error,
    saving,
    setRequireApprovalAlways,
  } = useCertOpsWorkspaceKillSwitch();
  const { muted } = useDashboardThemeColors();

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
    <DashboardPanel>
      <DashboardPanelHeader
        title='Job approval'
        description='Applies to every new job in this workspace: dashboard-created jobs, machine API token calls, bulk renew, scheduled renewal, and trust-anchor distribute or revoke. The per-job approval checkbox cannot override it.'
      />
      <HStack spacing={3} align='center'>
        <Text fontSize='sm' color={muted} flex='1'>
          Require approval before every new job can run, regardless of the
          per-job setting.
        </Text>
        {isAdmin && resolved ? (
          <Switch
            size='sm'
            isChecked={certOpsRequireApprovalAlways === true}
            isDisabled={saving}
            onChange={handleToggle}
            aria-label='Require approval for every new job'
          />
        ) : (
          <Badge
            colorScheme={certOpsRequireApprovalAlways ? 'purple' : 'gray'}
            variant='subtle'
            textTransform='none'
            fontWeight='medium'
            fontSize='xs'
            flexShrink={0}
          >
            {certOpsRequireApprovalAlways ? 'Always required' : 'Not required'}
          </Badge>
        )}
      </HStack>
    </DashboardPanel>
  );
}

/**
 * Settings tab: workspace-level certificate operations configuration. The
 * kill switch stays in the banner above every tab. Approval policy and
 * machine credentials live here.
 */
export default function CertOpsSettings() {
  const { certOpsPaused } = useOutletContext() || {};
  const canManage = useCertOpsCanManage();
  const [createOpen, setCreateOpen] = useState(false);

  return (
    <Stack spacing={3} align='stretch'>
      <JobApprovalPolicyPanel />

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
