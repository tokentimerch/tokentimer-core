import { Switch } from '@chakra-ui/react';
import { showError, showSuccess } from '../../utils/toast.js';
import { DashboardPanel, DashboardPanelHeader } from '../DashboardPrimitives';
import {
  SettingsActionList,
  SettingsActionRow,
} from '../SettingsPageShell.jsx';
import CertOpsBadge from './CertOpsBadge.jsx';
import AssistantWorkspacePolicyRow from './AssistantWorkspacePolicyRow.jsx';
import {
  useCertOpsIsWorkspaceAdmin,
  useCertOpsWorkspaceKillSwitch,
} from './useCertOps.js';

function JobApprovalPolicyRow() {
  const isAdmin = useCertOpsIsWorkspaceAdmin();
  const {
    certOpsRequireApprovalAlways,
    loading,
    error,
    saving,
    setRequireApprovalAlways,
  } = useCertOpsWorkspaceKillSwitch();
  const resolved =
    !loading && !error && certOpsRequireApprovalAlways !== undefined;
  const handleToggle = async event => {
    const next = event.target.checked;
    try {
      await setRequireApprovalAlways(next);
      showSuccess(
        next
          ? 'Every new job in this workspace now requires approval'
          : 'Jobs in this workspace no longer require approval by default'
      );
    } catch (failure) {
      showError(
        failure?.response?.data?.error ||
          'Could not update the approval policy. Please try again.'
      );
    }
  };
  return (
    <SettingsActionRow
      label='Job approval'
      description='Require a different approver before new jobs can run.'
      note={
        isAdmin
          ? 'Applies to all job sources. Scheduled renewals also wait for approval when enabled.'
          : 'Only workspace admins can enable or disable job approval.'
      }
      status={
        <CertOpsBadge
          colorScheme={
            resolved && certOpsRequireApprovalAlways ? 'blue' : 'gray'
          }
        >
          {!resolved
            ? error
              ? 'Unavailable'
              : 'Checking…'
            : certOpsRequireApprovalAlways
              ? 'On'
              : 'Off'}
        </CertOpsBadge>
      }
      showDivider
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

export default function CertOpsWorkspaceControls({ children }) {
  return (
    <DashboardPanel id='workspace-controls'>
      <DashboardPanelHeader
        title='Workspace controls'
        description='Control job execution and assistant access in this workspace.'
      />
      <SettingsActionList>
        {children}
        <JobApprovalPolicyRow />
        <AssistantWorkspacePolicyRow />
      </SettingsActionList>
    </DashboardPanel>
  );
}
