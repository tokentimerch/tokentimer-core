import { useEffect, useState } from 'react';
import { Button, Stack, Switch, Text } from '@chakra-ui/react';
import CertOpsBadge from './CertOpsBadge.jsx';
import { Link as RouterLink } from 'react-router';
import { FiArrowRight } from 'react-icons/fi';
import { DashboardActionButton } from '../DashboardPrimitives';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { SettingsActionRow } from '../SettingsPageShell.jsx';
import { useCertOpsCanManage } from './useCertOps.js';
import {
  loadAssistantSettings,
  setAssistantWrites,
  loadAssistantIssuanceSettings,
  setAssistantIssuance,
} from './assistantConnectionsApi.js';

function PolicyForWorkspace({ workspaceId, issuance = false }) {
  const canManage = useCertOpsCanManage();
  const [enabled, setEnabled] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setEnabled(null);
    setError('');
    (issuance ? loadAssistantIssuanceSettings : loadAssistantSettings)(
      workspaceId,
      controller.signal
    )
      .then(settings => {
        if (!controller.signal.aborted)
          setEnabled(
            issuance
              ? settings.issuanceEnabled === true
              : settings.writesEnabled === true
          );
      })
      .catch(failure => {
        if (controller.signal.aborted) return;
        setError(
          failure?.response?.status === 404
            ? 'MCP is not enabled on this server.'
            : 'Could not confirm the MCP setting. Retry before changing it.'
        );
      });
    return () => controller.abort();
  }, [workspaceId, attempt, issuance]);

  const toggle = async event => {
    const next = event.target.checked;
    setBusy(true);
    try {
      setEnabled(
        await (issuance ? setAssistantIssuance : setAssistantWrites)(
          workspaceId,
          next
        )
      );
    } catch {
      setEnabled(null);
      setError(
        'Could not confirm the MCP setting. Retry to check its current value.'
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <SettingsActionRow
      label={
        issuance ? 'Allow MCP issuance requests' : 'Allow MCP renewal requests'
      }
      description={
        issuance
          ? 'Let connected assistants request new certificates. Job approval still applies.'
          : 'Let connected assistants request certificate renewals. Job approval still applies.'
      }
      note='Owners and managers can change this. Server and connection permissions still apply. Turning this off stops unapproved requests; approved or running jobs may continue.'
      footer={
        !issuance ? (
          <DashboardActionButton
            as={RouterLink}
            to={`/preferences?workspace=${encodeURIComponent(workspaceId)}#mcp-assistants`}
            variant='outline'
            rightIcon={<FiArrowRight />}
          >
            Manage MCP assistants
          </DashboardActionButton>
        ) : null
      }
      status={
        <CertOpsBadge colorScheme={enabled ? 'blue' : 'gray'}>
          {enabled === null
            ? error
              ? 'Unavailable'
              : 'Checking…'
            : enabled
              ? 'On'
              : 'Off'}
        </CertOpsBadge>
      }
    >
      <Stack align={{ base: 'start', sm: 'end' }} spacing={2}>
        {canManage && enabled !== null ? (
          <Switch
            aria-label={
              issuance
                ? 'Allow MCP issuance requests'
                : 'Allow MCP renewal requests'
            }
            isChecked={enabled}
            isDisabled={busy}
            onChange={toggle}
          />
        ) : null}
        {error ? (
          <Text role='alert' fontSize='xs'>
            {error}
          </Text>
        ) : null}
        {error ? (
          <Button
            size='sm'
            variant='outline'
            onClick={() => setAttempt(value => value + 1)}
          >
            Retry MCP setting
          </Button>
        ) : null}
      </Stack>
    </SettingsActionRow>
  );
}

export default function AssistantWorkspacePolicyRow() {
  const { workspaceId } = useWorkspace();
  return workspaceId ? (
    <>
      <PolicyForWorkspace key={workspaceId} workspaceId={workspaceId} />
      <PolicyForWorkspace
        key={`${workspaceId}-issuance`}
        workspaceId={workspaceId}
        issuance
      />
    </>
  ) : null;
}
