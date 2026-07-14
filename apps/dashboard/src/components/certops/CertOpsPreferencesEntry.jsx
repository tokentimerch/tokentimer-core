import { Link as RouterLink } from 'react-router-dom';
import { HStack, Icon, Text } from '@chakra-ui/react';
import { ArrowRight, ShieldCheck } from 'lucide-react';
import {
  DashboardActionButton,
  DashboardPanel,
  DashboardPanelHeader,
} from '../DashboardPrimitives';
import { SettingsSection } from '../SettingsPageShell.jsx';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { useCertOpsAvailability } from './useCertOps.js';

/**
 * Workspace-preferences entry point to the CertOps orchestration page.
 * Renders nothing (including its settings section wrapper) when CertOps is
 * disabled for the workspace, so the preferences page stays unchanged for
 * non-CertOps workspaces (D6).
 */
export default function CertOpsPreferencesEntry() {
  const { muted } = useDashboardTheme();
  const { ready, enabled } = useCertOpsAvailability();

  if (!ready || enabled !== true) return null;

  return (
    <SettingsSection id='certops'>
      <DashboardPanel data-tour='preferences-certops'>
        <DashboardPanelHeader
          title='Certificate operations'
          description='Machine executor jobs, evidence timelines, and scoped API tokens for this workspace.'
          action={
            <DashboardActionButton
              as={RouterLink}
              to='/certops/operations'
              size='sm'
              variant='outline'
              rightIcon={<Icon as={ArrowRight} boxSize={3.5} />}
            >
              Open
            </DashboardActionButton>
          }
        />
        <HStack spacing={2} color={muted}>
          <Icon as={ShieldCheck} boxSize={4} flexShrink={0} />
          <Text fontSize='sm'>
            Certificate operations is enabled for this workspace. Manage machine
            API tokens and review executor-reported jobs on the operations page.
          </Text>
        </HStack>
      </DashboardPanel>
    </SettingsSection>
  );
}
