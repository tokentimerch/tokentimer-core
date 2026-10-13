import { useState } from 'react';
import {
  HStack,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalHeader,
  ModalOverlay,
  Stack,
} from '@chakra-ui/react';
import { useOutletContext, useSearchParams } from 'react-router';
import AgentFleetPanel from '../../components/certops/AgentFleetPanel.jsx';
import BootstrapTokenList from '../../components/certops/BootstrapTokenList.jsx';
import DeployAgentModal from '../../components/certops/DeployAgentModal.jsx';
import TrustAnchorsPanel from '../../components/certops/TrustAnchorsPanel.jsx';
import { useCertOpsCanManage } from '../../components/certops/useCertOps.js';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../../components/DashboardModalFrame.jsx';
import {
  DashboardActionButton,
  DashboardPanel,
} from '../../components/DashboardPrimitives';

/**
 * Agents tab: the fleet. Bootstrap tokens stay behind a modal next to
 * Deploy an agent, since they are credentials rather than the fleet itself.
 *
 * Deep links (`?agentId=` / `?trustAnchorId=`) are resolved inside the
 * panels after their lists load: highlight + scroll (no details modal).
 */
export default function CertOpsAgents() {
  const { certOpsPaused } = useOutletContext() || {};
  const canManage = useCertOpsCanManage();
  const [searchParams] = useSearchParams();
  const focusAgentId = searchParams.get('agentId') || '';
  const focusTrustAnchorId = searchParams.get('trustAnchorId') || '';
  const modal = useDashboardModalProps();
  const [deployOpen, setDeployOpen] = useState(false);
  const [tokensOpen, setTokensOpen] = useState(false);
  // Bumped when DeployAgentModal detects a freshly registered agent, so the
  // fleet panel refetches immediately instead of waiting on its own poll.
  const [fleetRefreshSignal, setFleetRefreshSignal] = useState(0);

  return (
    <Stack spacing={3} align='stretch'>
      <DashboardPanel>
        <AgentFleetPanel
          refreshSignal={fleetRefreshSignal}
          focusAgentId={focusAgentId || undefined}
          headerAction={
            canManage ? (
              <HStack spacing={2}>
                <DashboardActionButton
                  variant='outline'
                  onClick={() => setTokensOpen(true)}
                >
                  Bootstrap tokens
                </DashboardActionButton>
                <DashboardActionButton
                  colorScheme='blue'
                  onClick={() => setDeployOpen(true)}
                >
                  Deploy an agent
                </DashboardActionButton>
              </HStack>
            ) : null
          }
        />
      </DashboardPanel>
      <DashboardPanel>
        <TrustAnchorsPanel
          focusTrustAnchorId={focusTrustAnchorId || undefined}
        />
      </DashboardPanel>

      <Modal isOpen={tokensOpen} onClose={() => setTokensOpen(false)} size='xl'>
        <ModalOverlay {...modal.overlayProps} />
        <DashboardModalFrame>
          <ModalHeader {...modal.headerProps}>
            <DashboardModalTitle>Bootstrap tokens</DashboardModalTitle>
            <DashboardModalDescription>
              Tokens that let a new agent register. The secret is shown only
              when the token is created.
            </DashboardModalDescription>
          </ModalHeader>
          <ModalCloseButton {...modal.closeButtonProps} />
          <ModalBody {...modal.bodyProps}>
            {tokensOpen ? <BootstrapTokenList hideTitle /> : null}
          </ModalBody>
        </DashboardModalFrame>
      </Modal>

      <DeployAgentModal
        isOpen={deployOpen}
        onClose={() => setDeployOpen(false)}
        certOpsPaused={Boolean(certOpsPaused)}
        onAgentRegistered={() => setFleetRefreshSignal(tick => tick + 1)}
      />
    </Stack>
  );
}
