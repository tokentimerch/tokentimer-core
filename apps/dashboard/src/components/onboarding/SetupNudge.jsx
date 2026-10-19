import { useEffect, useRef, useState } from 'react';
import {
  Button,
  Icon,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Text,
  VStack,
  HStack,
} from '@chakra-ui/react';
import { FaRocket } from 'react-icons/fa';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import { onboardingAPI } from '../../utils/onboardingApi.js';
import { markChecked, shouldNudge, wasChecked } from './nudgeRules.js';

const FLOW = 'mega';

/**
 * Invites the owner of an empty workspace to the setup guide. Mounted once on
 * the dashboard; it renders nothing unless the rules say the workspace is
 * truly empty and the person has not been asked before.
 */
export default function SetupNudge({
  workspaceId,
  isViewer,
  suppress = false,
  onStart,
  api = onboardingAPI,
}) {
  const [open, setOpen] = useState(false);
  const session = useRef(null);
  const primaryRef = useRef(null);
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    outlineButtonProps,
    primaryButtonProps,
    tokens: modalTokens,
  } = useDashboardModalProps();

  useEffect(() => {
    if (!workspaceId || isViewer || suppress || wasChecked(workspaceId)) {
      return undefined;
    }
    let cancelled = false;
    (async () => {
      try {
        const [s, summary] = await Promise.all([
          api.getSession(workspaceId, FLOW),
          api.getSummary(workspaceId, FLOW),
        ]);
        if (cancelled) return;
        markChecked(workspaceId);
        session.current = s;
        if (shouldNudge({ session: s, summary, isViewer })) setOpen(true);
      } catch (_) {
        // Advisory only: a failed check must never get in the way.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [workspaceId, isViewer, suppress, api]);

  const dismiss = async () => {
    setOpen(false);
    try {
      const { current } = session;
      await api.putSession(workspaceId, FLOW, {
        status: 'dismissed',
        expectedRevision: current?.revision ?? 0,
      });
    } catch (_) {
      /* worst case the invitation shows once more */
    }
  };

  const start = () => {
    setOpen(false);
    onStart?.();
  };

  if (!open || suppress) return null;

  return (
    <Modal
      isOpen
      onClose={dismiss}
      isCentered
      size='md'
      closeOnOverlayClick
      closeOnEsc
      initialFocusRef={primaryRef}
    >
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame maxW='520px'>
        <ModalHeader
          {...headerProps}
          pr={headerProps.px}
          textAlign='center'
          display='flex'
          justifyContent='center'
        >
          <VStack spacing={3} align='center' w='full' maxW='400px' mx='auto'>
            <Icon as={FaRocket} w={8} h={8} color={modalTokens.focusBorder} />
            <DashboardModalTitle color={modalTokens.text} textAlign='center'>
              Your workspace is empty
            </DashboardModalTitle>
            <DashboardModalDescription
              color={modalTokens.muted}
              textAlign='center'
            >
              Nothing is being watched yet, so no alerts can fire.
            </DashboardModalDescription>
          </VStack>
        </ModalHeader>
        <ModalBody {...bodyProps}>
          <VStack spacing={2} textAlign='center'>
            <Text fontSize='sm' color={modalTokens.text}>
              The setup guide gets you to something working in a few minutes:
              monitor a site or add assets, then choose who gets alerted.
            </Text>
            <Text fontSize='xs' color={modalTokens.muted}>
              You can reopen it any time from Preferences.
            </Text>
          </VStack>
        </ModalBody>
        <ModalFooter {...footerProps} justifyContent='center'>
          <HStack spacing={3} flexWrap='wrap' justify='center' w='full'>
            <Button ref={primaryRef} onClick={start} {...primaryButtonProps}>
              Set up my environment
            </Button>
            <Button onClick={dismiss} {...outlineButtonProps}>
              Not now
            </Button>
          </HStack>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}
