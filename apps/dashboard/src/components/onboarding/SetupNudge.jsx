import { useEffect, useRef, useState } from 'react';
import {
  Button,
  HStack,
  Icon,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Text,
  VStack,
} from '@chakra-ui/react';
import { FaRocket } from 'react-icons/fa';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import { onboardingAPI } from '../../utils/onboardingApi.js';
import SetupBanner from './SetupBanner.jsx';
import {
  inviteKind,
  markChecked,
  markModalShown,
  wasChecked,
  wasModalShown,
} from './nudgeRules.js';

const FLOW = 'mega';

/**
 * Invites the owner of an empty workspace to the setup guide. Mounted once on
 * the dashboard. It opens a modal the first time, and from then on leaves a
 * slim banner for as long as the workspace is empty, so closing the modal by
 * accident never removes the way back. Only "Not now" and "Hide" stop it for
 * good; closing the modal with the X, Esc or a click outside does not.
 */
export default function SetupNudge({
  workspaceId,
  isViewer,
  suppress = false,
  onStart,
  api = onboardingAPI,
}) {
  // The answer belongs to the workspace it was computed for. Keeping the id
  // beside it means a switch can never show the previous workspace's banner,
  // whether or not the new one needs a fresh check.
  const [answer, setAnswer] = useState({
    workspaceId: null,
    mode: null, // null | 'modal' | 'banner'
    goalChosen: false,
  });
  const mode = answer.workspaceId === workspaceId ? answer.mode : null;
  const goalChosen = answer.workspaceId === workspaceId && answer.goalChosen;
  const setMode = next =>
    setAnswer(current => ({ ...current, workspaceId, mode: next }));
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
        session.current = s;
        const kind = inviteKind({
          session: s,
          summary,
          isViewer,
          modalShown: wasModalShown(workspaceId),
        });
        if (kind === 'modal') markModalShown(workspaceId);
        // Only an empty answer is final for this browser session; a banner is
        // checked again on each visit so it disappears once there is content.
        if (!kind) markChecked(workspaceId);
        setAnswer({
          workspaceId,
          mode: kind,
          goalChosen: Boolean(s?.intent?.goal),
        });
      } catch (_) {
        // Advisory only: a failed check must never get in the way.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [workspaceId, isViewer, suppress, api]);

  // "Not now" and "Hide": stop for good.
  const dismiss = async () => {
    setMode(null);
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

  // X, Esc, click outside: close for now, keep the way back.
  const later = () => setMode('banner');

  const start = () => {
    setMode(null);
    onStart?.();
  };

  if (!mode || suppress) return null;

  if (mode === 'banner') {
    return (
      <SetupBanner
        title='Your workspace is empty.'
        message='Nothing is being watched, so no alerts can fire.'
        actionLabel={goalChosen ? 'Continue setup' : 'Set up my environment'}
        onAction={start}
        onHide={dismiss}
      />
    );
  }

  return (
    <Modal
      isOpen
      onClose={later}
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
              Closing this keeps a reminder on the dashboard. Not now hides it
              for good, and you can reopen the guide any time from Preferences.
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
