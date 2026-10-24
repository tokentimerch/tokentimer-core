import { useRef } from 'react';
import {
  Modal,
  ModalOverlay,
  ModalHeader,
  ModalBody,
  ModalFooter,
  Button,
  VStack,
  Text,
  Link,
  Box,
  Icon,
  HStack,
} from '@chakra-ui/react';
import {
  DashboardModalFrame,
  DashboardModalDescription,
  DashboardModalTitle,
  useDashboardModalProps,
} from './DashboardModalFrame.jsx';
import { FaRocket, FaCheckCircle } from 'react-icons/fa';
import { FiPlay } from 'react-icons/fi';
import { SELF_HOSTED_DOCS_BASE } from '../utils/docsUrls';

function WelcomeModal({
  isOpen,
  onClose,
  data,
  displayName,
  emailSent = true,
  onStartSetup,
  introductionVideoUrl,
}) {
  const primaryActionRef = useRef(null);
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    fieldProps,
    outlineButtonProps,
    primaryButtonProps,
    tokens: modalTokens,
  } = useDashboardModalProps();
  const showSetupAction = Boolean(onStartSetup);
  const showIntroVideoAction = Boolean(introductionVideoUrl);

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      isCentered
      scrollBehavior='inside'
      size='md'
      closeOnOverlayClick
      closeOnEsc
      initialFocusRef={primaryActionRef}
    >
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame maxW='560px'>
        <ModalHeader
          {...headerProps}
          pr={headerProps.px}
          textAlign='center'
          display='flex'
          justifyContent='center'
        >
          <VStack spacing={3} align='center' w='full' maxW='420px' mx='auto'>
            <Icon as={FaRocket} w={8} h={8} color={modalTokens.focusBorder} />
            <DashboardModalTitle color={modalTokens.text} textAlign='center'>
              Welcome on board!
            </DashboardModalTitle>
            <DashboardModalDescription
              color={modalTokens.muted}
              textAlign='center'
              maxW='420px'
            >
              Your TokenTimer account is ready.
            </DashboardModalDescription>
          </VStack>
        </ModalHeader>

        <ModalBody {...bodyProps}>
          <VStack spacing={4} textAlign='center'>
            <Box>
              <Text
                fontSize={{ base: 'md', md: 'lg' }}
                fontWeight='semibold'
                color={modalTokens.text}
                mb={2}
              >
                Hi {data?.userName || displayName || 'there'}!
              </Text>
              <Text color={modalTokens.subtleText} fontSize='sm'>
                Your TokenTimer account has been created successfully.
              </Text>
            </Box>

            <Box {...fieldProps} p={4} w='full'>
              <VStack spacing={3}>
                <Icon
                  as={FaCheckCircle}
                  w={6}
                  h={6}
                  color={modalTokens.focusBorder}
                />
                <Text
                  fontSize='sm'
                  color={modalTokens.text}
                  fontWeight='semibold'
                >
                  {emailSent ? 'Account Ready!' : 'Email Verified!'}
                </Text>
                <Text fontSize='sm' color={modalTokens.subtleText}>
                  {emailSent
                    ? 'Your account has been created and is ready to use.'
                    : 'Your email has been verified and your account is now active.'}
                </Text>
                <Text fontSize='xs' color={modalTokens.muted}>
                  You can start managing your tokens right away.
                </Text>
              </VStack>
            </Box>

            <Box {...fieldProps} p={4} w='full'>
              <Text fontSize='sm' color={modalTokens.text}>
                <strong>
                  {showSetupAction ? 'Set up your environment' : "What's next?"}
                </strong>
              </Text>
              <VStack spacing={2} mt={2} align='start'>
                {showSetupAction ? (
                  <>
                    <Text fontSize='xs' color={modalTokens.muted}>
                      A guided setup that leaves you with something working.
                      Websites, assets and alerts take about 2 minutes:
                    </Text>
                    <Text fontSize='xs' color={modalTokens.muted}>
                      Monitor a website certificate or track a key, secret or
                      license
                    </Text>
                    <Text fontSize='xs' color={modalTokens.muted}>
                      Import from a file, GitHub, GitLab, Vault, AWS and more
                    </Text>
                    <Text fontSize='xs' color={modalTokens.muted}>
                      Choose who gets alerted, by email or webhook
                    </Text>
                    <Text fontSize='xs' color={modalTokens.muted}>
                      Discover and renew certificates on your servers (needs a
                      server, about 20 minutes)
                    </Text>
                    <Text fontSize='xs' color={modalTokens.muted}>
                      Progress is saved. Reopen the guide any time from
                      Preferences.
                    </Text>
                  </>
                ) : (
                  <>
                    <Text fontSize='xs' color={modalTokens.muted}>
                      Add your first token or secret
                    </Text>
                    <Text fontSize='xs' color={modalTokens.muted}>
                      Set up your contact groups and thresholds
                    </Text>
                  </>
                )}
                {showIntroVideoAction && (
                  <Text fontSize='xs' color={modalTokens.muted}>
                    <Link
                      href={introductionVideoUrl}
                      isExternal
                      onClick={onClose}
                      color={modalTokens.focusBorder}
                      textDecoration='underline'
                      _hover={{ textDecoration: 'underline' }}
                    >
                      Watch the introduction video
                    </Link>
                  </Text>
                )}
                <Text fontSize='xs' color={modalTokens.muted}>
                  <Link
                    href={SELF_HOSTED_DOCS_BASE}
                    isExternal
                    color={modalTokens.focusBorder}
                    textDecoration='underline'
                  >
                    Check the documentation to see how it works
                  </Link>
                </Text>
                <Text fontSize='xs' color={modalTokens.muted}>
                  Add your first token or secret
                </Text>
                <Text fontSize='xs' color={modalTokens.muted}>
                  Set up your contact groups and thresholds
                </Text>
              </VStack>
            </Box>
          </VStack>
        </ModalBody>

        <ModalFooter {...footerProps} justifyContent='center'>
          <HStack spacing={3} flexWrap='wrap' justify='center' w='full'>
            {showIntroVideoAction && (
              <Button
                as='a'
                href={introductionVideoUrl}
                target='_blank'
                rel='noopener noreferrer'
                leftIcon={<Icon as={FiPlay} />}
                onClick={onClose}
                {...outlineButtonProps}
              >
                Watch Video
              </Button>
            )}
            <Button
              ref={primaryActionRef}
              onClick={showSetupAction ? onStartSetup : onClose}
              {...primaryButtonProps}
            >
              {showSetupAction
                ? 'Set up my environment'
                : emailSent
                  ? 'Go to Dashboard'
                  : 'Get Started'}
            </Button>
            {showSetupAction && (
              <Button onClick={onClose} {...outlineButtonProps}>
                {emailSent ? 'Go to Dashboard' : 'Skip for now'}
              </Button>
            )}
          </HStack>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}

export default WelcomeModal;
