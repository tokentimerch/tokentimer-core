import { useRef } from 'react';
import { SELF_HOSTED_DOCS_BASE } from '../utils/docsUrls';
import {
  Modal,
  ModalOverlay,
  ModalHeader,
  ModalBody,
  ModalFooter,
  ModalCloseButton,
  Button,
  VStack,
  Text,
  Link,
  Box,
  Icon,
  HStack,
  Stack,
  List,
  ListItem,
  useColorModeValue,
} from '@chakra-ui/react';
import {
  DashboardModalFrame,
  DashboardModalDescription,
  DashboardModalTitle,
  useDashboardModalProps,
} from './DashboardModalFrame.jsx';
import {
  FiPlay,
  FiShield,
  FiDownload,
  FiBell,
  FiServer,
  FiArrowRight,
  FiBookOpen,
  FiClock,
  FiCheck,
  FiCheckCircle,
} from 'react-icons/fi';

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
    closeButtonProps,
    fieldProps,
    primaryButtonProps,
    tokens,
  } = useDashboardModalProps();
  const accentBg = useColorModeValue('blue.50', 'rgba(59, 130, 246, 0.1)');
  const accent = tokens.sectionAccent;
  const showSetupAction = Boolean(onStartSetup);
  const name = data?.userName || displayName;
  const steps = showSetupAction
    ? [
        {
          icon: FiShield,
          title: 'Monitor what matters',
          description: 'Website certificates, keys, secrets and licenses.',
        },
        {
          icon: FiDownload,
          title: 'Bring your assets together',
          description:
            'Import from a file, GitHub, GitLab, Vault, AWS and more.',
        },
        {
          icon: FiBell,
          title: 'Stay ahead of expiry',
          description: 'Choose who gets alerted by email or webhook.',
        },
      ]
    : [
        {
          icon: FiShield,
          title: 'Add your first token or secret',
          description: 'Keep its expiration in sight.',
        },
        {
          icon: FiBell,
          title: 'Set up your alerts',
          description: 'Choose contact groups and alert thresholds.',
        },
      ];

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
      <DashboardModalFrame maxW='560px' fontFamily='body' fontWeight='normal'>
        <ModalCloseButton {...closeButtonProps} />
        <ModalHeader
          {...headerProps}
          pr={{ base: 5, md: 6 }}
          textAlign='center'
          bgGradient={`linear(to-b, ${accentBg}, transparent)`}
        >
          <VStack spacing={3} px={5}>
            <Box
              display='flex'
              alignItems='center'
              justifyContent='center'
              boxSize='48px'
              borderRadius='xl'
              bg={accentBg}
              color={accent}
            >
              <Icon as={FiShield} boxSize={6} />
            </Box>
            <Box>
              <HStack justify='center' spacing={1.5} mb={2} color={accent}>
                <Icon as={FiCheckCircle} boxSize={3.5} />
                <Text fontSize='xs' fontFamily='body' fontWeight='medium'>
                  {emailSent
                    ? 'Your account is ready'
                    : 'Your email is verified'}
                </Text>
              </HStack>
              <DashboardModalTitle
                fontSize={{ base: 'xl', md: '2xl' }}
                letterSpacing='-0.02em'
              >
                {name ? `Welcome, ${name}!` : 'Welcome to TokenTimer'}
              </DashboardModalTitle>
              <DashboardModalDescription
                fontFamily='body'
                fontWeight='normal'
                fontSize='sm'
                maxW='360px'
                mx='auto'
              >
                Keep your certificates and secrets one step ahead of expiry.
              </DashboardModalDescription>
            </Box>
          </VStack>
        </ModalHeader>
        <ModalBody {...bodyProps}>
          <VStack spacing={4} align='stretch'>
            <Box {...fieldProps} p={{ base: 4, md: 5 }}>
              <HStack
                justify='space-between'
                align='start'
                spacing={2}
                mb={4}
                flexWrap='wrap'
              >
                <Text
                  fontFamily='heading'
                  fontWeight='semibold'
                  fontSize='md'
                  color={tokens.text}
                >
                  {showSetupAction
                    ? 'Start with the essentials'
                    : 'Your first steps'}
                </Text>
                {showSetupAction && (
                  <HStack
                    spacing={1}
                    color={tokens.muted}
                    flexShrink={0}
                    pt={0.5}
                  >
                    <Icon as={FiClock} boxSize={3} />
                    <Text fontSize='xs'>About 2 min</Text>
                  </HStack>
                )}
              </HStack>
              <List spacing={4}>
                {steps.map(({ icon, title, description }) => (
                  <ListItem key={title}>
                    <HStack spacing={3} align='start'>
                      <Box
                        display='flex'
                        alignItems='center'
                        justifyContent='center'
                        boxSize={8}
                        borderRadius='lg'
                        bg={accentBg}
                        color={accent}
                        flexShrink={0}
                      >
                        <Icon as={icon} boxSize={4} />
                      </Box>
                      <Box minW={0}>
                        <Text
                          fontSize='sm'
                          fontWeight='semibold'
                          color={tokens.text}
                        >
                          {title}
                        </Text>
                        <Text
                          mt={0.5}
                          fontSize='sm'
                          fontWeight='normal'
                          lineHeight='1.5'
                          color={tokens.subtleText}
                        >
                          {description}
                        </Text>
                      </Box>
                    </HStack>
                  </ListItem>
                ))}
              </List>
            </Box>
            {showSetupAction && (
              <>
                <HStack spacing={3} align='start' px={1}>
                  <Icon
                    as={FiServer}
                    boxSize={4}
                    mt={1}
                    color={tokens.muted}
                    flexShrink={0}
                  />
                  <Box minW={0}>
                    <HStack spacing={2} flexWrap='wrap'>
                      <Text
                        fontSize='sm'
                        fontWeight='semibold'
                        color={tokens.text}
                      >
                        Server certificates
                      </Text>
                      <Text fontSize='xs' color={tokens.muted}>
                        Optional · About 20 min
                      </Text>
                    </HStack>
                    <Text
                      mt={1}
                      fontSize='xs'
                      lineHeight='tall'
                      color={tokens.subtleText}
                    >
                      Discover and renew certificates on your servers. Requires
                      a server.
                    </Text>
                  </Box>
                </HStack>
                <HStack spacing={2} align='start' px={1} color={tokens.muted}>
                  <Icon as={FiCheck} boxSize={3.5} mt={0.5} flexShrink={0} />
                  <Text fontSize='xs' lineHeight='tall'>
                    Progress saved. Pick up where you left off in Preferences.
                  </Text>
                </HStack>
              </>
            )}
          </VStack>
        </ModalBody>
        <ModalFooter
          {...footerProps}
          display='block'
          sx={{ ...footerProps.sx, '& > *': { width: '100%' } }}
        >
          <VStack spacing={4} w='full'>
            <Stack
              direction={{ base: 'column', sm: 'row' }}
              spacing={2}
              w='full'
            >
              <Button
                ref={primaryActionRef}
                onClick={showSetupAction ? onStartSetup : onClose}
                {...primaryButtonProps}
                flex={1}
                minH='44px'
                rightIcon={
                  showSetupAction ? <Icon as={FiArrowRight} /> : undefined
                }
              >
                {showSetupAction
                  ? 'Start guided setup'
                  : emailSent
                    ? 'Go to Dashboard'
                    : 'Get Started'}
              </Button>
              {showSetupAction && (
                <Button
                  onClick={onClose}
                  variant='ghost'
                  color={tokens.subtleText}
                  minH='44px'
                >
                  Skip for now
                </Button>
              )}
            </Stack>
            <HStack
              spacing={5}
              justify='center'
              flexWrap='wrap'
              rowGap={2}
              fontSize='xs'
              color={tokens.subtleText}
            >
              <Link
                href={SELF_HOSTED_DOCS_BASE}
                isExternal
                display='inline-flex'
                alignItems='center'
                gap={1.5}
                _hover={{ color: accent, textDecoration: 'underline' }}
              >
                <Icon as={FiBookOpen} /> Setup documentation
              </Link>
              {introductionVideoUrl && (
                <Link
                  href={introductionVideoUrl}
                  isExternal
                  onClick={onClose}
                  display='inline-flex'
                  alignItems='center'
                  gap={1.5}
                  _hover={{ color: accent, textDecoration: 'underline' }}
                >
                  <Icon as={FiPlay} /> Watch introduction
                </Link>
              )}
            </HStack>
          </VStack>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}

export default WelcomeModal;
