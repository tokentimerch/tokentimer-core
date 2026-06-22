import { useState, useEffect } from 'react';
import { logger } from '../utils/logger.js';
import {
  Box,
  Button,
  Text,
  VStack,
  HStack,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  Modal,
  ModalOverlay,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  useDisclosure,
  Divider,
  Flex,
  Circle,
  Icon,
  SimpleGrid,
  useColorModeValue,
  FormControl,
  FormLabel,
  Input,
  Link,
} from '@chakra-ui/react';
import { FiChevronRight, FiSettings, FiUser } from 'react-icons/fi';
import SEO from '../components/SEO.jsx';
import DashboardPageLayout from '../components/DashboardPageLayout';
import {
  DashboardActionButton,
  DashboardPanel,
  DashboardPanelHeader,
} from '../components/DashboardPrimitives';
import {
  DashboardModalFrame,
  DashboardModalDescription,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../components/DashboardModalFrame.jsx';
import { SettingsFormWidth } from '../components/SettingsPageShell.jsx';
import { useDashboardTheme } from '../hooks/useDashboardTheme';
import apiClient, { workspaceAPI } from '../utils/apiClient';
import { showSuccess } from '../utils/toast.js';
import { useWorkspace } from '../utils/WorkspaceContext.jsx';
import { Link as RouterLink } from 'react-router-dom';
import { trackEvent } from '../utils/analytics.js';

function resolveLoginMethodDisplay(session) {
  const providerSlug = session?.ssoProviderSlug;
  const method = String(session?.authMethod || 'local').toLowerCase();
  const isSsoSession =
    providerSlug ||
    session?.loginMethod === 'sso' ||
    ['sso', 'saml', 'oidc'].includes(method);

  if (isSsoSession) {
    const providerLabel = providerSlug
      ? ` (${providerSlug.replace(/-/g, ' ')})`
      : '';
    return {
      label: `Single Sign-On${providerLabel}`,
      colorScheme: 'purple',
    };
  }
  if (method === 'local') {
    return { label: 'Email and password', colorScheme: 'green' };
  }
  if (method === 'google') {
    return { label: 'Google', colorScheme: 'blue' };
  }
  return { label: method, colorScheme: 'gray' };
}

function AccountDetailRow({
  label,
  children,
  muted,
  text,
  showDivider = false,
}) {
  return (
    <>
      <Flex
        direction='row'
        align='center'
        gap={2}
        flexWrap='wrap'
        px={{ base: 3, md: 4 }}
        py={3}
      >
        <Text
          color={muted}
          fontSize='sm'
          fontWeight='semibold'
          minW='fit-content'
        >
          {label}:
        </Text>
        <Box color={text} fontSize='sm' minW={0} wordBreak='break-word'>
          {children}
        </Box>
      </Flex>
      {showDivider ? <Divider opacity={0.65} /> : null}
    </>
  );
}

function AccountSettingsLinkCard({
  to,
  title,
  description,
  icon,
  border,
  muted,
}) {
  const { dashboard } = useDashboardTheme();
  const hoverBg = dashboard.accent.interactiveSurface;
  const hoverBorder = dashboard.accent.interactiveBorder;
  const iconBg = dashboard.accent.interactiveSurface;
  const iconColor = dashboard.accent.interactiveForeground;

  return (
    <Link
      as={RouterLink}
      to={to}
      _hover={{ textDecoration: 'none' }}
      display='block'
    >
      <HStack
        p={3}
        border='1px solid'
        borderColor={border}
        borderRadius='md'
        spacing={3}
        transition='background 0.15s ease, border-color 0.15s ease'
        _hover={{ bg: hoverBg, borderColor: hoverBorder }}
      >
        <Circle size='40px' bg={iconBg} color={iconColor} flexShrink={0}>
          <Icon as={icon} boxSize={4} aria-hidden />
        </Circle>
        <Box flex='1' minW={0}>
          <Text fontWeight='semibold' fontSize='sm' lineHeight='short'>
            {title}
          </Text>
          <Text fontSize='sm' color={muted} lineHeight='1.45' mt={0.5}>
            {description}
          </Text>
        </Box>
        <Icon as={FiChevronRight} boxSize={4} color={muted} flexShrink={0} />
      </HStack>
    </Link>
  );
}

function AccountSecuritySection({
  title,
  description,
  text,
  muted,
  children,
  showDivider = false,
}) {
  return (
    <>
      <Box px={{ base: 3, md: 4 }} py={4}>
        <Text
          color={text}
          fontSize='sm'
          fontWeight='semibold'
          lineHeight='short'
        >
          {title}
        </Text>
        <Text fontSize='sm' color={muted} lineHeight='1.45' mt={0.5} mb={4}>
          {description}
        </Text>
        {children}
      </Box>
      {showDivider ? <Divider opacity={0.65} /> : null}
    </>
  );
}

function AccountProfileIdentity({
  session,
  text,
  muted,
  profileIconBg,
  profileIconColor,
  sessionInitials,
}) {
  return (
    <HStack spacing={4} align='flex-start'>
      <Circle
        size='56px'
        bg={profileIconBg}
        color={profileIconColor}
        fontWeight='bold'
        fontSize='md'
        flexShrink={0}
      >
        {sessionInitials || <Icon as={FiUser} boxSize={5} aria-hidden />}
      </Circle>
      <Box minW={0}>
        <Text
          fontSize='sm'
          fontWeight='semibold'
          color={text}
          lineHeight='short'
          wordBreak='break-word'
        >
          {session.displayName}
        </Text>
        <Text fontSize='sm' color={muted} mt={0.5} wordBreak='break-all'>
          {session.email}
        </Text>
      </Box>
    </HStack>
  );
}

function Account({
  session,
  onAccountDeleted,
  onLogout,
  onAccountClick,
  onSessionUpdate,
}) {
  const loginMethodDisplay = resolveLoginMethodDisplay(session);
  const { selectWorkspace: _selectWorkspace } = useWorkspace();
  const { border, text, muted, bodySecondary, dashboard } = useDashboardTheme();
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    outlineButtonProps,
    primaryButtonProps,
    dangerButtonProps,
    tokens: modalTokens,
  } = useDashboardModalProps();
  const [canSeeManagerNav, setCanSeeManagerNav] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [error, setError] = useState('');
  const [info, _setInfo] = useState('');
  const [pwdMessage, setPwdMessage] = useState('');
  const [pwdError, setPwdError] = useState('');
  const [twoFaError, setTwoFaError] = useState('');
  const [isPwdSaving, setIsPwdSaving] = useState(false);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmNewPassword, setConfirmNewPassword] = useState('');
  const [qrData, setQrData] = useState('');
  const [secret, setSecret] = useState('');
  const [_otpAuth, setOtpAuth] = useState('');
  const [twoFaCode, setTwoFaCode] = useState('');
  const [disablePwd, setDisablePwd] = useState('');
  const { isOpen, onOpen, onClose } = useDisclosure();
  const {
    isOpen: isTwoFaWizardOpen,
    onOpen: onTwoFaWizardOpen,
    onClose: onTwoFaWizardClose,
  } = useDisclosure();

  const profileIconBg = useColorModeValue('blue.50', 'whiteAlpha.100');
  const profileIconColor = useColorModeValue('blue.600', 'blue.200');
  const isGoogleAuth =
    String(session?.authMethod || '').toLowerCase() === 'google';
  const sessionInitials = String(session?.displayName || session?.email || 'U')
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map(part => part[0])
    .join('')
    .toUpperCase();
  const formLabelProps = {
    color: bodySecondary,
    fontSize: 'sm',
    fontWeight: 'medium',
    mb: 2,
  };

  useEffect(() => {
    let cancelled = false;

    async function loadManagerNav() {
      if (!session) {
        if (!cancelled) setCanSeeManagerNav(false);
        return;
      }
      const isSystemAdmin = session.isAdmin === true;
      try {
        const ws = await workspaceAPI.list(50, 0);
        if (cancelled) return;
        const items = ws?.items || [];
        const roles = items.map(w => String(w.role || '').toLowerCase());
        const hasManagerOrAdmin =
          roles.includes('admin') || roles.includes('workspace_manager');
        setCanSeeManagerNav(isSystemAdmin || hasManagerOrAdmin);
      } catch (_) {
        if (!cancelled) setCanSeeManagerNav(isSystemAdmin);
      }
    }

    loadManagerNav();
    return () => {
      cancelled = true;
    };
  }, [session]);

  const layoutProps = {
    variant: 'wide',
    pageTitle: 'Account Settings',
    session,
    onLogout,
    onAccountClick,
    contentProps: { w: 'full', maxW: '100%' },
  };

  const closeTwoFaWizard = () => {
    onTwoFaWizardClose();
    setQrData('');
    setSecret('');
    setOtpAuth('');
    setTwoFaCode('');
    setTwoFaError('');
  };

  const startTwoFaSetup = async () => {
    setTwoFaError('');
    onTwoFaWizardOpen();
    try {
      const { data } = await apiClient.post('/api/account/2fa/setup');
      setOtpAuth(data.otpauth || '');
      setQrData(data.qr || '');
      setSecret(data.secret || '');
    } catch (e) {
      const msg = e?.response?.data?.error || 'Failed to start 2FA setup';
      setTwoFaError(msg);
    }
  };

  if (!session) {
    return (
      <>
        <SEO
          title='Account Settings'
          description='Manage your profile, password, security, and data export.'
          noindex
        />
        <DashboardPageLayout {...layoutProps}>
          <VStack spacing={6} align='stretch' w='full'>
            <Alert status='error'>
              <AlertIcon />
              <AlertDescription>
                Session not found. Please log in again.
              </AlertDescription>
            </Alert>
          </VStack>
        </DashboardPageLayout>
      </>
    );
  }

  const handleDeleteAccount = async () => {
    setIsDeleting(true);
    setError('');

    try {
      await apiClient.delete('/api/account');

      try {
        trackEvent('account_deletion');
      } catch (_) {}
      onAccountDeleted();
    } catch (err) {
      logger.error('Account deletion error:', err);
      const status = err?.response?.status;
      const data = err?.response?.data;
      if (status === 409 && data?.code === 'ONLY_ADMIN') {
        try {
          const names = Array.isArray(data?.workspaces)
            ? data.workspaces.map(w => w.name).join(', ')
            : 'listed workspaces';
          // eslint-disable-next-line no-alert
          const ok = window.confirm(
            `You are the only admin of: ${names}.\nIf you continue, these workspaces and their data will be deleted.\nDo you want to proceed?`
          );
          if (ok) {
            await apiClient.delete('/api/account', { params: { force: 1 } });
            try {
              trackEvent('account_deletion_force');
            } catch (_) {}
            onAccountDeleted();
            return;
          }
          setError('Account deletion canceled.');
        } catch (_) {
          setError(
            'You are the only admin of one or more workspaces. Transfer admin rights or delete those workspaces before deleting your account.'
          );
        }
      } else {
        setError('Failed to delete account. Please try again.');
      }
      setIsDeleting(false);
    }
  };

  const handleExportData = async () => {
    try {
      const response = await apiClient.get('/api/account/export', {
        responseType: 'blob',
      });

      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute(
        'download',
        `tokentimer-data-${new Date().toISOString().split('T')[0]}.json`
      );
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      logger.error('Data export error:', err);
      setError('Failed to export data. Please try again.');
    }
  };

  return (
    <>
      <SEO
        title='Account Settings'
        description='Manage your profile, password, security, and data export.'
        noindex
      />
      <DashboardPageLayout {...layoutProps}>
        <VStack spacing={6} align='stretch' w='full'>
          <DashboardPanel p={{ base: 4, md: 5 }}>
            <DashboardPanelHeader
              title='Profile'
              description='Your sign-in identity for this account.'
            />
            {info && (
              <Alert status='success' mb={4} borderRadius='md'>
                <AlertIcon />
                <AlertDescription>{info}</AlertDescription>
              </Alert>
            )}
            <Box
              border='1px solid'
              borderColor={border}
              borderRadius='md'
              overflow='hidden'
              px={{ base: 3, md: 4 }}
              py={4}
              mb={4}
            >
              <AccountProfileIdentity
                session={session}
                text={text}
                muted={bodySecondary}
                profileIconBg={profileIconBg}
                profileIconColor={profileIconColor}
                sessionInitials={sessionInitials}
              />
            </Box>
            <Box
              border='1px solid'
              borderColor={border}
              borderRadius='md'
              overflow='hidden'
            >
              <AccountDetailRow
                label='Login method'
                muted={bodySecondary}
                text={text}
                showDivider
              >
                {loginMethodDisplay.label}
              </AccountDetailRow>
              <AccountDetailRow
                label='Account created'
                muted={bodySecondary}
                text={text}
              >
                {new Date(
                  session.created_at || Date.now()
                ).toLocaleDateString()}
              </AccountDetailRow>
            </Box>
          </DashboardPanel>

          <SimpleGrid columns={{ base: 1, xl: 2 }} spacing={6} w='full'>
            <DashboardPanel p={{ base: 4, md: 5 }}>
              <DashboardPanelHeader
                title='Security'
                description='Password and two-factor authentication for this account.'
              />
              {isGoogleAuth ? (
                <Alert status='info' borderRadius='md'>
                  <AlertIcon />
                  <AlertDescription>
                    This account uses Google sign-in. Password and 2FA settings
                    are managed in your Google account.
                  </AlertDescription>
                </Alert>
              ) : (
                <>
                  {pwdMessage && (
                    <Alert status='success' mb={4} borderRadius='md'>
                      <AlertIcon />
                      <AlertDescription>{pwdMessage}</AlertDescription>
                    </Alert>
                  )}
                  {pwdError && (
                    <Alert status='error' mb={4} borderRadius='md'>
                      <AlertIcon />
                      <AlertDescription>{pwdError}</AlertDescription>
                    </Alert>
                  )}

                  <Box
                    border='1px solid'
                    borderColor={border}
                    borderRadius='md'
                    overflow='hidden'
                  >
                    <AccountSecuritySection
                      title='Change password'
                      description='Use at least 8 characters with uppercase, lowercase, and a number.'
                      text={text}
                      muted={bodySecondary}
                      showDivider
                    >
                      <SettingsFormWidth maxW='100%'>
                        <form
                          onSubmit={async e => {
                            e.preventDefault();
                            setPwdMessage('');
                            setPwdError('');
                            setIsPwdSaving(true);
                            try {
                              if (newPassword !== confirmNewPassword) {
                                setPwdError(
                                  'New password and confirmation do not match'
                                );
                                setIsPwdSaving(false);
                                return;
                              }
                              const { data } = await apiClient.post(
                                '/api/account/change-password',
                                { currentPassword, newPassword }
                              );
                              setPwdMessage(
                                data.message || 'Password changed successfully'
                              );
                              setCurrentPassword('');
                              setNewPassword('');
                              setConfirmNewPassword('');
                            } catch (err) {
                              const msg =
                                err?.response?.data?.error ||
                                'Failed to change password';
                              setPwdError(msg);
                            } finally {
                              setIsPwdSaving(false);
                            }
                          }}
                        >
                          <VStack align='stretch' spacing={4}>
                            <FormControl>
                              <FormLabel {...formLabelProps}>
                                Current password
                              </FormLabel>
                              <Input
                                type='password'
                                autoComplete='current-password'
                                value={currentPassword}
                                onChange={e =>
                                  setCurrentPassword(e.target.value)
                                }
                                placeholder='Enter current password'
                              />
                            </FormControl>
                            <FormControl>
                              <FormLabel {...formLabelProps}>
                                New password
                              </FormLabel>
                              <Input
                                type='password'
                                autoComplete='new-password'
                                value={newPassword}
                                onChange={e => setNewPassword(e.target.value)}
                                placeholder='At least 8 chars, include Aa1!'
                              />
                            </FormControl>
                            <FormControl>
                              <FormLabel {...formLabelProps}>
                                Confirm new password
                              </FormLabel>
                              <Input
                                type='password'
                                autoComplete='new-password'
                                value={confirmNewPassword}
                                onChange={e =>
                                  setConfirmNewPassword(e.target.value)
                                }
                                placeholder='Re-enter new password'
                              />
                            </FormControl>
                            <HStack>
                              <DashboardActionButton
                                type='submit'
                                colorScheme='blue'
                                isLoading={isPwdSaving}
                                w={{ base: '100%', md: 'auto' }}
                              >
                                Update password
                              </DashboardActionButton>
                            </HStack>
                          </VStack>
                        </form>
                      </SettingsFormWidth>
                    </AccountSecuritySection>

                    <AccountSecuritySection
                      title='Two-factor authentication'
                      description={
                        session?.twoFactorEnabled
                          ? 'Your account requires a code from an authenticator app at sign-in.'
                          : 'Add an authenticator app for stronger account protection.'
                      }
                      text={text}
                      muted={bodySecondary}
                    >
                      <SettingsFormWidth>
                        <VStack align='stretch' spacing={3} w='full'>
                          {session?.twoFactorEnabled ? (
                            <>
                              <FormControl>
                                <FormLabel {...formLabelProps}>
                                  Confirm password to disable 2FA
                                </FormLabel>
                                <Input
                                  type='password'
                                  autoComplete='current-password'
                                  placeholder='Enter your current password'
                                  value={disablePwd}
                                  onChange={e => setDisablePwd(e.target.value)}
                                />
                              </FormControl>
                              <HStack>
                                <DashboardActionButton
                                  variant='outline'
                                  colorScheme='red'
                                  w={{ base: '100%', md: 'auto' }}
                                  onClick={async () => {
                                    setTwoFaError('');
                                    try {
                                      const { data } = await apiClient.post(
                                        '/api/account/2fa/disable',
                                        { currentPassword: disablePwd }
                                      );
                                      showSuccess(
                                        data.message ||
                                          'Two-factor authentication disabled'
                                      );
                                      onSessionUpdate?.({
                                        twoFactorEnabled: false,
                                      });
                                      setDisablePwd('');
                                    } catch (e) {
                                      const msg =
                                        e?.response?.data?.error ||
                                        'Failed to disable 2FA';
                                      setTwoFaError(msg);
                                    }
                                  }}
                                >
                                  Disable 2FA
                                </DashboardActionButton>
                              </HStack>
                            </>
                          ) : (
                            <HStack>
                              <DashboardActionButton
                                colorScheme='blue'
                                w={{ base: '100%', md: 'auto' }}
                                onClick={startTwoFaSetup}
                              >
                                Set up 2FA
                              </DashboardActionButton>
                            </HStack>
                          )}
                          {twoFaError && !isTwoFaWizardOpen && (
                            <Alert status='error' borderRadius='md'>
                              <AlertIcon />
                              <AlertDescription>{twoFaError}</AlertDescription>
                            </Alert>
                          )}
                        </VStack>
                      </SettingsFormWidth>
                    </AccountSecuritySection>
                  </Box>
                </>
              )}
            </DashboardPanel>

            <DashboardPanel p={{ base: 4, md: 5 }}>
              <DashboardPanelHeader
                title='Data'
                description='Export your account data or jump to related settings.'
              />
              <VStack align='stretch' spacing={4}>
                <Box
                  border='1px solid'
                  borderColor={border}
                  borderRadius='md'
                  px={{ base: 3, md: 4 }}
                  py={4}
                >
                  <Text
                    color={text}
                    fontSize='sm'
                    fontWeight='semibold'
                    lineHeight='short'
                  >
                    Export my data
                  </Text>
                  <Text
                    fontSize='sm'
                    color={bodySecondary}
                    lineHeight='1.45'
                    mt={0.5}
                  >
                    Download a JSON backup of your profile, settings, and tokens
                    you can access. For audit history, use the Audit export
                    page.
                  </Text>
                  <DashboardActionButton
                    onClick={handleExportData}
                    colorScheme='blue'
                    variant='outline'
                    mt={3}
                    w={{ base: '100%', md: 'auto' }}
                  >
                    Export my data
                  </DashboardActionButton>
                </Box>

                <AccountSettingsLinkCard
                  to='/preferences'
                  title='User preferences'
                  description='Theme, product tour, and documentation links.'
                  icon={FiUser}
                  border={border}
                  muted={bodySecondary}
                />
                {canSeeManagerNav ? (
                  <AccountSettingsLinkCard
                    to='/workspace-preferences'
                    title='Workspace preferences'
                    description='Alert thresholds, contacts, webhooks, and delivery windows.'
                    icon={FiSettings}
                    border={border}
                    muted={bodySecondary}
                  />
                ) : null}
              </VStack>
            </DashboardPanel>
          </SimpleGrid>

          <DashboardPanel
            p={{ base: 4, md: 5 }}
            bg={dashboard.callout.dangerSurface}
            borderColor={dashboard.callout.dangerBorder}
          >
            <DashboardPanelHeader
              title='Danger zone'
              description='Destructive account actions that cannot be undone.'
            />
            <Alert status='warning' mb={4} borderRadius='md'>
              <AlertIcon />
              <Box>
                <AlertTitle fontSize='sm' fontWeight='semibold'>
                  Account deletion
                </AlertTitle>
                <AlertDescription>
                  This permanently deletes your account and removes associated
                  data you own in this deployment.
                </AlertDescription>
              </Box>
            </Alert>

            {error && (
              <Alert status='error' mb={4} borderRadius='md'>
                <AlertIcon />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <DashboardActionButton
              colorScheme='red'
              onClick={onOpen}
              w={{ base: '100%', md: 'auto' }}
            >
              Delete my account
            </DashboardActionButton>
          </DashboardPanel>
        </VStack>

        <Modal
          isOpen={isTwoFaWizardOpen}
          onClose={closeTwoFaWizard}
          isCentered
          size='md'
          scrollBehavior='inside'
        >
          <ModalOverlay {...overlayProps} />
          <DashboardModalFrame maxW='520px'>
            <ModalHeader {...headerProps}>
              <DashboardModalTitle>
                Set up two-factor authentication
              </DashboardModalTitle>
              <DashboardModalDescription>
                Scan the QR code, then enter the 6-digit code from your app.
              </DashboardModalDescription>
            </ModalHeader>
            <ModalCloseButton {...closeButtonProps} />
            <ModalBody {...bodyProps}>
              <VStack align='stretch' spacing={4}>
                <Box w='full' display='flex' justifyContent='center'>
                  {qrData ? (
                    <img
                      src={qrData}
                      alt='2FA QR'
                      style={{
                        width: '200px',
                        height: '200px',
                        display: 'block',
                      }}
                    />
                  ) : (
                    <Box
                      w='200px'
                      h='200px'
                      border='1px dashed'
                      borderColor={border}
                      borderRadius='md'
                      display='flex'
                      alignItems='center'
                      justifyContent='center'
                      color={bodySecondary}
                    >
                      Loading QR code...
                    </Box>
                  )}
                </Box>
                {secret && (
                  <Text fontSize='xs' color={bodySecondary} textAlign='center'>
                    Secret: {secret}
                  </Text>
                )}
                <FormControl>
                  <FormLabel {...formLabelProps}>Authenticator code</FormLabel>
                  <Input
                    type='text'
                    inputMode='numeric'
                    pattern='[0-9]*'
                    placeholder='Enter 6-digit code'
                    value={twoFaCode}
                    onChange={e => setTwoFaCode(e.target.value)}
                  />
                </FormControl>
                {twoFaError && (
                  <Alert status='error' borderRadius='md'>
                    <AlertIcon />
                    <AlertDescription>{twoFaError}</AlertDescription>
                  </Alert>
                )}
              </VStack>
            </ModalBody>
            <ModalFooter {...footerProps}>
              <Button onClick={closeTwoFaWizard} mr={3} {...outlineButtonProps}>
                Cancel
              </Button>
              <Button
                isDisabled={!twoFaCode.trim()}
                onClick={async () => {
                  setTwoFaError('');
                  try {
                    const { data } = await apiClient.post(
                      '/api/account/2fa/enable',
                      { token: twoFaCode }
                    );
                    showSuccess(
                      data.message || 'Two-factor authentication enabled'
                    );
                    onSessionUpdate?.({ twoFactorEnabled: true });
                    setTwoFaCode('');
                    closeTwoFaWizard();
                  } catch (e) {
                    const msg =
                      e?.response?.data?.error || 'Failed to enable 2FA';
                    setTwoFaError(msg);
                  }
                }}
                {...primaryButtonProps}
              >
                Confirm & Enable
              </Button>
            </ModalFooter>
          </DashboardModalFrame>
        </Modal>

        <Modal
          isOpen={isOpen}
          onClose={onClose}
          isCentered
          scrollBehavior='inside'
        >
          <ModalOverlay {...overlayProps} />
          <DashboardModalFrame maxW='560px'>
            <ModalHeader {...headerProps}>
              <DashboardModalTitle color={dashboard.state.danger}>
                Delete account
              </DashboardModalTitle>
              <DashboardModalDescription>
                Confirm this permanent account action.
              </DashboardModalDescription>
            </ModalHeader>
            <ModalCloseButton {...closeButtonProps} />
            <ModalBody {...bodyProps}>
              <VStack spacing={4} align='stretch'>
                <Alert status='error'>
                  <AlertIcon />
                  <Box>
                    <AlertTitle fontSize='sm' fontWeight='semibold'>
                      This action is irreversible!
                    </AlertTitle>
                    <AlertDescription>
                      All your tokens, account data, and settings will be
                      permanently deleted.
                    </AlertDescription>
                  </Box>
                </Alert>
                <Text fontSize='sm' color={bodySecondary}>
                  Deleting your account removes your personal workspace data and
                  memberships. Other workspace data remains according to
                  ownership and role rules.
                </Text>
                <Text fontSize='sm' color={modalTokens.text}>
                  Are you sure you want to delete your account{' '}
                  <strong>{session.displayName}</strong>?
                </Text>
                <Text fontSize='sm' color={bodySecondary}>
                  Consider exporting your data first if you need a backup.
                </Text>
              </VStack>
            </ModalBody>
            <ModalFooter {...footerProps}>
              <Flex
                w='100%'
                gap={3}
                justify={{ base: 'stretch', sm: 'flex-end' }}
                direction={{ base: 'column-reverse', sm: 'row' }}
              >
                <Button
                  onClick={onClose}
                  minW={{ base: '100%', sm: '104px' }}
                  {...outlineButtonProps}
                >
                  Cancel
                </Button>
                <Button
                  onClick={handleDeleteAccount}
                  isLoading={isDeleting}
                  loadingText='Deleting...'
                  minW={{ base: '100%', sm: '180px' }}
                  {...dangerButtonProps}
                >
                  Yes, delete my account
                </Button>
              </Flex>
            </ModalFooter>
          </DashboardModalFrame>
        </Modal>
      </DashboardPageLayout>
    </>
  );
}

export default Account;
