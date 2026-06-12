import { useState, useEffect } from 'react';
import { logger } from '../utils/logger.js';
import {
  Box,
  Button,
  Text,
  VStack,
  HStack,
  Stack,
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
  Badge,
  Flex,
  Spacer,
  useColorModeValue,
  FormControl,
  FormLabel,
  Input,
  Link,
} from '@chakra-ui/react';
import SEO from '../components/SEO.jsx';
import DashboardPageLayout from '../components/DashboardPageLayout';
import {
  DashboardActionButton,
  DashboardPanel,
  DashboardPanelHeader,
} from '../components/DashboardPrimitives';
import {
  DashboardModalFrame,
  useDashboardModalProps,
} from '../components/DashboardModalFrame.jsx';
import { useDashboardTheme } from '../hooks/useDashboardTheme';
import apiClient, { workspaceAPI } from '../utils/apiClient';
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
    return { label: 'Email & Password', colorScheme: 'green' };
  }
  if (method === 'google') {
    return { label: 'Google', colorScheme: 'blue' };
  }
  return { label: method, colorScheme: 'gray' };
}

function AccountInfoRow({ label, children, muted, text }) {
  return (
    <Flex
      direction={{ base: 'column', sm: 'row' }}
      align={{ base: 'stretch', sm: 'center' }}
      gap={{ base: 1, sm: 0 }}
    >
      <Text color={muted} fontSize='sm' fontWeight='medium' minW='fit-content'>
        {label}:
      </Text>
      <Spacer display={{ base: 'none', sm: 'block' }} />
      <Box
        color={text}
        fontSize='sm'
        fontWeight='normal'
        minW={0}
        wordBreak='break-word'
      >
        {children}
      </Box>
    </Flex>
  );
}

function Account({ session, onAccountDeleted, onLogout, onAccountClick }) {
  const loginMethodDisplay = resolveLoginMethodDisplay(session);
  const { selectWorkspace: _selectWorkspace } = useWorkspace();
  const { border, text, muted, dashboard } = useDashboardTheme();
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    tokens: modalTokens,
  } = useDashboardModalProps();
  const [canSeeManagerNav, setCanSeeManagerNav] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [error, setError] = useState('');
  const [info, _setInfo] = useState('');
  const [pwdMessage, setPwdMessage] = useState('');
  const [pwdError, setPwdError] = useState('');
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

  const dangerBorderColor = useColorModeValue('red.200', 'red.700');
  const dangerTextColor = useColorModeValue('red.600', 'red.300');
  const formLabelProps = {
    color: muted,
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
      if (session.isAdmin === true) {
        if (!cancelled) setCanSeeManagerNav(true);
        return;
      }
      try {
        const ws = await workspaceAPI.list(50, 0);
        if (cancelled) return;
        const items = ws?.items || [];
        const roles = items.map(w => String(w.role || '').toLowerCase());
        const managerAny =
          roles.includes('admin') || roles.includes('workspace_manager');
        setCanSeeManagerNav(items.length ? managerAny : true);
      } catch (_) {
        if (!cancelled) setCanSeeManagerNav(false);
      }
    }

    loadManagerNav();
    return () => {
      cancelled = true;
    };
  }, [session]);

  const layoutProps = {
    variant: 'narrow',
    pageTitle: 'Account Settings',
    session,
    onLogout,
    onAccountClick,
    contentProps: { overflowX: 'hidden' },
  };

  // Safety check for session
  if (!session) {
    return (
      <>
        <SEO
          title='Account Settings'
          description='Manage your profile, password, security, and data export.'
          noindex
        />
        <DashboardPageLayout {...layoutProps}>
          <VStack spacing={6} align='stretch'>
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

      // Account deleted successfully
      try {
        trackEvent('account_deletion');
      } catch (_) {}
      onAccountDeleted();
    } catch (err) {
      logger.error('Account deletion error:', err);
      const status = err?.response?.status;
      const data = err?.response?.data;
      if (status === 409 && data?.code === 'ONLY_ADMIN') {
        // Confirm destructive wipe of listed workspaces, then retry with force
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

      // Create download link
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
        <VStack spacing={6} align='stretch'>
          {/* Account Information */}
          <DashboardPanel p={{ base: 4, md: 5 }}>
            <DashboardPanelHeader
              title='Account information'
              description='Profile identity and authentication details for this session.'
            />
            <VStack align='stretch' spacing={3}>
              {info && (
                <Alert status='success'>
                  <AlertIcon />
                  <AlertDescription>{info}</AlertDescription>
                </Alert>
              )}

              <AccountInfoRow label='Name' muted={muted} text={text}>
                {session.displayName}
              </AccountInfoRow>
              <AccountInfoRow label='Email' muted={muted} text={text}>
                {session.email}
              </AccountInfoRow>
              <AccountInfoRow label='Login Method' muted={muted} text={text}>
                <Badge
                  colorScheme={loginMethodDisplay.colorScheme}
                  maxW='fit-content'
                >
                  {loginMethodDisplay.label}
                </Badge>
              </AccountInfoRow>
              <AccountInfoRow label='Account Created' muted={muted} text={text}>
                {new Date(
                  session.created_at || Date.now()
                ).toLocaleDateString()}
              </AccountInfoRow>
            </VStack>
          </DashboardPanel>

          {/* Security */}
          <DashboardPanel p={{ base: 4, md: 5 }}>
            <DashboardPanelHeader
              title='Security'
              description='Manage password and two-factor authentication for your account.'
            />
            <VStack align='stretch' spacing={4}>
              {pwdMessage && (
                <Alert status='success'>
                  <AlertIcon />
                  <AlertDescription>{pwdMessage}</AlertDescription>
                </Alert>
              )}
              {pwdError && (
                <Alert status='error'>
                  <AlertIcon />
                  <AlertDescription>{pwdError}</AlertDescription>
                </Alert>
              )}
              <Text fontSize='sm' fontWeight='medium' color={text}>
                Change password
              </Text>
              <form
                onSubmit={async e => {
                  e.preventDefault();
                  setPwdMessage('');
                  setPwdError('');
                  setIsPwdSaving(true);
                  try {
                    if (newPassword !== confirmNewPassword) {
                      setPwdError('New password and confirmation do not match');
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
                      err?.response?.data?.error || 'Failed to change password';
                    setPwdError(msg);
                  } finally {
                    setIsPwdSaving(false);
                  }
                }}
              >
                <VStack align='stretch' spacing={4}>
                  <FormControl>
                    <FormLabel {...formLabelProps}>Current Password</FormLabel>
                    <Input
                      type='password'
                      autoComplete='current-password'
                      value={currentPassword}
                      onChange={e => setCurrentPassword(e.target.value)}
                      placeholder='Enter current password'
                    />
                  </FormControl>
                  <FormControl>
                    <FormLabel {...formLabelProps}>New Password</FormLabel>
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
                      Confirm New Password
                    </FormLabel>
                    <Input
                      type='password'
                      autoComplete='new-password'
                      value={confirmNewPassword}
                      onChange={e => setConfirmNewPassword(e.target.value)}
                      placeholder='Re-enter new password'
                    />
                  </FormControl>
                  <HStack>
                    <DashboardActionButton
                      type='submit'
                      colorScheme='blue'
                      isLoading={isPwdSaving}
                    >
                      Update Password
                    </DashboardActionButton>
                  </HStack>
                </VStack>
              </form>

              <Divider />

              {String(session?.authMethod || '').toLowerCase() !== 'google' && (
                <>
                  <Text fontSize='sm' fontWeight='medium' color={text}>
                    Two-factor authentication (2FA)
                  </Text>
                  <Text fontSize='sm' color={muted}>
                    Protect your account with a one-time code from an
                    authenticator app.
                  </Text>

                  <Stack
                    direction={{ base: 'column', md: 'row' }}
                    align='stretch'
                    spacing={6}
                  >
                    <VStack align='stretch' spacing={3} w='full'>
                      {session?.twoFactorEnabled ? (
                        <>
                          {/* Disable with password input styled like others */}
                          <FormControl>
                            <FormLabel {...formLabelProps}>
                              Confirm Password to Disable 2FA
                            </FormLabel>
                            <Input
                              type='password'
                              autoComplete='current-password'
                              placeholder='Enter your current password'
                              value={disablePwd}
                              onChange={e => setDisablePwd(e.target.value)}
                            />
                          </FormControl>
                          <Button
                            variant='ghost'
                            onClick={async () => {
                              setPwdMessage('');
                              setPwdError('');
                              try {
                                const { data } = await apiClient.post(
                                  '/api/account/2fa/disable',
                                  { currentPassword: disablePwd }
                                );
                                setPwdMessage(data.message || '2FA disabled');
                                setDisablePwd('');
                              } catch (e) {
                                const msg =
                                  e?.response?.data?.error ||
                                  'Failed to disable 2FA';
                                setPwdError(msg);
                              }
                            }}
                          >
                            Disable 2FA
                          </Button>
                        </>
                      ) : (
                        <>
                          <HStack>
                            <Button
                              onClick={async () => {
                                setPwdMessage('');
                                setPwdError('');
                                try {
                                  const { data } = await apiClient.post(
                                    '/api/account/2fa/setup'
                                  );
                                  setOtpAuth(data.otpauth || '');
                                  setQrData(data.qr || '');
                                  setSecret(data.secret || '');
                                } catch (e) {
                                  const msg =
                                    e?.response?.data?.error ||
                                    'Failed to start 2FA setup';
                                  setPwdError(msg);
                                }
                              }}
                            >
                              Start 2FA Setup
                            </Button>
                          </HStack>
                          {/* QR preview - placed right after Start 2FA Setup */}
                          <Box w={{ base: '100%', md: '200px' }}>
                            {qrData ? (
                              <img
                                src={qrData}
                                alt='2FA QR'
                                style={{
                                  width: '200px',
                                  height: '200px',
                                  display: 'block',
                                  margin: '12px 0',
                                }}
                              />
                            ) : (
                              <Box
                                w={{ base: '200px', md: '200px' }}
                                h={{ base: '200px', md: '200px' }}
                                border='1px dashed'
                                borderColor={border}
                                borderRadius='md'
                                display='flex'
                                alignItems='center'
                                justifyContent='center'
                                mt={3}
                                color={muted}
                              >
                                QR will appear here
                              </Box>
                            )}
                            {secret && (
                              <Text
                                mt={2}
                                fontSize='xs'
                                color={muted}
                                noOfLines={2}
                              >
                                Secret: {secret}
                              </Text>
                            )}
                          </Box>
                          <FormControl>
                            <FormLabel {...formLabelProps}>
                              Authenticator Code
                            </FormLabel>
                            <Input
                              type='text'
                              inputMode='numeric'
                              pattern='[0-9]*'
                              placeholder='Enter 6-digit code'
                              value={twoFaCode}
                              onChange={e => setTwoFaCode(e.target.value)}
                            />
                          </FormControl>
                          <HStack>
                            <Button
                              variant='outline'
                              onClick={async () => {
                                setPwdMessage('');
                                setPwdError('');
                                try {
                                  const { data } = await apiClient.post(
                                    '/api/account/2fa/enable',
                                    { token: twoFaCode }
                                  );
                                  setPwdMessage(data.message || '2FA enabled');
                                  setTwoFaCode('');
                                } catch (e) {
                                  const msg =
                                    e?.response?.data?.error ||
                                    'Failed to enable 2FA';
                                  setPwdError(msg);
                                }
                              }}
                            >
                              Confirm & Enable
                            </Button>
                          </HStack>
                        </>
                      )}
                    </VStack>
                  </Stack>
                </>
              )}
            </VStack>
          </DashboardPanel>

          {/* Data Management */}
          <DashboardPanel p={{ base: 4, md: 5 }}>
            <DashboardPanelHeader
              title='Data management'
              description='Export account data or review permanent account actions.'
            />
            <VStack align='stretch' spacing={4}>
              <Alert status='info' borderRadius='md'>
                <AlertIcon />
                <Box>
                  <AlertTitle fontSize='sm' fontWeight='semibold'>
                    Data actions
                  </AlertTitle>
                  <AlertDescription>
                    Export your data or permanently delete your account from
                    this page.
                  </AlertDescription>
                </Box>
              </Alert>

              <DashboardActionButton
                onClick={handleExportData}
                colorScheme='blue'
                variant='outline'
                alignSelf='flex-start'
              >
                Export my data
              </DashboardActionButton>
              <Text fontSize='sm' color={muted}>
                Exports a JSON with your profile and settings, your personal
                tokens, and (when applicable) workspace settings and tokens
                according to your role.
              </Text>
              <VStack align='stretch' spacing={1} pl={2}>
                <Text fontSize='xs' color={muted}>
                  Includes: Profile, user settings (webhooks hashed, phone,
                  WhatsApp opt-in), personal tokens, and for admin/manager: all
                  admin/managed workspaces (settings, contact groups with
                  phones, delivery window, WhatsApp opt-in evidence, tokens).
                </Text>
                <Text fontSize='xs' color={muted}>
                  Viewers: only personal workspace. For audit history, use the
                  Audit export page.
                </Text>
              </VStack>
            </VStack>
          </DashboardPanel>

          {canSeeManagerNav && (
            <Text fontSize='sm' color={muted}>
              Workspace alerting settings live on{' '}
              <Link
                as={RouterLink}
                to='/workspace-preferences'
                color='blue.500'
                fontWeight='semibold'
              >
                Workspace preferences
              </Link>
              .
            </Text>
          )}

          <Divider />

          {/* Danger Zone */}
          <DashboardPanel
            bg={dashboard.bg.panelHover}
            borderColor={dangerBorderColor}
          >
            <DashboardPanelHeader
              title='Danger zone'
              description='Destructive account actions that cannot be undone.'
            />
            <Alert status='warning' mb={4}>
              <AlertIcon />
              <Box>
                <AlertTitle fontSize='sm' fontWeight='semibold'>
                  Account Deletion
                </AlertTitle>
                <AlertDescription>
                  This will permanently delete your account and remove
                  associated data you own in this deployment. This action cannot
                  be undone.
                </AlertDescription>
              </Box>
            </Alert>

            {error && (
              <Alert status='error' mb={4}>
                <AlertIcon />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <Button colorScheme='red' onClick={onOpen} width='100%'>
              Delete my account
            </Button>
          </DashboardPanel>
        </VStack>

        {/* Confirmation Modal */}
        <Modal isOpen={isOpen} onClose={onClose} isCentered>
          <ModalOverlay {...overlayProps} />
          <DashboardModalFrame maxW='560px'>
            <ModalHeader {...headerProps}>
              <Text
                fontSize={{ base: 'md', md: 'lg' }}
                fontWeight='bold'
                color={dangerTextColor}
              >
                Delete account
              </Text>
              <Text
                fontSize='sm'
                color={modalTokens.muted}
                mt={1.5}
                fontWeight='medium'
              >
                Confirm this permanent account action.
              </Text>
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
                <Text fontSize='sm' color={muted}>
                  Deleting your account removes your personal workspace data and
                  memberships. Other workspace data remains according to
                  ownership and role rules.
                </Text>
                <Text fontSize='sm' color={modalTokens.text}>
                  Are you sure you want to delete your account{' '}
                  <strong>{session.displayName}</strong>?
                </Text>
                <Text fontSize='sm' color={muted}>
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
                  variant='outline'
                  onClick={onClose}
                  borderColor='rgba(148, 163, 184, 0.34)'
                  color={modalTokens.subtleText}
                  minW={{ base: '100%', sm: '104px' }}
                  _hover={{
                    bg: modalTokens.fieldBg,
                    borderColor: modalTokens.focusBorder,
                  }}
                >
                  Cancel
                </Button>
                <Button
                  colorScheme='red'
                  onClick={handleDeleteAccount}
                  isLoading={isDeleting}
                  loadingText='Deleting...'
                  minW={{ base: '100%', sm: '180px' }}
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
