import { useState } from 'react';
import { logger } from '../utils/logger.js';
import {
  Box,
  Button,
  Heading,
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
  ModalContent,
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
import apiClient from '../utils/apiClient';
import { useWorkspace } from '../utils/WorkspaceContext.jsx';
import { Link as RouterLink } from 'react-router-dom';
import { trackEvent } from '../utils/analytics.js';

function Account({ session, onAccountDeleted }) {
  const { selectWorkspace: _selectWorkspace } = useWorkspace();
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

  // Color mode values
  const bgColor = useColorModeValue('rgba(255, 255, 255, 0.95)', 'gray.800');
  const borderColor = useColorModeValue('gray.400', 'gray.600');
  const dangerBgColor = useColorModeValue('red.50', 'red.900');
  const dangerBorderColor = useColorModeValue('red.200', 'red.700');
  const dangerTextColor = useColorModeValue('red.600', 'red.300');
  const subtextColor = useColorModeValue('gray.600', 'gray.400');

  // Safety check for session
  if (!session) {
    return (
      <Box maxW='2xl' mx='auto' p={{ base: 4, md: 6 }} overflowX='hidden'>
        <VStack spacing={6} align='stretch'>
          <Heading size='lg'>Account Settings</Heading>
          <Alert status='error'>
            <AlertIcon />
            <AlertDescription>
              Session not found. Please log in again.
            </AlertDescription>
          </Alert>
        </VStack>
      </Box>
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
        description='Manage your account settings, password, and two-factor authentication'
        noindex
      />
      <Box maxW='2xl' mx='auto' p={{ base: 4, md: 6 }} overflowX='hidden'>
        <VStack spacing={6} align='stretch'>
          <Heading size='lg'>Account Settings</Heading>

          {/* Account Information */}
          <Box
            bg={bgColor}
            p={6}
            borderRadius='md'
            boxShadow='sm'
            border='1px solid'
            borderColor={borderColor}
          >
            <Heading size='md' mb={4}>
              Account Information
            </Heading>
            <VStack align='stretch' spacing={3}>
              {info && (
                <Alert status='success'>
                  <AlertIcon />
                  <AlertDescription>{info}</AlertDescription>
                </Alert>
              )}

              <Flex
                direction={{ base: 'column', sm: 'row' }}
                align={{ base: 'stretch', sm: 'center' }}
                gap={{ base: 1, sm: 0 }}
              >
                <Text fontWeight='semibold' minW='fit-content'>
                  Name:
                </Text>
                <Spacer display={{ base: 'none', sm: 'block' }} />
                <Text wordBreak='break-word'>{session.displayName}</Text>
              </Flex>
              <Flex
                direction={{ base: 'column', sm: 'row' }}
                align={{ base: 'stretch', sm: 'center' }}
                gap={{ base: 1, sm: 0 }}
              >
                <Text fontWeight='semibold' minW='fit-content'>
                  Email:
                </Text>
                <Spacer display={{ base: 'none', sm: 'block' }} />
                <Text wordBreak='break-word'>{session.email}</Text>
              </Flex>
              <Flex
                direction={{ base: 'column', sm: 'row' }}
                align={{ base: 'stretch', sm: 'center' }}
                gap={{ base: 1, sm: 0 }}
              >
                <Text fontWeight='semibold' minW='fit-content'>
                  Login Method:
                </Text>
                <Spacer display={{ base: 'none', sm: 'block' }} />
                <Badge colorScheme='green' maxW='fit-content'>
                  Email & Password
                </Badge>
              </Flex>
              <Flex
                direction={{ base: 'column', sm: 'row' }}
                align={{ base: 'stretch', sm: 'center' }}
                gap={{ base: 1, sm: 0 }}
              >
                <Text fontWeight='semibold' minW='fit-content'>
                  Account Created:
                </Text>
                <Spacer display={{ base: 'none', sm: 'block' }} />
                <Text wordBreak='break-word'>
                  {new Date(
                    session.created_at || Date.now()
                  ).toLocaleDateString()}
                </Text>
              </Flex>
            </VStack>
          </Box>

          {/* Security */}
          <Box
            bg={bgColor}
            p={6}
            borderRadius='md'
            boxShadow='sm'
            border='1px solid'
            borderColor={borderColor}
          >
            <Heading size='md' mb={4}>
              Security
            </Heading>
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
              <Heading size='sm'>Change Password</Heading>
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
                    <FormLabel>Current Password</FormLabel>
                    <Input
                      type='password'
                      autoComplete='current-password'
                      value={currentPassword}
                      onChange={e => setCurrentPassword(e.target.value)}
                      placeholder='Enter current password'
                    />
                  </FormControl>
                  <FormControl>
                    <FormLabel>New Password</FormLabel>
                    <Input
                      type='password'
                      autoComplete='new-password'
                      value={newPassword}
                      onChange={e => setNewPassword(e.target.value)}
                      placeholder='At least 8 chars, include Aa1!'
                    />
                  </FormControl>
                  <FormControl>
                    <FormLabel>Confirm New Password</FormLabel>
                    <Input
                      type='password'
                      autoComplete='new-password'
                      value={confirmNewPassword}
                      onChange={e => setConfirmNewPassword(e.target.value)}
                      placeholder='Re-enter new password'
                    />
                  </FormControl>
                  <HStack>
                    <Button
                      type='submit'
                      colorScheme='blue'
                      isLoading={isPwdSaving}
                    >
                      Update Password
                    </Button>
                  </HStack>
                </VStack>
              </form>

              <Divider />

              {String(session?.authMethod || '').toLowerCase() !== 'google' && (
                <>
                  <Heading size='sm'>Two-Factor Authentication (2FA)</Heading>
                  <Text fontSize='sm' color={subtextColor}>
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
                            <FormLabel>
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
                                borderColor={borderColor}
                                borderRadius='md'
                                display='flex'
                                alignItems='center'
                                justifyContent='center'
                                mt={3}
                                color={subtextColor}
                              >
                                QR will appear here
                              </Box>
                            )}
                            {secret && (
                              <Text
                                mt={2}
                                fontSize='xs'
                                color={subtextColor}
                                noOfLines={2}
                              >
                                Secret: {secret}
                              </Text>
                            )}
                          </Box>
                          <FormControl>
                            <FormLabel>Authenticator Code</FormLabel>
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
          </Box>

          {/* Data Management */}
          <Box
            bg={bgColor}
            p={6}
            borderRadius='md'
            boxShadow='sm'
            border='1px solid'
            borderColor={borderColor}
          >
            <Heading size='md' mb={4}>
              Data Management
            </Heading>
            <VStack align='stretch' spacing={4}>
              <Alert status='info' borderRadius='md'>
                <AlertIcon />
                <Box>
                  <AlertTitle>Data actions</AlertTitle>
                  <AlertDescription>
                    Export your data or permanently delete your account from
                    this page.
                  </AlertDescription>
                </Box>
              </Alert>

              <Button
                onClick={handleExportData}
                colorScheme='blue'
                variant='outline'
                size='lg'
              >
                📥 Export My Data
              </Button>
              <Text fontSize='sm' color={subtextColor}>
                Exports a JSON with your profile and settings, your personal
                tokens, and (when applicable) workspace settings and tokens
                according to your role.
              </Text>
              <VStack align='stretch' spacing={1} pl={2}>
                <Text fontSize='xs' color={subtextColor}>
                  • Includes: Profile, user settings (webhooks hashed, phone,
                  WhatsApp opt-in), personal tokens, and for admin/manager: all
                  admin/managed workspaces (settings, contact groups with
                  phones, delivery window, WhatsApp opt-in evidence, tokens).
                </Text>
                <Text fontSize='xs' color={subtextColor}>
                  • Viewers: only personal workspace. For audit history, use the
                  Audit export page.
                </Text>
              </VStack>
            </VStack>
          </Box>

          {/* Preferences Shortcut */}
          <Box
            bg={bgColor}
            p={6}
            borderRadius='md'
            boxShadow='sm'
            border='1px solid'
            borderColor={borderColor}
          >
            <Heading size='md' mb={4}>
              Alerting Preferences
            </Heading>
            <VStack align='stretch' spacing={3}>
              <Text>
                Manage your alerting preferences (thresholds and integrations)
                on the{' '}
                <Link
                  as={RouterLink}
                  to='/preferences'
                  color='blue.500'
                  fontWeight='semibold'
                >
                  Alerting Preferences
                </Link>{' '}
                page.
              </Text>
              <Text fontSize='sm'>
                Use this page for account profile and security settings. Use the
                Preferences page for notification rules and integrations.
              </Text>
            </VStack>
          </Box>

          <Divider />

          {/* Danger Zone */}
          <Box
            bg={dangerBgColor}
            p={6}
            borderRadius='md'
            border='1px solid'
            borderColor={dangerBorderColor}
          >
            <Heading size='md' mb={4} color={dangerTextColor}>
              Danger Zone
            </Heading>
            <Alert status='warning' mb={4}>
              <AlertIcon />
              <Box>
                <AlertTitle>Account Deletion</AlertTitle>
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

            <Button colorScheme='red' onClick={onOpen} size='lg' width='100%'>
              🗑️ Delete My Account
            </Button>
          </Box>
        </VStack>

        {/* Confirmation Modal */}
        <Modal isOpen={isOpen} onClose={onClose} isCentered>
          <ModalOverlay />
          <ModalContent
            bg={bgColor}
            border='1px solid'
            borderColor={borderColor}
          >
            <ModalHeader color={dangerTextColor}>⚠️ Delete Account</ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <VStack spacing={4} align='stretch'>
                <Alert status='error'>
                  <AlertIcon />
                  <Box>
                    <AlertTitle>This action is irreversible!</AlertTitle>
                    <AlertDescription>
                      All your tokens, account data, and settings will be
                      permanently deleted.
                    </AlertDescription>
                  </Box>
                </Alert>
                <Text fontSize='sm' color='gray.600'>
                  Deleting your account removes your personal workspace data and
                  memberships. Other workspace data remains according to
                  ownership and role rules.
                </Text>
                <Text>
                  Are you sure you want to delete your account{' '}
                  <strong>{session.displayName}</strong>?
                </Text>
                <Text fontSize='sm' color={subtextColor}>
                  Consider exporting your data first if you need a backup.
                </Text>
              </VStack>
            </ModalBody>
            <ModalFooter>
              <Button variant='ghost' mr={3} onClick={onClose}>
                Cancel
              </Button>
              <Button
                colorScheme='red'
                onClick={handleDeleteAccount}
                isLoading={isDeleting}
                loadingText='Deleting...'
              >
                Yes, Delete My Account
              </Button>
            </ModalFooter>
          </ModalContent>
        </Modal>
      </Box>
    </>
  );
}

export default Account;
