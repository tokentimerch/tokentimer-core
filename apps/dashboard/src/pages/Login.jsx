import { useState, useEffect } from 'react';
import { Link as RouterLink, useLocation, useNavigate } from 'react-router';
import SEO from '../components/SEO.jsx';
import { getLogoPath } from '../utils/logoUtils.js';
import { logger } from '../utils/logger.js';
import {
  Box,
  Badge,
  Button,
  Divider,
  HStack,
  Heading,
  Text,
  VStack,
  Link,
  Alert,
  AlertIcon,
  AlertDescription,
  Input,
  FormControl,
  FormLabel,
  FormErrorMessage,
  useColorModeValue,
} from '@chakra-ui/react';
import apiClient, { authAPI, API_BASE_URL } from '../utils/apiClient';
import WelcomeModal from '../components/WelcomeModal';
import { trackEvent } from '../utils/analytics.js';
import { dashboardHrefAfterLogin } from '../utils/lastWorkspacePreference.js';

import {
  buildSsoLoginUrl,
  isSsoLoginError,
  loginNextPath,
  parseAuthFeaturesProviders,
} from '../lib/sso-ui-shared.js';

const SSO_ERROR_ADMIN_HINTS = {
  oidc_failed: 'OIDC callback or token validation failed.',
  saml_failed: 'SAML assertion validation failed.',
  provider_disabled: 'This provider was disabled during sign-in.',
  oidc_not_ready: 'OIDC provider is not sign-in ready on this API pod.',
  saml_not_ready: 'SAML provider is not sign-in ready on this API pod.',
  state_mismatch:
    'OIDC state mismatch. Session cookie was lost between sign-in start and callback (check API_URL, APP_URL, SESSION_COOKIE_DOMAIN, or sticky sessions).',
  oidc_auto_link_disabled:
    'A local-password account exists for this email. Enable allow auto-link under System Settings → SSO policy (or override on the provider), or use email login.',
  oidc_email_not_verified:
    'IdP did not assert email_verified=true; linking to an existing account was refused.',
  oidc_missing_claims:
    'IdP token did not include a usable email or subject. Check claim mapping and Keycloak mappers.',
  oidc_account_mismatch:
    'This email is linked to a different SSO subject. Ask an admin to fix external_identities.',
  oidc_no_group_mapping:
    'IdP groups for this login matched no mapping and strict membership sync is enabled. Ask an admin to add a group mapping or grant workspace access.',
};

const SSO_REASON_ADMIN_HINTS = {
  callback_error:
    'OIDC callback failed. Common causes: API cannot reach the IdP token endpoint (network, firewall, IPv6), wrong client secret, or redirect URI mismatch. Check LOGIN_FAILED audit metadata.error.',
  state_mismatch: SSO_ERROR_ADMIN_HINTS.state_mismatch,
  session_login_error: 'User was resolved but passport session login failed.',
  issuer_mismatch: 'ID token issuer does not match configured issuer.',
  pkce_verifier_missing:
    'PKCE code_verifier missing from session (cookie lost or expired).',
  userinfo_sub_mismatch: 'UserInfo sub does not match ID token sub.',
  missing_email: 'IdP token did not include a usable email.',
  oidc_no_user: 'Could not create or link a user from SSO claims.',
  auto_link_disabled: SSO_ERROR_ADMIN_HINTS.oidc_auto_link_disabled,
  cross_provider_auto_link_disabled:
    'Email matches an SSO user linked to another provider. Enable allow auto-link under System Settings → SSO policy, or sign in with the original provider.',
  no_group_mapping_matched: SSO_ERROR_ADMIN_HINTS.oidc_no_group_mapping,
};

export default function Login({ session }) {
  const navigate = useNavigate();
  const location = useLocation();
  const searchParams = new URLSearchParams(location.search);
  const errorParam = searchParams.get('error');
  const reason = searchParams.get('reason');
  const nextPath = loginNextPath(searchParams);
  const adminDetail =
    session?.isAdmin === true && isSsoLoginError(errorParam)
      ? (Object.hasOwn(SSO_REASON_ADMIN_HINTS, reason) &&
          SSO_REASON_ADMIN_HINTS[reason]) ||
        (Object.hasOwn(SSO_ERROR_ADMIN_HINTS, errorParam) &&
          SSO_ERROR_ADMIN_HINTS[errorParam])
      : null;
  const [showErrorDetails, setShowErrorDetails] = useState(false);
  const [error, setError] = useState('');
  const [signInProviders, setSignInProviders] = useState([]);
  const formBackground = useColorModeValue(
    'rgba(255, 255, 255, 0.72)',
    'gray.800'
  );
  const formBorder = useColorModeValue('gray.200', 'gray.600');
  const textColor = useColorModeValue('gray.600', 'gray.400');

  useEffect(() => {
    let controller;
    async function refreshProviders() {
      controller?.abort();
      const request = new AbortController();
      controller = request;
      try {
        const response = await fetch(`${API_BASE_URL}/api/auth/features`, {
          credentials: 'include',
          cache: 'no-store',
          signal: request.signal,
        });
        const data = response.ok ? await response.json() : null;
        if (!request.signal.aborted) {
          setSignInProviders(
            parseAuthFeaturesProviders(data)
              .filter(provider => provider.signInReady === true)
              .sort(
                (a, b) =>
                  (a.sortOrder ?? a.sort_order ?? 100) -
                    (b.sortOrder ?? b.sort_order ?? 100) ||
                  (a.displayName || a.slug).localeCompare(
                    b.displayName || b.slug
                  )
              )
          );
        }
      } catch {
        if (!request.signal.aborted) setSignInProviders([]);
      }
    }

    function refreshOnVisibility() {
      if (document.visibilityState === 'visible') refreshProviders();
    }

    refreshProviders();
    const retrySoon = window.setTimeout(refreshProviders, 500);
    const retryLater = window.setTimeout(refreshProviders, 1500);
    window.addEventListener('focus', refreshProviders);
    window.addEventListener('pageshow', refreshProviders);
    document.addEventListener('visibilitychange', refreshOnVisibility);
    return () => {
      controller?.abort();
      window.clearTimeout(retrySoon);
      window.clearTimeout(retryLater);
      window.removeEventListener('focus', refreshProviders);
      window.removeEventListener('pageshow', refreshProviders);
      document.removeEventListener('visibilitychange', refreshOnVisibility);
    };
  }, [location.key]);
  const [verificationMessage, setVerificationMessage] = useState('');
  const [verificationAlert, setVerificationAlert] = useState({
    show: false,
    message: '',
    type: 'success',
  });
  const [emailForm, setEmailForm] = useState({
    email: '',
    password: '',
  });
  const [formErrors, setFormErrors] = useState({});
  const [isLoading, setIsLoading] = useState(false);
  const [twoFARequired, setTwoFARequired] = useState(false);
  const [twoFaCode, setTwoFaCode] = useState('');
  const [isOtpLoading, setIsOtpLoading] = useState(false);
  const [showWelcomeModal, setShowWelcomeModal] = useState(false);
  // Check for URL parameters for OAuth errors and verification messages
  useEffect(() => {
    const urlParams = new URLSearchParams(location.search);
    setError('');
    setShowErrorDetails(false);
    const errorParam = urlParams.get('error');
    const verificationSent = urlParams.get('verification_sent');
    const verificationSuccess = urlParams.get('verification_success');
    const email = urlParams.get('email');

    if (isSsoLoginError(errorParam)) {
      setError(
        'Single sign-on failed. Try again or contact your administrator.'
      );
    } else if (errorParam === 'account_not_found') {
      setError('Account not found. Contact your administrator for access.');
    } else if (errorParam === 'email_exists') {
      setError(
        'This email is already associated with an account. Please sign in below with your email and password.'
      );
    } else if (errorParam === 'invalid_verification') {
      setError(
        'Invalid or expired verification link. Please contact your administrator.'
      );
    } else if (errorParam === 'verification_failed') {
      setError(
        'Email verification failed. Please try again or contact support.'
      );
    }

    if (verificationSent === 'true' && email) {
      setVerificationMessage(
        `📧 Verification email sent to ${email}. Please check your inbox and click the verification link to activate your account.`
      );
      setEmailForm(prev => ({ ...prev, email: decodeURIComponent(email) }));
    }

    if (verificationSuccess === 'true' && email) {
      setVerificationMessage(
        `✅ Email verified successfully! You can now log in with your email and password.`
      );
      setEmailForm(prev => ({ ...prev, email: decodeURIComponent(email) }));
      setError('');
      // Show welcome modal to confirm verification success
      setShowWelcomeModal(true);
    }

    // Prefill email if present in URL
    if (email) {
      try {
        setEmailForm(prev => ({ ...prev, email: decodeURIComponent(email) }));
      } catch (_) {}
    }
  }, [location.search]);

  const handleEmailLogin = async e => {
    e.preventDefault();

    // Validate form
    const errors = {};
    if (!emailForm.email.trim()) errors.email = 'Email is required';
    if (!emailForm.password) errors.password = 'Password is required';

    setFormErrors(errors);

    if (Object.keys(errors).length === 0) {
      setIsLoading(true);
      try {
        const loginResponse = await authAPI.login({
          email: emailForm.email,
          password: emailForm.password,
        });

        if (loginResponse?.requires2FA) {
          setTwoFARequired(true);
          return;
        }

        try {
          trackEvent('login_success', { method: 'email', two_factor: false });
        } catch (_) {}
        window.location.href =
          nextPath ||
          dashboardHrefAfterLogin({
            firstLogin:
              new URLSearchParams(window.location.search).get(
                'verification_success'
              ) === 'true',
          });
      } catch (error) {
        logger.error('Login error:', error);
        let errorMessage = 'Login failed. Please try again.';

        if (error.response?.status === 404) {
          errorMessage =
            'Unexpected error occurred. Please try again or contact support if the problem persists.';
        } else if (error.response?.data?.error) {
          errorMessage = error.response.data.error;
        }

        setFormErrors({ general: errorMessage });

        // If user needs email verification, show special message
        if (error.response?.data?.needsVerification) {
          setFormErrors({
            general:
              'Please verify your email address before logging in. Check your inbox for a verification link, or click "Resend Verification" below.',
          });
        }
      } finally {
        setIsLoading(false);
      }
    }
  };

  const handleVerify2FA = async e => {
    e.preventDefault();
    setIsOtpLoading(true);
    try {
      await apiClient.post('/auth/verify-2fa', { token: twoFaCode });
      try {
        trackEvent('login_success', { method: 'email', two_factor: true });
      } catch (_) {}
      window.location.href =
        nextPath ||
        dashboardHrefAfterLogin({
          firstLogin:
            new URLSearchParams(window.location.search).get(
              'verification_success'
            ) === 'true',
        });
    } catch (error) {
      const errorMessage =
        error.response?.data?.error || 'Invalid 2FA code. Please try again.';
      setFormErrors({ general: errorMessage });
    } finally {
      setIsOtpLoading(false);
    }
  };

  return (
    <Box
      minH={{ base: 'calc(100dvh - 120px)', md: 'calc(100dvh - 70px)' }}
      display='flex'
      flexDirection='column'
      justifyContent='center'
      maxW='lg'
      mx='auto'
      w='full'
      py={{ base: 6, md: 8 }}
      px={{ base: 4, md: 8 }}
      position='relative'
      overflowX='hidden'
    >
      <SEO
        title='Login'
        description='Sign in to your TokenTimer account.'
        noindex
      />
      {/* Theme Toggle Button */}
      {/* Theme toggle removed */}

      <VStack spacing={6} align='stretch'>
        <Box textAlign='center'>
          <Box
            onClick={() => navigate('/')}
            cursor='pointer'
            _hover={{ textDecoration: 'none' }}
          >
            <img
              src={getLogoPath()}
              width={75}
              height={75}
              style={{ margin: '0 auto 20px', cursor: 'pointer' }}
              alt='TokenTimer logo'
            />
          </Box>
          <Heading as='h1' size='xl' mb={2}>
            Welcome Back
          </Heading>
          <Text color={textColor}>Sign in to your TokenTimer account</Text>
        </Box>

        {/* Verification Message */}
        {verificationMessage && (
          <Alert status='success' borderRadius='md'>
            <AlertIcon />
            <AlertDescription>{verificationMessage}</AlertDescription>
          </Alert>
        )}

        {/* Error Alert */}
        {error && (
          <Alert status='error' borderRadius='md'>
            <AlertIcon />
            <AlertDescription>
              {error.includes('Account not found') ? (
                <>
                  Account not found. Please contact your administrator for
                  access.
                </>
              ) : (
                error
              )}
              {adminDetail && (
                <Box mt={2}>
                  <Button
                    size='xs'
                    variant='link'
                    aria-expanded={showErrorDetails}
                    aria-controls='sso-sign-in-details'
                    onClick={() => setShowErrorDetails(v => !v)}
                  >
                    Details
                  </Button>
                  {showErrorDetails && (
                    <Text id='sso-sign-in-details' fontSize='xs' mt={1}>
                      {adminDetail}{' '}
                      <Link
                        as={RouterLink}
                        to='/system-settings'
                        color='blue.300'
                      >
                        Open System Settings
                      </Link>
                    </Text>
                  )}
                </Box>
              )}
            </AlertDescription>
          </Alert>
        )}

        {/* Verification Alert */}
        {verificationAlert.show && (
          <Alert status={verificationAlert.type} borderRadius='md'>
            <AlertIcon />
            <AlertDescription>{verificationAlert.message}</AlertDescription>
          </Alert>
        )}

        {/* Login Options */}
        <VStack spacing={4}>
          {signInProviders.map(provider => {
            const signInLabel = `Sign in with ${provider.displayName || provider.slug}`;
            return (
              <Box
                key={provider.slug}
                w='full'
                bg={formBackground}
                p={6}
                borderRadius='md'
                boxShadow='sm'
                border='1px solid'
                borderColor={formBorder}
              >
                <HStack mb={3} align='center' justify='space-between'>
                  <Heading as='h2' size='md' overflowWrap='anywhere'>
                    {signInLabel}
                  </Heading>
                  <Badge colorScheme='purple' flexShrink={0}>
                    SSO
                  </Badge>
                </HStack>
                <Text fontSize='sm' color={textColor} mb={4}>
                  Continue with your organization identity provider.
                </Text>
                <Button
                  as='a'
                  href={buildSsoLoginUrl(provider, nextPath, API_BASE_URL)}
                  aria-label={signInLabel}
                  colorScheme='blue'
                  variant='outline'
                  w='full'
                >
                  Continue
                </Button>
              </Box>
            );
          })}

          {signInProviders.length > 0 && <Divider />}
          {/* Email Login */}
          <Box
            w='full'
            bg={formBackground}
            p={6}
            borderRadius='md'
            boxShadow='sm'
            border='1px solid'
            borderColor={formBorder}
          >
            {signInProviders.length > 0 && (
              <>
                <Heading as='h2' size='md' mb={1}>
                  Email and password
                </Heading>
                <Text fontSize='sm' color={textColor} mb={4}>
                  Sign in with your local administrator or fallback account.
                </Text>
              </>
            )}

            {formErrors.general && (
              <VStack spacing={3} mb={4}>
                <Alert status='error' borderRadius='md'>
                  <AlertIcon />
                  <AlertDescription>{formErrors.general}</AlertDescription>
                </Alert>
                {formErrors.general.includes('verify your email') && (
                  <Button
                    size='sm'
                    variant='outline'
                    colorScheme='blue'
                    onClick={async () => {
                      // Prevent the verification success welcome modal from showing during resend
                      setShowWelcomeModal(false);
                      // Also clear any existing success banner message
                      setVerificationMessage('');
                      try {
                        const url = new URL(window.location.href);
                        url.searchParams.delete('verification_success');
                        window.history.replaceState({}, '', url.toString());
                      } catch (_) {}

                      try {
                        const response = await apiClient.post(
                          '/auth/resend-verification',
                          { email: emailForm.email }
                        );

                        if (response.data.emailSent) {
                          setVerificationAlert({
                            show: true,
                            message:
                              'Verification email sent! Please check your inbox.',
                            type: 'success',
                          });
                        } else {
                          setVerificationAlert({
                            show: true,
                            message:
                              response.data.error ||
                              'Failed to send verification email.',
                            type: 'error',
                          });
                        }
                      } catch (error) {
                        const errorMessage =
                          error.response?.data?.error ||
                          error.response?.data?.details ||
                          'Failed to resend verification email. Please try again.';
                        setVerificationAlert({
                          show: true,
                          message: errorMessage,
                          type: 'error',
                        });
                      }
                    }}
                  >
                    Resend Verification Email
                  </Button>
                )}
              </VStack>
            )}

            <form onSubmit={twoFARequired ? handleVerify2FA : handleEmailLogin}>
              <VStack spacing={4}>
                {!twoFARequired && (
                  <>
                    <FormControl isInvalid={formErrors.email}>
                      <FormLabel>Email</FormLabel>
                      <Input
                        type='email'
                        autoComplete='username'
                        value={emailForm.email}
                        onChange={e =>
                          setEmailForm({ ...emailForm, email: e.target.value })
                        }
                        placeholder='Enter your email'
                        isDisabled={twoFARequired}
                      />
                      <FormErrorMessage>{formErrors.email}</FormErrorMessage>
                    </FormControl>

                    <FormControl isInvalid={formErrors.password}>
                      <FormLabel>Password</FormLabel>
                      <Input
                        type='password'
                        autoComplete='current-password'
                        value={emailForm.password}
                        onChange={e =>
                          setEmailForm({
                            ...emailForm,
                            password: e.target.value,
                          })
                        }
                        placeholder='Enter your password'
                        isDisabled={twoFARequired}
                      />
                      <FormErrorMessage>{formErrors.password}</FormErrorMessage>
                    </FormControl>
                  </>
                )}

                {twoFARequired && (
                  <FormControl>
                    <Text fontSize='sm' mb={2}>
                      Enter the authenticator code for {emailForm.email}.
                    </Text>
                    <FormLabel>Two-Factor Code</FormLabel>
                    <Input
                      type='text'
                      inputMode='numeric'
                      autoComplete='one-time-code'
                      autoFocus
                      pattern='[0-9]*'
                      placeholder='Enter 6-digit code'
                      value={twoFaCode}
                      onChange={e => setTwoFaCode(e.target.value)}
                    />
                  </FormControl>
                )}

                <Button
                  type='submit'
                  colorScheme='blue'
                  size='lg'
                  w='full'
                  isLoading={twoFARequired ? isOtpLoading : isLoading}
                  loadingText={twoFARequired ? 'Verifying...' : 'Signing in...'}
                >
                  {twoFARequired ? 'Verify & Sign In' : 'Sign In'}
                </Button>
                {twoFARequired && (
                  <Button
                    variant='outline'
                    w='full'
                    onClick={() => {
                      setTwoFARequired(false);
                      setTwoFaCode('');
                      setEmailForm(previous => ({ ...previous, password: '' }));
                      setFormErrors({});
                    }}
                  >
                    Back to sign in
                  </Button>
                )}

                <Box textAlign='center' pt={2}>
                  <Link
                    color='blue.500'
                    onClick={() => navigate('/reset-password')}
                    cursor='pointer'
                    fontSize='sm'
                  >
                    Forgot your password?
                  </Link>
                </Box>
              </VStack>
            </form>
          </Box>
        </VStack>

        {/* Footer Links */}
        <Box textAlign='center' pt={4}>
          <Text fontSize='sm' color={useColorModeValue('gray.600', 'gray.400')}>
            Don{"'"}t have an account? Contact your administrator for access.
          </Text>
        </Box>
      </VStack>

      {/* Welcome modal after successful verification */}
      <WelcomeModal
        isOpen={showWelcomeModal}
        onClose={() => setShowWelcomeModal(false)}
        data={{ userName: '', isNewUser: true }}
        emailSent={false}
      />
    </Box>
  );
}
