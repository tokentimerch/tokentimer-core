import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import SEO from '../components/SEO.jsx';
import { getLogoPath } from '../utils/logoUtils.js';
import { logger } from '../utils/logger.js';
import {
  Box,
  Button,
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
import apiClient, { authAPI } from '../utils/apiClient';
import WelcomeModal from '../components/WelcomeModal';
import { trackEvent } from '../utils/analytics.js';

export default function Login() {
  const navigate = useNavigate();
  const [error, setError] = useState('');
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
    const urlParams = new URLSearchParams(window.location.search);
    const errorParam = urlParams.get('error');
    const verificationSent = urlParams.get('verification_sent');
    const verificationSuccess = urlParams.get('verification_success');
    const email = urlParams.get('email');

    if (errorParam === 'account_not_found') {
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
  }, []);

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

        const urlParams = new URLSearchParams(window.location.search);
        const verificationSuccess = urlParams.get('verification_success');
        if (verificationSuccess === 'true') {
          try {
            trackEvent('login_success', { method: 'email', two_factor: false });
          } catch (_) {}
          try {
            localStorage.removeItem('tt_last_workspace_id');
          } catch (_) {}
          window.location.href = '/dashboard?first_login=true';
        } else {
          try {
            trackEvent('login_success', { method: 'email', two_factor: false });
          } catch (_) {}
          try {
            localStorage.removeItem('tt_last_workspace_id');
          } catch (_) {}
          window.location.href = '/dashboard';
        }
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
      const urlParams = new URLSearchParams(window.location.search);
      const verificationSuccess = urlParams.get('verification_success');
      if (verificationSuccess === 'true') {
        try {
          trackEvent('login_success', { method: 'email', two_factor: true });
        } catch (_) {}
        try {
          localStorage.removeItem('tt_last_workspace_id');
        } catch (_) {}
        window.location.href = '/dashboard?first_login=true';
      } else {
        try {
          trackEvent('login_success', { method: 'email', two_factor: true });
        } catch (_) {}
        try {
          localStorage.removeItem('tt_last_workspace_id');
        } catch (_) {}
        window.location.href = '/dashboard';
      }
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
      maxW='lg'
      mx='auto'
      mt={12}
      p={{ base: 4, md: 8 }}
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
          <Text color={useColorModeValue('gray.600', 'gray.400')}>
            Sign in to your TokenTimer account
          </Text>
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
          {/* Email Login */}
          <Box
            w='full'
            bg={useColorModeValue('rgba(255, 255, 255, 0.72)', 'gray.800')}
            p={6}
            borderRadius='md'
            boxShadow='sm'
            border='1px solid'
            borderColor={useColorModeValue('gray.200', 'gray.600')}
          >
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
                      setEmailForm({ ...emailForm, password: e.target.value })
                    }
                    placeholder='Enter your password'
                    isDisabled={twoFARequired}
                  />
                  <FormErrorMessage>{formErrors.password}</FormErrorMessage>
                </FormControl>

                {twoFARequired && (
                  <FormControl>
                    <FormLabel>Two-Factor Code</FormLabel>
                    <Input
                      type='text'
                      inputMode='numeric'
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
