import { useState, useEffect, useRef } from 'react';
import SEO from '../components/SEO.jsx';
import { getLogoPath } from '../utils/logoUtils.js';
import {
  Box,
  Button,
  Heading,
  Text,
  VStack,
  Alert,
  AlertIcon,
  AlertDescription,
  Spinner,
  useColorModeValue,
} from '@chakra-ui/react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { API_BASE_URL } from '../utils/apiClient';

function VerifyEmail() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [status, setStatus] = useState('checking'); // "checking", "verifying", "success", "error", "pending"
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [email, setEmail] = useState('');
  const [resendLoading, setResendLoading] = useState(false);
  const redirectTimeoutRef = useRef(null);

  // Color mode values
  const cardBgColor = useColorModeValue(
    'rgba(255, 255, 255, 0.95)',
    'gray.800'
  );
  const successColor = useColorModeValue('green.500', 'green.400');
  const infoColor = useColorModeValue('blue.500', 'blue.400');
  const errorColor = useColorModeValue('red.600', 'red.400');
  const textColor = useColorModeValue('gray.800', 'gray.400');
  const subTextColor = useColorModeValue('gray.700', 'gray.500');
  const hintColor = useColorModeValue('gray.600', 'gray.400');

  useEffect(() => {
    const token = searchParams.get('token');
    const emailParam = searchParams.get('email');

    if (emailParam) {
      setEmail(emailParam);
    }

    if (!token) {
      // No token provided - this is likely after registration
      if (emailParam) {
        setStatus('pending');
        setMessage(
          'Please check your email and click the verification link to complete your registration.'
        );
      } else {
        setStatus('error');
        setError('No verification token or email provided');
      }
      return;
    }

    // Token provided - let backend verify and set auth cookie via top-level navigation.
    const verifyEmail = () => {
      setStatus('verifying');
      const apiUrl = API_BASE_URL || '';
      window.location.href = `${apiUrl}/auth/verify-email/${encodeURIComponent(token)}`;
    };

    verifyEmail();
    return () => {
      if (redirectTimeoutRef.current) {
        clearTimeout(redirectTimeoutRef.current);
        redirectTimeoutRef.current = null;
      }
    };
  }, [searchParams, navigate, email]);

  const handleResendVerification = async () => {
    try {
      setResendLoading(true);
      // Cancel any pending redirect to the login page triggered by a prior successful verification
      if (redirectTimeoutRef.current) {
        clearTimeout(redirectTimeoutRef.current);
        redirectTimeoutRef.current = null;
      }
      const apiUrl = API_BASE_URL || '';

      const response = await axios.post(
        `${apiUrl}/auth/resend-verification`,
        {
          email,
        },
        { withCredentials: true }
      );

      if (response.data.emailSent) {
        setMessage('Verification email sent! Please check your inbox.');
        // Stay in the pending/check state to avoid showing the "Email Verified" success panel
        setStatus('pending');
      } else {
        setError(response.data.error || 'Failed to send verification email.');
      }
    } catch (error) {
      const errorMessage =
        error.response?.data?.error ||
        error.response?.data?.details ||
        'Failed to resend verification email.';
      setError(errorMessage);
    } finally {
      setResendLoading(false);
    }
  };

  const handleGoToLogin = () => {
    navigate('/login');
  };

  const handleGoHome = () => {
    navigate('/');
  };

  const handleLogout = async () => {
    try {
      const apiUrl = API_BASE_URL || '';
      await axios.post(`${apiUrl}/api/logout`, {}, { withCredentials: true });
    } catch (e) {
      // Ignore errors; we still navigate away
    } finally {
      navigate('/');
    }
  };

  if (status === 'verifying' || status === 'checking') {
    return (
      <Box maxW='lg' mx='auto' mt={12} p={{ base: 4, md: 8 }}>
        <VStack spacing={6} textAlign='center'>
          <SEO
            title='Verify Email'
            description='Verify your TokenTimer account email.'
            noindex
          />
          <Box onClick={() => navigate('/')} cursor='pointer'>
            <img
              src={getLogoPath()}
              width={75}
              height={75}
              style={{ margin: '0 auto', cursor: 'pointer' }}
              alt='TokenTimer logo'
            />
          </Box>
          <Spinner size='xl' color='blue.500' />
          <Heading as='h1' size='lg'>
            {status === 'verifying'
              ? 'Verifying your email...'
              : 'Checking verification status...'}
          </Heading>
          <Text color={hintColor}>
            {status === 'verifying'
              ? 'Please wait while we verify your email address.'
              : 'Please wait while we check your verification status.'}
          </Text>
        </VStack>
      </Box>
    );
  }

  return (
    <Box maxW='lg' mx='auto' mt={12} p={{ base: 4, md: 8 }}>
      <VStack spacing={6} align='stretch'>
        <Box textAlign='center'>
          <Box onClick={() => navigate('/')} cursor='pointer'>
            <img
              src={getLogoPath()}
              width={75}
              height={75}
              style={{ margin: '0 auto 20px', cursor: 'pointer' }}
              alt='TokenTimer logo'
            />
          </Box>
        </Box>
        <Box
          maxW='md'
          w='full'
          bg={cardBgColor}
          rounded='lg'
          shadow='lg'
          p={{ base: 4, md: 8 }}
          overflowX='hidden'
          mx='auto'
        >
          <VStack spacing={6} textAlign='center'>
            {status === 'success' ? (
              <>
                <Alert status='success' rounded='md'>
                  <AlertIcon />
                  <AlertDescription>{message}</AlertDescription>
                </Alert>

                <Heading size='lg' color={successColor}>
                  Email Verified!
                </Heading>

                <Text color={textColor}>
                  Your email has been successfully verified. You can now log in
                  to your account.
                </Text>

                <Button
                  colorScheme='blue'
                  size='lg'
                  w='full'
                  onClick={handleGoToLogin}
                >
                  Go to Login
                </Button>

                <Button
                  variant='outline'
                  size='md'
                  w='full'
                  onClick={handleGoHome}
                >
                  Go to Home
                </Button>

                <Button
                  variant='outline'
                  size='md'
                  w='full'
                  onClick={handleLogout}
                >
                  Logout
                </Button>

                <Text fontSize='sm' color={subTextColor}>
                  Redirecting to login page in a few seconds...
                </Text>
              </>
            ) : status === 'pending' ? (
              <>
                <Alert status='info' rounded='md'>
                  <AlertIcon />
                  <AlertDescription>{message}</AlertDescription>
                </Alert>

                <Heading size='lg' color={infoColor}>
                  Check Your Email
                </Heading>

                <Text color={textColor}>
                  We{"'"}ve sent a verification email to{' '}
                  <strong>{email}</strong>. Please check your inbox and click
                  the verification link to complete your registration.
                </Text>

                <VStack spacing={4} w='full'>
                  <Button
                    colorScheme='blue'
                    size='lg'
                    w='full'
                    onClick={handleGoToLogin}
                  >
                    Go to Login
                  </Button>

                  <Button
                    variant='outline'
                    size='md'
                    w='full'
                    onClick={handleResendVerification}
                    isLoading={resendLoading}
                    loadingText='Sending...'
                  >
                    Resend Verification Email
                  </Button>

                  <Button
                    variant='outline'
                    size='md'
                    w='full'
                    onClick={handleLogout}
                  >
                    Logout
                  </Button>

                  <Button
                    variant='outline'
                    size='sm'
                    w='full'
                    onClick={handleGoHome}
                  >
                    Go to Home
                  </Button>
                </VStack>

                <Text fontSize='sm' color={subTextColor}>
                  Didn{"'"}t receive the email? Check your spam folder or try
                  resending.
                </Text>
              </>
            ) : (
              <>
                <Alert status='error' rounded='md'>
                  <AlertIcon />
                  <AlertDescription>{error}</AlertDescription>
                </Alert>

                <Heading size='lg' color={errorColor}>
                  Verification Failed
                </Heading>

                <Text color={textColor}>
                  We couldn{"'"}t verify your email address. The link may be
                  expired or invalid.
                </Text>

                <VStack spacing={4} w='full'>
                  <Button
                    colorScheme='blue'
                    size='lg'
                    w='full'
                    onClick={handleGoToLogin}
                  >
                    Go to Login
                  </Button>

                  <Button
                    variant='outline'
                    size='md'
                    w='full'
                    onClick={handleResendVerification}
                  >
                    Resend Verification Email
                  </Button>

                  <Button
                    variant='outline'
                    size='md'
                    w='full'
                    onClick={handleLogout}
                  >
                    Logout
                  </Button>

                  <Button
                    variant='outline'
                    size='sm'
                    w='full'
                    onClick={handleGoHome}
                  >
                    Go to Home
                  </Button>
                </VStack>

                <Text fontSize='sm' color={subTextColor}>
                  Need help? Contact support if you continue having issues.
                </Text>
              </>
            )}
          </VStack>
        </Box>
      </VStack>
    </Box>
  );
}

export default VerifyEmail;
