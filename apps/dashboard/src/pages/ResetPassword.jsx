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
  Input,
  FormControl,
  FormLabel,
  Alert,
  AlertIcon,
  AlertDescription,
  Divider,
  Link,
  useColorModeValue,
} from '@chakra-ui/react';
import axios from 'axios';
import { API_BASE_URL } from '../utils/apiClient.js';

function ResetPassword() {
  const navigate = useNavigate();
  const [step, setStep] = useState('request'); // 'request' or 'reset'
  const [email, setEmail] = useState('');
  const [token, setToken] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  // Move useColorModeValue to top level
  const textColor = useColorModeValue('gray.800', 'gray.400');
  const inputBg = useColorModeValue('rgba(255, 255, 255, 0.95)', 'gray.700');
  const inputBorder = useColorModeValue('gray.400', 'gray.600');
  const cardBg = useColorModeValue('rgba(255, 255, 255, 0.95)', 'gray.800');
  const cardBorder = useColorModeValue('gray.200', 'gray.700');
  const headingColor = useColorModeValue('blue.600', 'white');
  const subtextColor = useColorModeValue('gray.600', 'gray.400');
  const btnBg = useColorModeValue('blue.500', 'white');
  const btnColor = useColorModeValue('white', 'gray.800');
  const btnHover = useColorModeValue({ bg: 'blue.600' }, { bg: 'gray.100' });

  // Check for token in URL on component mount
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const tokenFromUrl = urlParams.get('token');
    const emailFromUrl = urlParams.get('email');

    if (tokenFromUrl) {
      setToken(tokenFromUrl);
      if (emailFromUrl) {
        setEmail(emailFromUrl);
      }
      setStep('reset');
    }
  }, []);

  const handleRequestReset = async e => {
    e.preventDefault();
    setError('');
    setMessage('');
    if (!email.trim()) {
      setError('Email is required');
      return;
    }
    setIsLoading(true);
    try {
      const response = await axios.post(
        `${API_BASE_URL}/auth/request-password-reset`,
        {
          email,
        },
        { withCredentials: true }
      );

      setMessage(response.data.message);
      setStep('reset');
    } catch (error) {
      logger.error('Password reset request error:', error);
      let errorMessage = 'Failed to request password reset. Please try again.';

      if (error.response?.status === 404) {
        errorMessage =
          'Password reset endpoint not found. Please verify API URL configuration.';
      } else if (error.response?.data?.error) {
        errorMessage = error.response.data.error;
      }

      setError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  const handleResetPassword = async e => {
    e.preventDefault();
    setError('');
    setMessage('');
    if (!token.trim()) {
      setError('Reset token is required');
      return;
    }
    if (!newPassword) {
      setError('New password is required');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    setIsLoading(true);
    try {
      const response = await axios.post(
        `${API_BASE_URL}/auth/reset-password`,
        {
          token,
          newPassword,
        },
        { withCredentials: true }
      );

      setMessage(response.data.message);
      // Redirect to login after successful reset
      setTimeout(() => {
        window.location.href = '/login';
      }, 2000);
    } catch (error) {
      logger.error('Password reset error:', error);
      let errorMessage = 'Failed to reset password. Please try again.';

      if (error.response?.status === 404) {
        errorMessage =
          'Password reset endpoint not found. Please verify API URL configuration.';
      } else if (error.response?.data?.error) {
        errorMessage = error.response.data.error;
      }

      setError(errorMessage);
    } finally {
      setIsLoading(false);
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
        title='Reset Password'
        description='Reset your TokenTimer account password.'
        noindex
      />
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
          <Heading as='h1' size='xl' color={headingColor} mb={2}>
            {step === 'request' ? 'Reset Password' : 'Enter New Password'}
          </Heading>
          <Text color={subtextColor}>
            {step === 'request'
              ? 'Enter your email to receive a password reset link'
              : token
                ? 'Enter your new password below'
                : 'Enter the token from your email and your new password'}
          </Text>
          {step === 'reset' && (
            <Text mt={2} fontSize='sm' color={textColor}>
              For security, the reset link is valid for 5 minutes.
            </Text>
          )}
        </Box>

        {message && (
          <Alert status='success' borderRadius='md'>
            <AlertIcon />
            <AlertDescription>{message}</AlertDescription>
          </Alert>
        )}

        {error && (
          <Alert status='error' borderRadius='md'>
            <AlertIcon />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {step === 'request' ? (
          <Box
            bg={cardBg}
            border='1px solid'
            borderColor={cardBorder}
            borderRadius='lg'
            p={6}
          >
            <form onSubmit={handleRequestReset}>
              <VStack spacing={4}>
                <FormControl isRequired>
                  <FormLabel>Email Address</FormLabel>
                  <Input
                    type='email'
                    autoComplete='username'
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    placeholder='Enter your email address'
                    bg={inputBg}
                    borderColor={inputBorder}
                  />
                </FormControl>

                <Button
                  type='submit'
                  colorScheme='blue'
                  size='lg'
                  w='full'
                  isLoading={isLoading}
                  loadingText='Sending Reset Link...'
                >
                  Send Reset Link
                </Button>
              </VStack>
            </form>
          </Box>
        ) : (
          <Box
            bg={cardBg}
            border='1px solid'
            borderColor={cardBorder}
            borderRadius='lg'
            p={6}
          >
            <form onSubmit={handleResetPassword}>
              <VStack spacing={4}>
                <FormControl isRequired>
                  <FormLabel>Email Address</FormLabel>
                  <Input
                    type='email'
                    autoComplete='username'
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    placeholder='Enter your email address'
                    isReadOnly={!!email}
                    bg={inputBg}
                    borderColor={inputBorder}
                  />
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>Reset Token</FormLabel>
                  <Input
                    type='text'
                    value={token}
                    onChange={e => setToken(e.target.value)}
                    placeholder='Enter the token from your email'
                    isReadOnly={!!token}
                    bg={inputBg}
                    borderColor={inputBorder}
                  />
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>New Password</FormLabel>
                  <Input
                    type='password'
                    autoComplete='new-password'
                    value={newPassword}
                    onChange={e => setNewPassword(e.target.value)}
                    placeholder='Enter your new password'
                    bg={inputBg}
                    borderColor={inputBorder}
                  />
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>Confirm New Password</FormLabel>
                  <Input
                    type='password'
                    autoComplete='new-password'
                    value={confirmPassword}
                    onChange={e => setConfirmPassword(e.target.value)}
                    placeholder='Confirm your new password'
                    bg={inputBg}
                    borderColor={inputBorder}
                  />
                </FormControl>

                <Button
                  type='submit'
                  colorScheme='blue'
                  size='lg'
                  w='full'
                  isLoading={isLoading}
                  loadingText='Resetting Password...'
                  bg={btnBg}
                  color={btnColor}
                  _hover={btnHover}
                >
                  Reset Password
                </Button>

                <Button
                  variant='outline'
                  size='md'
                  w='full'
                  onClick={() => {
                    setStep('request');
                    setToken('');
                    setNewPassword('');
                    setConfirmPassword('');
                    setMessage('');
                    setError('');
                  }}
                >
                  Request New Reset Link
                </Button>
              </VStack>
            </form>
          </Box>
        )}

        <Divider />

        <Box textAlign='center'>
          <Text fontSize='sm' color={subtextColor}>
            Remember your password?{' '}
            <Link
              color='blue.500'
              onClick={() => navigate('/login')}
              cursor='pointer'
              fontWeight='semibold'
            >
              Sign in here
            </Link>
          </Text>
        </Box>
      </VStack>
    </Box>
  );
}

export default ResetPassword;
