import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import {
  Box,
  Button,
  FormControl,
  FormErrorMessage,
  FormLabel,
  Heading,
  Input,
  Link,
  Text,
  VStack,
  Alert,
  AlertIcon,
  AlertDescription,
  useColorModeValue,
} from '@chakra-ui/react';
import SEO from '../components/SEO.jsx';
import { API_BASE_URL } from '../utils/apiClient.js';
import { getLogoPath } from '../utils/logoUtils.js';

export default function Register() {
  const navigate = useNavigate();
  const [token, setToken] = useState('');
  const [form, setForm] = useState({
    email: '',
    first_name: '',
    last_name: '',
    password: '',
    confirmPassword: '',
  });
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [info, setInfo] = useState('');

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const inviteToken = params.get('token') || '';
    const inviteEmail = params.get('email') || '';
    setToken(inviteToken);
    if (inviteEmail) {
      setForm(prev => ({ ...prev, email: decodeURIComponent(inviteEmail) }));
    }
  }, []);

  const validate = () => {
    const nextErrors = {};
    if (!token) nextErrors.general = 'Invitation token is missing or invalid.';
    if (!form.email.trim() || !/.+@.+\..+/.test(form.email.trim())) {
      nextErrors.email = 'Valid email is required';
    }
    if (!form.first_name.trim())
      nextErrors.first_name = 'First name is required';
    if (!form.last_name.trim()) nextErrors.last_name = 'Last name is required';
    if (!form.password || form.password.length < 12) {
      nextErrors.password = 'Password must be at least 12 characters long';
    } else if (!/[a-z]/.test(form.password)) {
      nextErrors.password =
        'Password must contain at least one lowercase letter';
    } else if (!/[A-Z]/.test(form.password)) {
      nextErrors.password =
        'Password must contain at least one uppercase letter';
    } else if (!/\d/.test(form.password)) {
      nextErrors.password = 'Password must contain at least one number';
    } else if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(form.password)) {
      nextErrors.password =
        'Password must contain at least one special character';
    }
    if (form.password !== form.confirmPassword) {
      nextErrors.confirmPassword = 'Passwords do not match';
    }
    setErrors(nextErrors);
    return Object.keys(nextErrors).length === 0;
  };

  const onSubmit = async e => {
    e.preventDefault();
    setInfo('');
    if (!validate()) return;
    setLoading(true);
    try {
      const apiUrl = API_BASE_URL || '';
      const response = await axios.post(
        `${apiUrl}/auth/register`,
        {
          token,
          email: form.email.trim(),
          first_name: form.first_name.trim(),
          last_name: form.last_name.trim(),
          password: form.password,
        },
        { withCredentials: true }
      );

      const requiresVerification = !!response.data?.requiresEmailVerification;
      const userEmail = form.email.trim();
      if (requiresVerification) {
        window.location.href = `/verify-email?email=${encodeURIComponent(userEmail)}&new_user=true`;
        return;
      }
      window.location.href = `/login?email=${encodeURIComponent(userEmail)}`;
    } catch (err) {
      const apiError =
        err?.response?.data?.error || 'Registration failed. Please try again.';
      setErrors(prev => ({ ...prev, general: apiError }));
    } finally {
      setLoading(false);
    }
  };

  const bgCard = useColorModeValue('rgba(255, 255, 255, 0.72)', 'gray.800');
  const borderColor = useColorModeValue('gray.200', 'gray.600');
  const subtextColor = useColorModeValue('gray.600', 'gray.400');

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
        title='Register'
        description='Create your TokenTimer account.'
        noindex
      />
      <VStack spacing={6} align='stretch'>
        <Box textAlign='center'>
          <Box
            cursor='pointer'
            _hover={{ textDecoration: 'none' }}
            onClick={() => navigate('/')}
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
            Complete Your Invitation
          </Heading>
          <Text color={subtextColor}>
            Create credentials for your invited workspace account.
          </Text>
        </Box>

        {errors.general && (
          <Alert status='error' borderRadius='md'>
            <AlertIcon />
            <AlertDescription>{errors.general}</AlertDescription>
          </Alert>
        )}
        {info && (
          <Alert status='success' borderRadius='md'>
            <AlertIcon />
            <AlertDescription>{info}</AlertDescription>
          </Alert>
        )}

        <Box
          w='full'
          bg={bgCard}
          p={6}
          borderRadius='md'
          boxShadow='sm'
          border='1px solid'
          borderColor={borderColor}
        >
          <form onSubmit={onSubmit}>
            <VStack spacing={4}>
              <FormControl isInvalid={errors.email}>
                <FormLabel>Email</FormLabel>
                <Input
                  type='email'
                  autoComplete='username'
                  value={form.email}
                  onChange={e =>
                    setForm(prev => ({ ...prev, email: e.target.value }))
                  }
                  placeholder='you@company.com'
                />
                <FormErrorMessage>{errors.email}</FormErrorMessage>
              </FormControl>

              <FormControl isInvalid={errors.first_name}>
                <FormLabel>First Name</FormLabel>
                <Input
                  value={form.first_name}
                  onChange={e =>
                    setForm(prev => ({ ...prev, first_name: e.target.value }))
                  }
                />
                <FormErrorMessage>{errors.first_name}</FormErrorMessage>
              </FormControl>

              <FormControl isInvalid={errors.last_name}>
                <FormLabel>Last Name</FormLabel>
                <Input
                  value={form.last_name}
                  onChange={e =>
                    setForm(prev => ({ ...prev, last_name: e.target.value }))
                  }
                />
                <FormErrorMessage>{errors.last_name}</FormErrorMessage>
              </FormControl>

              <FormControl isInvalid={errors.password}>
                <FormLabel>Password</FormLabel>
                <Input
                  type='password'
                  autoComplete='new-password'
                  value={form.password}
                  onChange={e =>
                    setForm(prev => ({ ...prev, password: e.target.value }))
                  }
                />
                <FormErrorMessage>{errors.password}</FormErrorMessage>
              </FormControl>

              <FormControl isInvalid={errors.confirmPassword}>
                <FormLabel>Confirm Password</FormLabel>
                <Input
                  type='password'
                  autoComplete='new-password'
                  value={form.confirmPassword}
                  onChange={e =>
                    setForm(prev => ({
                      ...prev,
                      confirmPassword: e.target.value,
                    }))
                  }
                />
                <FormErrorMessage>{errors.confirmPassword}</FormErrorMessage>
              </FormControl>

              <Button
                type='submit'
                colorScheme='blue'
                size='lg'
                w='full'
                isLoading={loading}
                loadingText='Creating account...'
              >
                Create Account
              </Button>
            </VStack>
          </form>
        </Box>

        <Box textAlign='center' pt={4}>
          <Text fontSize='sm' color={subtextColor}>
            Already have an account?{' '}
            <Link
              color='blue.500'
              onClick={() => navigate('/login')}
              cursor='pointer'
            >
              Sign in
            </Link>
          </Text>
        </Box>
      </VStack>
    </Box>
  );
}
