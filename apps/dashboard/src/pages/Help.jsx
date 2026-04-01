import { useState, useEffect } from 'react';
import SEO from '../components/SEO.jsx';
import {
  Box,
  Container,
  Heading,
  Text,
  VStack,
  FormControl,
  FormLabel,
  FormErrorMessage,
  Input,
  Textarea,
  Select,
  Button,
  useColorModeValue,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  Link,
} from '@chakra-ui/react';
import { Link as RouterLink } from 'react-router-dom';
import { showSuccess, showError } from '../utils/toast.js';
import Navigation from '../components/Navigation';
import apiClient from '../utils/apiClient';

function Help({
  session,
  onLogout,
  onAccountClick,
  onNavigateToDashboard,
  onNavigateToLanding,
}) {
  const [formData, setFormData] = useState({
    category: '',
    subject: '',
    message: '',
    email: '',
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errors, setErrors] = useState({});

  const bgColor = useColorModeValue('rgba(255, 255, 255, 0.95)', 'gray.800');
  const borderColor = useColorModeValue('gray.400', 'gray.600');
  const textColor = useColorModeValue('gray.800', 'gray.300');

  // Set user email from session
  useEffect(() => {
    if (session?.user?.email) {
      setFormData(prev => ({
        ...prev,
        email: session.user.email,
      }));
    } else if (session?.email) {
      // Fallback in case email is directly on session
      setFormData(prev => ({
        ...prev,
        email: session.email,
      }));
    }
  }, [session]);

  const categories = [
    {
      value: 'feedback',
      label: 'Feedback & Suggestions',
      description: 'Share your thoughts about TokenTimer',
    },
    {
      value: 'account',
      label: 'Account Issues',
      description: 'Problems with login, registration, or account settings',
    },
    {
      value: 'technical',
      label: 'Technical Problems',
      description: 'Bugs, errors, or functionality issues',
    },
    {
      value: 'feature',
      label: 'Feature Request',
      description: 'Suggest new features or improvements',
    },
    {
      value: 'security',
      label: 'Security Concern',
      description: 'Report security issues or data privacy concerns',
    },
    {
      value: 'other',
      label: 'Other',
      description: 'Anything else not covered above',
    },
  ];

  const handleInputChange = e => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value,
    }));

    // Clear error when user starts typing
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: '',
      }));
    }
  };

  const validateForm = () => {
    const newErrors = {};

    if (!formData.category) {
      newErrors.category = 'Please select a category';
    }

    if (!formData.subject.trim()) {
      newErrors.subject = 'Subject is required';
    } else if (formData.subject.trim().length < 5) {
      newErrors.subject = 'Subject must be at least 5 characters';
    }

    if (!formData.message.trim()) {
      newErrors.message = 'Message is required';
    } else if (formData.message.trim().length < 10) {
      newErrors.message = 'Message must be at least 10 characters';
    }

    // Email validation - skip if user is authenticated and email is pre-filled
    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      newErrors.email = 'Please enter a valid email address';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async e => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    setIsSubmitting(true);

    try {
      await apiClient.post('/api/contact', formData);

      showSuccess(
        'Message sent successfully!',
        "We'll get back to you as soon as possible."
      );

      // Reset form (keep email)
      setFormData({
        category: '',
        subject: '',
        message: '',
        email: formData.email, // Keep the user's email
      });
      setErrors({});
    } catch (error) {
      let errorMessage = 'Failed to send message';

      if (error.response) {
        // Server responded with error status
        if (error.response.status === 401) {
          errorMessage = 'Please log in to send a support message';
        } else if (error.response.status === 429) {
          errorMessage =
            error.response.data?.error ||
            'Too many requests. Please wait before trying again.';
        } else {
          errorMessage = error.response.data?.error || 'Failed to send message';
        }
      } else if (error.request) {
        // Network error
        errorMessage =
          'Network error. Please check your connection and try again.';
      } else {
        // Other error
        errorMessage = error.message || 'An unexpected error occurred';
      }

      showError('Failed to send message', errorMessage);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <>
      <SEO
        title='Help & Support'
        description="Contact TokenTimer support or send feedback. We're here to help."
        noindex
      />
      <Navigation
        user={session}
        onLogout={onLogout}
        onAccountClick={onAccountClick}
        onNavigateToDashboard={onNavigateToDashboard}
        onNavigateToLanding={onNavigateToLanding}
      />
      <Container maxW='4xl' py={8} px={{ base: 4, md: 6 }} overflowX='hidden'>
        <VStack spacing={8} align='stretch'>
          <Box textAlign='center' py={8}>
            <Heading as='h1' size='2xl' mb={4}>
              Help <span style={{ fontFamily: 'Montserrat' }}>&</span> Support
            </Heading>
            <Text fontSize='lg' color={textColor}>
              We{"'"}re here to help! Send us a message and we{"'"}ll get back
              to you as soon as possible.
            </Text>
          </Box>

          {/* Contact Form */}
          <Box
            bg={bgColor}
            p={8}
            borderRadius='md'
            boxShadow='sm'
            border='1px solid'
            borderColor={borderColor}
          >
            <VStack spacing={6} as='form' onSubmit={handleSubmit}>
              <Heading size='md' mb={4}>
                Contact Form
              </Heading>

              {/* Category Selection */}
              <FormControl isInvalid={!!errors.category}>
                <FormLabel>Category *</FormLabel>
                <Select
                  name='category'
                  value={formData.category}
                  onChange={handleInputChange}
                  placeholder='Select a category'
                  size='lg'
                >
                  {categories.map(category => (
                    <option key={category.value} value={category.value}>
                      {category.label}
                    </option>
                  ))}
                </Select>
                <FormErrorMessage>{errors.category}</FormErrorMessage>
              </FormControl>

              {/* Email */}
              <FormControl isInvalid={!!errors.email}>
                <FormLabel>Your Email *</FormLabel>
                <Input
                  name='email'
                  type='email'
                  value={formData.email}
                  placeholder='your.email@example.com'
                  size='lg'
                  isReadOnly
                  bg={useColorModeValue(
                    'rgba(255, 255, 255, 0.95)',
                    'gray.700'
                  )}
                  borderColor={useColorModeValue('gray.400', 'gray.600')}
                  _hover={{
                    bg: useColorModeValue(
                      'rgba(255, 255, 255, 0.95)',
                      'gray.700'
                    ),
                  }}
                  _focus={{
                    bg: useColorModeValue(
                      'rgba(255, 255, 255, 0.95)',
                      'gray.700'
                    ),
                  }}
                  color={useColorModeValue('gray.900', 'white')}
                  _readOnly={{
                    bg: useColorModeValue(
                      'rgba(255, 255, 255, 0.95)',
                      'gray.700'
                    ),
                    color: useColorModeValue('gray.900', 'white'),
                    borderColor: useColorModeValue('gray.400', 'gray.600'),
                    cursor: 'default',
                  }}
                />
                <FormErrorMessage>{errors.email}</FormErrorMessage>
              </FormControl>

              {/* Subject */}
              <FormControl isInvalid={!!errors.subject}>
                <FormLabel>Subject *</FormLabel>
                <Input
                  name='subject'
                  value={formData.subject}
                  onChange={handleInputChange}
                  placeholder='Brief description of your issue'
                  size='lg'
                />
                <FormErrorMessage>{errors.subject}</FormErrorMessage>
              </FormControl>

              {/* Message */}
              <FormControl isInvalid={!!errors.message}>
                <FormLabel>Message *</FormLabel>
                <Textarea
                  name='message'
                  value={formData.message}
                  onChange={handleInputChange}
                  placeholder='Please provide details about your issue, suggestion, or question...'
                  size='lg'
                  rows={6}
                  resize='vertical'
                />
                <FormErrorMessage>{errors.message}</FormErrorMessage>
              </FormControl>

              {/* Submit Button */}
              <Button
                type='submit'
                colorScheme='blue'
                size='lg'
                isLoading={isSubmitting}
                loadingText='Sending...'
                width='full'
              >
                Send Message
              </Button>
            </VStack>
          </Box>

          {/* Additional Help Options */}
          <Box
            bg={bgColor}
            p={6}
            borderRadius='md'
            boxShadow='sm'
            border='1px solid'
            borderColor={borderColor}
          >
            <Heading size='md' mb={4}>
              Other Ways to Get Help
            </Heading>
            <VStack spacing={4} align='stretch'>
              <Alert status='info' borderRadius='md'>
                <AlertIcon />
                <Box>
                  <AlertTitle>Need Help?</AlertTitle>
                  <AlertDescription>
                    For urgent issues, contact your system administrator.
                  </AlertDescription>
                </Box>
              </Alert>

              <Alert status='info' borderRadius='md'>
                <AlertIcon />
                <Box>
                  <AlertTitle>Documentation</AlertTitle>
                  <AlertDescription>
                    Visit the{' '}
                    <Link
                      as={RouterLink}
                      to='/docs'
                      color='blue.500'
                      textDecoration='underline'
                    >
                      Product & API Docs
                    </Link>{' '}
                    for usage guides and API reference.
                  </AlertDescription>
                </Box>
              </Alert>

              <Alert status='info' borderRadius='md'>
                <AlertIcon />
                <Box>
                  <AlertTitle>Response Time</AlertTitle>
                  <AlertDescription>
                    We typically respond within 24 hours during business days.
                    For urgent security issues, please email us directly.
                  </AlertDescription>
                </Box>
              </Alert>

              <Alert status='info' borderRadius='md'>
                <AlertIcon />
                <Box>
                  <AlertTitle>Feature Requests</AlertTitle>
                  <AlertDescription>
                    Want to suggest a new feature or report a bug? Visit the{' '}
                    <Link
                      href='https://github.com/tokentimerch/tokentimer-core/issues'
                      isExternal
                      color='blue.500'
                      textDecoration='underline'
                    >
                      GitHub Issues
                    </Link>{' '}
                    page.
                  </AlertDescription>
                </Box>
              </Alert>
            </VStack>
          </Box>
        </VStack>
      </Container>
    </>
  );
}

export default Help;
