import { useEffect, useState } from 'react';
import {
  Box,
  Heading,
  Text,
  VStack,
  HStack,
  FormControl,
  FormLabel,
  Input,
  Button,
  Alert,
  AlertIcon,
  AlertDescription,
  Badge,
  useColorModeValue,
  Divider,
  InputGroup,
  InputRightElement,
  IconButton,
  Tooltip,
  Switch,
} from '@chakra-ui/react';
import { FiEye, FiEyeOff, FiCheck, FiX } from 'react-icons/fi';
import apiClient from '../utils/apiClient';
import { showSuccess, showWarning } from '../utils/toast.js';
import Navigation from '../components/Navigation';
import SEO from '../components/SEO.jsx';
import { logger } from '../utils/logger.js';

/**
 * Admin-only System Settings page.
 * Allows configuring SMTP and Twilio WhatsApp settings from the UI.
 * Fields set via environment variables are greyed out with a warning badge.
 */
export default function SystemSettings({
  session,
  onLogout,
  onAccountClick,
  onNavigateToDashboard,
  onNavigateToLanding,
}) {
  const [loading, setLoading] = useState(true);
  const [savingSmtp, setSavingSmtp] = useState(false);
  const [savingWhatsapp, setSavingWhatsapp] = useState(false);
  const [smtp, setSmtp] = useState({});
  const [whatsapp, setWhatsapp] = useState({});
  const [smtpForm, setSmtpForm] = useState({});
  const [whatsappForm, setWhatsappForm] = useState({});
  const [testingSmtp, setTestingSmtp] = useState(false);
  const [testingWhatsapp, setTestingWhatsapp] = useState(false);
  const [testEmail, setTestEmail] = useState('');
  const [testPhone, setTestPhone] = useState('');
  const [showSmtpPass, setShowSmtpPass] = useState(false);
  const [showAuthToken, setShowAuthToken] = useState(false);

  const cardBg = useColorModeValue('white', 'gray.800');
  const borderColor = useColorModeValue('gray.200', 'gray.700');
  const lockedInputBg = useColorModeValue('gray.100', 'gray.700');
  const grayText = useColorModeValue('gray.600', 'gray.400');
  const subTitleColor = useColorModeValue('gray.600', 'gray.300');

  useEffect(() => {
    loadSettings();
  }, []);

  async function loadSettings() {
    try {
      setLoading(true);
      const res = await apiClient.get('/api/admin/system-settings');
      const data = res.data || {};
      setSmtp(data.smtp || {});
      setWhatsapp(data.whatsapp || {});
      // Initialize form values from current settings (use empty string for nulls)
      setSmtpForm({
        host: data.smtp?.host?.value || '',
        port: data.smtp?.port?.value || '',
        user: data.smtp?.user?.value || '',
        pass: '', // Never pre-fill passwords
        from_email: data.smtp?.from_email?.value || '',
        from_name: data.smtp?.from_name?.value || '',
        secure: data.smtp?.secure?.value === 'true',
        require_tls: data.smtp?.require_tls?.value !== 'false',
      });
      setWhatsappForm({
        account_sid: data.whatsapp?.account_sid?.value || '',
        auth_token: '', // Never pre-fill secrets
        whatsapp_from: data.whatsapp?.whatsapp_from?.value || '',
        test_content_sid: data.whatsapp?.test_content_sid?.value || '',
        alert_content_sid_expires:
          data.whatsapp?.alert_content_sid_expires?.value || '',
        alert_content_sid_expired:
          data.whatsapp?.alert_content_sid_expired?.value || '',
        alert_content_sid_endpoint_down:
          data.whatsapp?.alert_content_sid_endpoint_down?.value || '',
        alert_content_sid_endpoint_recovered:
          data.whatsapp?.alert_content_sid_endpoint_recovered?.value || '',
        weekly_digest_content_sid:
          data.whatsapp?.weekly_digest_content_sid?.value || '',
      });
    } catch (e) {
      logger.error('Failed to load system settings', e);
      showWarning('Failed to load system settings');
    } finally {
      setLoading(false);
    }
  }

  async function handleSaveSmtp() {
    try {
      setSavingSmtp(true);
      const smtpPayload = {};
      for (const [key, val] of Object.entries(smtpForm)) {
        const setting = smtp[key];
        if (setting?.locked) continue;
        if (val !== undefined && val !== '') smtpPayload[key] = val;
        else if (val === '' && setting?.value) smtpPayload[key] = null;
      }
      const res = await apiClient.put('/api/admin/system-settings', {
        smtp: smtpPayload,
      });
      const data = res.data || {};
      setSmtp(data.smtp || {});
      setWhatsapp(data.whatsapp || {});
      showSuccess('Email (SMTP) settings saved');
    } catch (e) {
      logger.error('Failed to save SMTP settings', e);
      showWarning(e?.response?.data?.error || 'Failed to save SMTP settings');
    } finally {
      setSavingSmtp(false);
    }
  }

  async function handleSaveWhatsapp() {
    try {
      setSavingWhatsapp(true);
      const waPayload = {};
      for (const [key, val] of Object.entries(whatsappForm)) {
        const setting = whatsapp[key];
        if (setting?.locked) continue;
        if (val !== undefined && val !== '') waPayload[key] = val;
        else if (val === '' && setting?.value) waPayload[key] = null;
      }
      const res = await apiClient.put('/api/admin/system-settings', {
        whatsapp: waPayload,
      });
      const data = res.data || {};
      setSmtp(data.smtp || {});
      setWhatsapp(data.whatsapp || {});
      showSuccess('WhatsApp (Twilio) settings saved');
    } catch (e) {
      logger.error('Failed to save WhatsApp settings', e);
      showWarning(
        e?.response?.data?.error || 'Failed to save WhatsApp settings'
      );
    } finally {
      setSavingWhatsapp(false);
    }
  }

  async function handleTestSmtp() {
    const email = testEmail.trim();
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      showWarning('Enter a valid email address for the test');
      return;
    }
    try {
      setTestingSmtp(true);
      const res = await apiClient.post('/api/admin/test-smtp', { email });
      showSuccess(res.data?.message || 'Test email sent');
    } catch (e) {
      showWarning(e?.response?.data?.error || 'SMTP test failed');
    } finally {
      setTestingSmtp(false);
    }
  }

  async function handleTestWhatsapp() {
    if (!testPhone || !/^\+?\d{6,15}$/.test(testPhone.trim())) {
      showWarning(
        'Enter a valid phone number in E.164 format (e.g. +14155550100)'
      );
      return;
    }
    try {
      setTestingWhatsapp(true);
      const res = await apiClient.post('/api/admin/test-whatsapp', {
        phone: testPhone.trim(),
      });
      showSuccess(res.data?.message || 'Test message sent');
    } catch (e) {
      showWarning(e?.response?.data?.error || 'WhatsApp test failed');
    } finally {
      setTestingWhatsapp(false);
    }
  }

  function renderField(label, key, section, form, setForm, options = {}) {
    const setting = section[key] || {};
    const isLocked = setting.locked === true;
    const { isSecret } = options;
    const showPassword = options.showState;
    const { toggleShow } = options;
    const placeholder = options.placeholder || '';

    return (
      <FormControl key={key} isDisabled={isLocked}>
        <FormLabel fontSize='sm' mb={1}>
          <HStack spacing={2}>
            <Text>{label}</Text>
            {isLocked && (
              <Tooltip label='This value is set via an environment variable and cannot be changed from the UI. To modify it, update your .env file or container environment and restart the application.'>
                <Badge
                  colorScheme='orange'
                  variant='solid'
                  fontSize='xs'
                  px={2}
                  py={0.5}
                  borderRadius='md'
                  cursor='help'
                >
                  ENV
                </Badge>
              </Tooltip>
            )}
            {!isLocked && setting.source === 'database' && (
              <Badge colorScheme='blue' fontSize='xs'>
                Saved in database
              </Badge>
            )}
          </HStack>
        </FormLabel>
        {isSecret ? (
          <InputGroup size='sm'>
            <Input
              type={showPassword ? 'text' : 'password'}
              value={isLocked ? setting.value || '' : form[key] || ''}
              onChange={e =>
                setForm(prev => ({ ...prev, [key]: e.target.value }))
              }
              placeholder={
                isLocked
                  ? ''
                  : setting.value
                    ? 'Leave blank to keep current value'
                    : placeholder
              }
              isReadOnly={isLocked}
              bg={isLocked ? lockedInputBg : undefined}
            />
            {!isLocked && (
              <InputRightElement>
                <IconButton
                  size='xs'
                  variant='ghost'
                  icon={showPassword ? <FiEyeOff /> : <FiEye />}
                  onClick={toggleShow}
                  aria-label={showPassword ? 'Hide' : 'Show'}
                />
              </InputRightElement>
            )}
          </InputGroup>
        ) : (
          <Input
            size='sm'
            value={isLocked ? setting.value || '' : form[key] || ''}
            onChange={e =>
              setForm(prev => ({ ...prev, [key]: e.target.value }))
            }
            placeholder={placeholder}
            isReadOnly={isLocked}
            bg={isLocked ? lockedInputBg : undefined}
          />
        )}
      </FormControl>
    );
  }

  function renderBooleanField(
    label,
    key,
    section,
    form,
    setForm,
    options = {}
  ) {
    const setting = section[key] || {};
    const isLocked = setting.locked === true;

    return (
      <FormControl key={key} isDisabled={isLocked}>
        <FormLabel fontSize='sm' mb={1}>
          <HStack spacing={2}>
            <Text>{label}</Text>
            {isLocked && (
              <Tooltip label='This value is set via an environment variable and cannot be changed from the UI. To modify it, update your .env file or container environment and restart the application.'>
                <Badge
                  colorScheme='orange'
                  variant='solid'
                  fontSize='xs'
                  px={2}
                  py={0.5}
                  borderRadius='md'
                  cursor='help'
                >
                  ENV
                </Badge>
              </Tooltip>
            )}
            {!isLocked && setting.source === 'database' && (
              <Badge colorScheme='blue' fontSize='xs'>
                Saved in database
              </Badge>
            )}
          </HStack>
        </FormLabel>
        <HStack spacing={3}>
          <Switch
            isChecked={isLocked ? setting.value === 'true' : !!form[key]}
            onChange={e =>
              setForm(prev => ({ ...prev, [key]: e.target.checked }))
            }
            isDisabled={isLocked}
          />
          <Text fontSize='sm' color={grayText}>
            {options.helpText || ''}
          </Text>
        </HStack>
      </FormControl>
    );
  }

  if (loading) {
    return (
      <>
        <SEO title='System Settings' />
        <Navigation
          user={session}
          onLogout={onLogout}
          onAccountClick={onAccountClick}
          onNavigateToDashboard={onNavigateToDashboard}
          onNavigateToLanding={onNavigateToLanding}
        />
        <Box maxW='800px' mx='auto' py={8} px={4}>
          <Text>Loading system settings...</Text>
        </Box>
      </>
    );
  }

  return (
    <>
      <SEO title='System Settings' />
      <Navigation
        user={session}
        onLogout={onLogout}
        onAccountClick={onAccountClick}
        onNavigateToDashboard={onNavigateToDashboard}
        onNavigateToLanding={onNavigateToLanding}
      />
      <Box maxW='800px' mx='auto' py={8} px={4}>
        <VStack align='stretch' spacing={6}>
          <Heading size='lg'>System Settings</Heading>
          <Text color={subTitleColor}>
            Configure email (SMTP) and WhatsApp (Twilio) notification providers.
            Settings defined via environment variables take priority and cannot
            be changed here.
          </Text>

          {/* SMTP Configuration */}
          <Box
            bg={cardBg}
            p={6}
            borderRadius='md'
            boxShadow='sm'
            border='1px solid'
            borderColor={borderColor}
          >
            <HStack justify='space-between' mb={4}>
              <Heading size='md'>Email (SMTP)</Heading>
              <HStack spacing={2}>
                {smtp.configured ? (
                  <Badge
                    colorScheme='green'
                    display='flex'
                    alignItems='center'
                    gap={1}
                  >
                    <FiCheck size={12} /> Configured
                  </Badge>
                ) : (
                  <Badge
                    colorScheme='orange'
                    display='flex'
                    alignItems='center'
                    gap={1}
                  >
                    <FiX size={12} /> Not configured
                  </Badge>
                )}
              </HStack>
            </HStack>

            <VStack align='stretch' spacing={3}>
              <HStack spacing={4} align='start'>
                <Box flex={3}>
                  {renderField(
                    'SMTP Host',
                    'host',
                    smtp,
                    smtpForm,
                    setSmtpForm,
                    { placeholder: 'smtp.example.com' }
                  )}
                </Box>
                <Box flex={1}>
                  {renderField('Port', 'port', smtp, smtpForm, setSmtpForm, {
                    placeholder: '465',
                  })}
                </Box>
              </HStack>
              {renderField('SMTP User', 'user', smtp, smtpForm, setSmtpForm, {
                placeholder: 'user@example.com',
              })}
              {renderField(
                'SMTP Password',
                'pass',
                smtp,
                smtpForm,
                setSmtpForm,
                {
                  isSecret: true,
                  showState: showSmtpPass,
                  toggleShow: () => setShowSmtpPass(p => !p),
                  placeholder: 'Enter SMTP password',
                }
              )}
              <HStack spacing={4} align='start'>
                <Box flex={1}>
                  {renderBooleanField(
                    'Force SSL/TLS (SMTPS)',
                    'secure',
                    smtp,
                    smtpForm,
                    setSmtpForm,
                    {
                      helpText:
                        'When disabled, SSL is auto-detected from port 465.',
                    }
                  )}
                </Box>
                <Box flex={1}>
                  {renderBooleanField(
                    'Require STARTTLS upgrade',
                    'require_tls',
                    smtp,
                    smtpForm,
                    setSmtpForm,
                    {
                      helpText: 'Recommended and enabled by default.',
                    }
                  )}
                </Box>
              </HStack>
              <Divider />
              <HStack spacing={4} align='start'>
                <Box flex={1}>
                  {renderField(
                    'From Email',
                    'from_email',
                    smtp,
                    smtpForm,
                    setSmtpForm,
                    { placeholder: 'noreply@example.com' }
                  )}
                </Box>
                <Box flex={1}>
                  {renderField(
                    'From Name',
                    'from_name',
                    smtp,
                    smtpForm,
                    setSmtpForm,
                    { placeholder: 'TokenTimer' }
                  )}
                </Box>
              </HStack>
            </VStack>

            <HStack
              mt={4}
              spacing={3}
              justify='space-between'
              align='end'
              flexWrap='wrap'
              rowGap={3}
            >
              <HStack spacing={3} align='end' flexWrap='wrap' rowGap={2}>
                <FormControl maxW='220px' isDisabled={!smtp.configured}>
                  <FormLabel fontSize='sm' mb={1}>
                    Test recipient
                  </FormLabel>
                  <Input
                    size='sm'
                    placeholder={session?.email || 'recipient@example.com'}
                    value={testEmail}
                    onChange={e => setTestEmail(e.target.value)}
                  />
                </FormControl>
                <Button
                  size='sm'
                  colorScheme='blue'
                  variant='outline'
                  px={4}
                  isLoading={testingSmtp}
                  onClick={handleTestSmtp}
                  isDisabled={!smtp.configured}
                >
                  Send test email
                </Button>
              </HStack>
              <Button
                size='sm'
                colorScheme='blue'
                isLoading={savingSmtp}
                onClick={handleSaveSmtp}
              >
                Save SMTP
              </Button>
            </HStack>
          </Box>

          {/* Twilio WhatsApp Configuration */}
          <Box
            bg={cardBg}
            p={6}
            borderRadius='md'
            boxShadow='sm'
            border='1px solid'
            borderColor={borderColor}
          >
            <HStack justify='space-between' mb={4}>
              <Heading size='md'>WhatsApp (Twilio)</Heading>
              <HStack spacing={2}>
                {whatsapp.configured ? (
                  <Badge
                    colorScheme='green'
                    display='flex'
                    alignItems='center'
                    gap={1}
                  >
                    <FiCheck size={12} /> Configured
                  </Badge>
                ) : (
                  <Badge
                    colorScheme='orange'
                    display='flex'
                    alignItems='center'
                    gap={1}
                  >
                    <FiX size={12} /> Not configured
                  </Badge>
                )}
              </HStack>
            </HStack>

            {!whatsapp.configured && (
              <Alert status='info' mb={4} borderRadius='md'>
                <AlertIcon />
                <AlertDescription fontSize='sm'>
                  WhatsApp features are hidden from all users until Twilio is
                  configured. You need a Twilio account with WhatsApp Business
                  enabled.
                </AlertDescription>
              </Alert>
            )}

            <VStack align='stretch' spacing={3}>
              <Text fontWeight='semibold' fontSize='sm' color={grayText}>
                Required
              </Text>
              {renderField(
                'Account SID',
                'account_sid',
                whatsapp,
                whatsappForm,
                setWhatsappForm,
                { placeholder: 'ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' }
              )}
              {renderField(
                'Auth Token',
                'auth_token',
                whatsapp,
                whatsappForm,
                setWhatsappForm,
                {
                  isSecret: true,
                  showState: showAuthToken,
                  toggleShow: () => setShowAuthToken(p => !p),
                  placeholder: 'Enter Twilio Auth Token',
                }
              )}
              <HStack spacing={4} align='start'>
                <Box flex={1}>
                  {renderField(
                    'WhatsApp From Number',
                    'whatsapp_from',
                    whatsapp,
                    whatsappForm,
                    setWhatsappForm,
                    { placeholder: '+14155238886' }
                  )}
                </Box>
              </HStack>

              <Divider />
              <Text fontWeight='semibold' fontSize='sm' color={grayText}>
                Content Templates
              </Text>
              <HStack spacing={4} align='start'>
                <Box flex={1}>
                  {renderField(
                    'Alert (Expires) Template SID',
                    'alert_content_sid_expires',
                    whatsapp,
                    whatsappForm,
                    setWhatsappForm,
                    { placeholder: 'HXxxxxxxxxx' }
                  )}
                </Box>
                <Box flex={1}>
                  {renderField(
                    'Alert (Expired) Template SID',
                    'alert_content_sid_expired',
                    whatsapp,
                    whatsappForm,
                    setWhatsappForm,
                    { placeholder: 'HXxxxxxxxxx' }
                  )}
                </Box>
              </HStack>
              <HStack spacing={4} align='start'>
                <Box flex={1}>
                  {renderField(
                    'Endpoint Down Template SID',
                    'alert_content_sid_endpoint_down',
                    whatsapp,
                    whatsappForm,
                    setWhatsappForm,
                    { placeholder: 'HXxxxxxxxxx' }
                  )}
                </Box>
                <Box flex={1}>
                  {renderField(
                    'Endpoint Recovered Template SID',
                    'alert_content_sid_endpoint_recovered',
                    whatsapp,
                    whatsappForm,
                    setWhatsappForm,
                    { placeholder: 'HXxxxxxxxxx' }
                  )}
                </Box>
              </HStack>
              <HStack spacing={4} align='start'>
                <Box flex={1}>
                  {renderField(
                    'Test Message Template SID',
                    'test_content_sid',
                    whatsapp,
                    whatsappForm,
                    setWhatsappForm,
                    { placeholder: 'HXxxxxxxxxx' }
                  )}
                </Box>
                <Box flex={1}>
                  {renderField(
                    'Weekly Digest Template SID',
                    'weekly_digest_content_sid',
                    whatsapp,
                    whatsappForm,
                    setWhatsappForm,
                    { placeholder: 'HXxxxxxxxxx' }
                  )}
                </Box>
              </HStack>
            </VStack>

            <HStack
              mt={4}
              spacing={3}
              justify='space-between'
              align='end'
              flexWrap='wrap'
              rowGap={3}
            >
              <HStack spacing={3} align='end' flexWrap='wrap' rowGap={2}>
                <FormControl maxW='200px' isDisabled={!whatsapp.configured}>
                  <FormLabel fontSize='sm' mb={1}>
                    Test recipient
                  </FormLabel>
                  <Input
                    size='sm'
                    placeholder='+14155550100'
                    value={testPhone}
                    onChange={e => setTestPhone(e.target.value)}
                  />
                </FormControl>
                <Button
                  size='sm'
                  colorScheme='green'
                  variant='outline'
                  px={4}
                  isLoading={testingWhatsapp}
                  onClick={handleTestWhatsapp}
                  isDisabled={!whatsapp.configured}
                >
                  Send test WhatsApp
                </Button>
              </HStack>
              <Button
                size='sm'
                colorScheme='blue'
                isLoading={savingWhatsapp}
                onClick={handleSaveWhatsapp}
              >
                Save WhatsApp
              </Button>
            </HStack>
          </Box>
        </VStack>
      </Box>
    </>
  );
}
