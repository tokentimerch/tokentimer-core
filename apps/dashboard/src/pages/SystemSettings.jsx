import { useEffect, useState } from 'react';
import { Link as RouterLink, useLocation, useSearchParams } from 'react-router';
import {
  Box,
  Text,
  VStack,
  HStack,
  Stack,
  FormControl,
  FormLabel,
  Input,
  Alert,
  AlertIcon,
  AlertDescription,
  Badge,
  Divider,
  Icon,
  InputGroup,
  InputRightElement,
  IconButton,
  Tooltip,
  Switch,
  Button,
  Collapse,
  FormHelperText,
  Heading,
} from '@chakra-ui/react';
import {
  FiChevronDown,
  FiChevronUp,
  FiEye,
  FiEyeOff,
  FiKey,
  FiMail,
  FiRepeat,
} from 'react-icons/fi';
import { FaWhatsapp } from 'react-icons/fa';
import TestWhatsappButton from '../components/TestWhatsappButton.jsx';
import AutoSyncSystemMetricSettings from '../components/AutoSyncSystemMetricSettings.jsx';
import AutoSyncMultiConfigPanel from '../components/AutoSyncMultiConfigPanel.jsx';
import { AUTO_SYNC_MULTI_CONFIG_HASH } from '../utils/autoSyncActivation.jsx';
import apiClient from '../utils/apiClient';
import { showSuccess, showWarning } from '../utils/toast.js';
import DashboardPageLayout from '../components/DashboardPageLayout';
import {
  DashboardActionButton,
  DashboardPanel,
  DashboardState,
} from '../components/DashboardPrimitives';
import { SettingsIntegrationCard } from '../components/SettingsIntegrationHub.jsx';
import { SettingsFormWidth } from '../components/SettingsPageShell.jsx';
import { SETTINGS_SECTION_GAP } from '../styles/dashboardLayout';
import SEO from '../components/SEO.jsx';
import { useDashboardTheme } from '../hooks/useDashboardTheme';
import { logger } from '../utils/logger.js';
import { isValidEmail } from '../utils/emailAddress.js';
import {
  SsoGroupMappingModal,
  SsoGroupMappingsSection,
  useSsoGroupMappings,
} from '../components/SsoGroupMappings.jsx';

const DEFAULT_SSO_FORM = {
  allow_auto_link_local_accounts: false,
  strict_membership_sync: true,
  config_sync_interval_ms: 45000,
  idp_http_timeout_ms: 20000,
  allow_private_idp_urls: false,
  allowed_idp_cidrs: '',
};

function ssoSettingVal(section, key, fallback = '') {
  const raw = section?.[key]?.value;
  if (raw === true || raw === false) return raw;
  if (raw === null || raw === undefined || raw === '') return fallback;
  return raw;
}

function ssoSettingLocked(section, key) {
  return !!section?.[key]?.locked;
}

function ssoFormFromSection(section, prev = DEFAULT_SSO_FORM) {
  return {
    allow_auto_link_local_accounts: ssoSettingVal(
      section,
      'allow_auto_link_local_accounts',
      prev.allow_auto_link_local_accounts
    ),
    strict_membership_sync: ssoSettingVal(
      section,
      'strict_membership_sync',
      prev.strict_membership_sync
    ),
    config_sync_interval_ms: Number(
      ssoSettingVal(
        section,
        'config_sync_interval_ms',
        prev.config_sync_interval_ms
      )
    ),
    idp_http_timeout_ms: Number(
      ssoSettingVal(section, 'idp_http_timeout_ms', prev.idp_http_timeout_ms)
    ),
    allow_private_idp_urls: ssoSettingVal(
      section,
      'allow_private_idp_urls',
      prev.allow_private_idp_urls
    ),
    allowed_idp_cidrs: ssoSettingVal(
      section,
      'allowed_idp_cidrs',
      prev.allowed_idp_cidrs
    ),
  };
}

function ssoSectionPersisted(section) {
  if (!section || typeof section !== 'object') return false;
  return Object.keys(DEFAULT_SSO_FORM).some(key => {
    const entry = section[key];
    return entry && entry.value !== undefined && entry.value !== null;
  });
}
/**
 * Admin-only System Settings page.
 * Allows configuring SSO, SMTP, and Twilio WhatsApp settings from the UI.
 * Fields set via environment variables are greyed out with a warning badge.
 */
export default function SystemSettings({ session, onLogout, onAccountClick }) {
  const [loading, setLoading] = useState(true);
  const [savingSso, setSavingSso] = useState(false);
  const [sso, setSso] = useState({});
  const [ssoForm, setSsoForm] = useState({ ...DEFAULT_SSO_FORM });
  const [showSsoAdvanced, setShowSsoAdvanced] = useState(false);
  const [savingSmtp, setSavingSmtp] = useState(false);
  const [savingWhatsapp, setSavingWhatsapp] = useState(false);
  const [smtp, setSmtp] = useState({});
  const [whatsapp, setWhatsapp] = useState({});
  const [smtpForm, setSmtpForm] = useState({});
  const [whatsappForm, setWhatsappForm] = useState({});
  const [testingSmtp, setTestingSmtp] = useState(false);
  const [testingWhatsapp, setTestingWhatsapp] = useState(false);
  const [testEmail, setTestEmail] = useState('');
  const smtpTestRecipient = smtp.test_recipient || null;
  const [testPhone, setTestPhone] = useState('');
  const [showSmtpPass, setShowSmtpPass] = useState(false);
  const [showAuthToken, setShowAuthToken] = useState(false);
  const [openIntegration, setOpenIntegration] = useState('smtp');
  const [autoSyncMetricsConfigured, setAutoSyncMetricsConfigured] =
    useState(false);
  const [autoSyncMultiConfigEnabled, setAutoSyncMultiConfigEnabled] =
    useState(null);
  const location = useLocation();
  const mappingsState = useSsoGroupMappings();
  const { mappingsLoading, mappingProviders, mappings } = mappingsState;
  const [searchParams, setSearchParams] = useSearchParams();
  const [wizardMappingHint, setWizardMappingHint] = useState(null);

  const { muted, dashboard } = useDashboardTheme();
  const lockedInputBg = dashboard.bg.panelHover;

  useEffect(() => {
    loadSettings();
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await apiClient.get('/api/v1/admin/auto-sync/activation');
        if (!cancelled) {
          setAutoSyncMultiConfigEnabled(res.data?.enabled === true);
        }
      } catch (e) {
        logger.error('Failed to load auto-sync activation', e);
        if (!cancelled) setAutoSyncMultiConfigEnabled(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (
      location.hash !== `#${AUTO_SYNC_MULTI_CONFIG_HASH}` &&
      location.hash !== '#auto-sync'
    )
      return;
    if (location.hash !== '#auto-sync' && autoSyncMultiConfigEnabled !== false)
      return;
    setOpenIntegration('auto-sync');
    requestAnimationFrame(() => {
      document.getElementById('auto-sync')?.scrollIntoView({
        behavior: 'smooth',
        block: 'start',
      });
    });
  }, [location.hash, autoSyncMultiConfigEnabled]);

  useEffect(() => {
    if (searchParams.get('section') !== 'sso-group-mappings') return;
    if (openIntegration !== 'sso') {
      setOpenIntegration('sso');
      return;
    }
    if (loading || mappingsLoading) return;

    const providerSlug = searchParams.get('provider')?.trim() || '';
    if (providerSlug) {
      const label =
        mappingProviders.find(p => p.slug === providerSlug)?.displayName ||
        providerSlug;
      setWizardMappingHint(
        `${label} is enabled. Add at least one group mapping below so SSO users receive workspace roles automatically.`
      );
    }

    const frame = requestAnimationFrame(() => {
      document.getElementById('sso-group-mappings')?.scrollIntoView?.({
        behavior: 'smooth',
        block: 'start',
      });
      const next = new URLSearchParams(searchParams);
      next.delete('section');
      next.delete('provider');
      setSearchParams(next, { replace: true });
    });
    return () => cancelAnimationFrame(frame);
  }, [
    loading,
    openIntegration,
    mappingsLoading,
    mappingProviders,
    searchParams,
    setSearchParams,
  ]);

  async function loadSettings() {
    try {
      setLoading(true);
      const res = await apiClient.get('/api/admin/system-settings');
      const data = res.data || {};
      setSmtp(data.smtp || {});
      setWhatsapp(data.whatsapp || {});
      setSso(data.sso || {});
      setSsoForm(ssoFormFromSection(data.sso));
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

  function buildSsoPayload() {
    const payload = {};
    for (const key of Object.keys(DEFAULT_SSO_FORM)) {
      if (ssoSettingLocked(sso, key)) continue;
      payload[key] = ssoForm[key];
    }
    return payload;
  }

  async function handleSaveSso() {
    const submitted = buildSsoPayload();
    try {
      setSavingSso(true);
      const res = await apiClient.put('/api/admin/system-settings', {
        sso: submitted,
      });
      const saved = res.data?.sso;
      if (!ssoSectionPersisted(saved)) {
        showWarning('SSO policy could not be persisted.');
        return;
      }
      setSso(saved);
      setSsoForm(prev => ssoFormFromSection(saved, prev));
      showSuccess('SSO policy settings saved');
    } catch (e) {
      logger.error('Failed to save SSO settings', e);
      showWarning(e?.response?.data?.error || 'Failed to save SSO settings');
    } finally {
      setSavingSso(false);
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
    const email = smtpTestRecipient || testEmail.trim() || session?.email || '';
    if (!isValidEmail(email)) {
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
      await apiClient.post('/api/admin/test-whatsapp', {
        phone: testPhone.trim(),
      });
      showSuccess(
        'Test submitted. Check the destination phone to confirm delivery.'
      );
    } catch (e) {
      showWarning(
        String(e?.response?.data?.code || '') === '63112'
          ? 'WhatsApp provider account unavailable. Check Meta business verification and account status for this sender.'
          : e?.response?.data?.error || 'WhatsApp test failed'
      );
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
              <Tooltip
                hasArrow
                placement='top'
                label='This value is set via an environment variable and cannot be changed from the UI. To modify it, update your .env file or container environment and restart the application.'
              >
                <Box as='span' display='inline-block'>
                  <Badge colorScheme='orange' variant='subtle' cursor='help'>
                    ENV
                  </Badge>
                </Box>
              </Tooltip>
            )}
            {!isLocked && setting.source === 'database' && (
              <Badge colorScheme='blue'>Saved in database</Badge>
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
              <Tooltip
                hasArrow
                placement='top'
                label='This value is set via an environment variable and cannot be changed from the UI. To modify it, update your .env file or container environment and restart the application.'
              >
                <Box as='span' display='inline-block'>
                  <Badge colorScheme='orange' variant='subtle' cursor='help'>
                    ENV
                  </Badge>
                </Box>
              </Tooltip>
            )}
            {!isLocked && setting.source === 'database' && (
              <Badge colorScheme='blue'>Saved in database</Badge>
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
          <Text fontSize='sm' color={muted}>
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
        <DashboardPageLayout
          session={session}
          onLogout={onLogout}
          onAccountClick={onAccountClick}
          pageTitle='System settings'
          variant='wide'
          contentProps={{ overflowX: 'hidden', w: 'full', maxW: '100%' }}
        >
          <DashboardPanel>
            <DashboardState type='loading' title='Loading system settings...' />
          </DashboardPanel>
        </DashboardPageLayout>
      </>
    );
  }

  return (
    <>
      <SEO title='System Settings' />
      <DashboardPageLayout
        session={session}
        onLogout={onLogout}
        onAccountClick={onAccountClick}
        pageTitle='System settings'
        variant='wide'
        contentProps={{ overflowX: 'hidden', w: 'full', maxW: '100%' }}
      >
        <VStack align='stretch' spacing={SETTINGS_SECTION_GAP} w='full'>
          <SettingsIntegrationCard
            title='Single Sign-On (SSO)'
            description='Connect identity providers, enable sign-in, and map IdP groups to TokenTimer roles.'
            icon={<Icon as={FiKey} boxSize={6} color='blue.500' />}
            configured={mappingProviders.length > 0}
            isOpen={openIntegration === 'sso'}
            onToggle={() =>
              setOpenIntegration(prev => (prev === 'sso' ? null : 'sso'))
            }
          >
            <SettingsFormWidth maxW='100%'>
              <HStack spacing={2} mb={4} flexWrap='wrap'>
                <Badge
                  colorScheme={mappingProviders.length > 0 ? 'green' : 'gray'}
                >
                  {mappingsLoading
                    ? '…'
                    : `${mappingProviders.length} provider${mappingProviders.length === 1 ? '' : 's'}`}
                </Badge>
                <Badge colorScheme={mappings.length > 0 ? 'green' : 'gray'}>
                  {mappingsLoading
                    ? '…'
                    : `${mappings.length} mapping${mappings.length === 1 ? '' : 's'}`}
                </Badge>
              </HStack>

              <Box>
                <Heading
                  size='sm'
                  mb={1}
                  color='inherit'
                  fontFamily='Archivo, system-ui, sans-serif'
                  fontWeight='bold'
                  lineHeight='short'
                >
                  Identity providers
                </Heading>
                <Text fontSize='sm' color={muted} mb={3} maxW='xl'>
                  Register Azure AD, Okta, Keycloak, or any OIDC / SAML
                  provider. Set callback URLs, store secrets, and enable
                  sign-in.
                </Text>
                <DashboardActionButton
                  as={RouterLink}
                  to='/sso-providers'
                  colorScheme='blue'
                  leftIcon={<FiKey />}
                  w={{ base: '100%', md: 'auto' }}
                >
                  Manage SSO providers
                </DashboardActionButton>
              </Box>

              <Box mt={6}>
                <Heading
                  size='sm'
                  mb={1}
                  color='inherit'
                  fontFamily='Archivo, system-ui, sans-serif'
                  fontWeight='bold'
                  lineHeight='short'
                >
                  Installation-wide SSO policy
                </Heading>
                <Text fontSize='sm' color={muted} mb={4} maxW='xl'>
                  Defaults for all providers. Per-provider overrides are
                  available under Manage SSO providers. Values set via
                  environment variables are read-only here.
                </Text>
                <VStack align='stretch' spacing={4}>
                  <FormControl
                    display='flex'
                    alignItems='center'
                    justifyContent='space-between'
                    isDisabled={ssoSettingLocked(
                      sso,
                      'allow_auto_link_local_accounts'
                    )}
                  >
                    <Box flex={1} pr={4}>
                      <FormLabel mb={0}>Allow auto-link by email</FormLabel>
                      <FormHelperText mt={0} fontSize='xs'>
                        Link SSO identities to existing accounts when the IdP
                        asserts the same email (local or SSO). Orphaned SSO
                        users relink after provider delete without this.
                      </FormHelperText>
                    </Box>
                    <Switch
                      isChecked={!!ssoForm.allow_auto_link_local_accounts}
                      onChange={e =>
                        setSsoForm(f => ({
                          ...f,
                          allow_auto_link_local_accounts: e.target.checked,
                        }))
                      }
                    />
                  </FormControl>
                  {ssoSettingLocked(sso, 'allow_auto_link_local_accounts') ? (
                    <Badge
                      colorScheme='orange'
                      variant='subtle'
                      alignSelf='flex-start'
                    >
                      Set via SSO_ALLOW_AUTO_LINK_LOCAL_ACCOUNTS
                    </Badge>
                  ) : null}
                  <FormControl
                    display='flex'
                    alignItems='center'
                    justifyContent='space-between'
                    isDisabled={ssoSettingLocked(sso, 'strict_membership_sync')}
                  >
                    <Box flex={1} pr={4}>
                      <FormLabel mb={0}>Strict membership sync</FormLabel>
                      <FormHelperText mt={0} fontSize='xs'>
                        Deny sign-in without mapped or existing access and revoke
                        workspace roles this provider no longer grants.
                      </FormHelperText>
                    </Box>
                    <Switch
                      isChecked={!!ssoForm.strict_membership_sync}
                      onChange={e =>
                        setSsoForm(f => ({
                          ...f,
                          strict_membership_sync: e.target.checked,
                        }))
                      }
                    />
                  </FormControl>
                  {ssoSettingLocked(sso, 'strict_membership_sync') ? (
                    <Badge
                      colorScheme='orange'
                      variant='subtle'
                      alignSelf='flex-start'
                    >
                      Set via SSO_STRICT_MEMBERSHIP_SYNC
                    </Badge>
                  ) : null}
                  <Button
                    variant='ghost'
                    size='sm'
                    alignSelf='flex-start'
                    rightIcon={
                      showSsoAdvanced ? <FiChevronUp /> : <FiChevronDown />
                    }
                    onClick={() => setShowSsoAdvanced(v => !v)}
                  >
                    {showSsoAdvanced
                      ? 'Hide advanced settings'
                      : 'Advanced settings'}
                  </Button>
                  <Collapse in={showSsoAdvanced}>
                    <VStack align='stretch' spacing={4} pt={1}>
                      <FormControl
                        isDisabled={ssoSettingLocked(
                          sso,
                          'config_sync_interval_ms'
                        )}
                      >
                        <FormLabel fontSize='sm'>
                          Config sync interval (ms)
                        </FormLabel>
                        <Input
                          size='sm'
                          type='number'
                          min={5000}
                          value={ssoForm.config_sync_interval_ms}
                          onChange={e =>
                            setSsoForm(f => ({
                              ...f,
                              config_sync_interval_ms:
                                Number(e.target.value) || 45000,
                            }))
                          }
                        />
                        <FormHelperText fontSize='xs'>
                          How often API pods poll sso_config_version. Takes
                          effect after API pod restart (env or database).
                        </FormHelperText>
                      </FormControl>
                      <FormControl
                        isDisabled={ssoSettingLocked(
                          sso,
                          'idp_http_timeout_ms'
                        )}
                      >
                        <FormLabel fontSize='sm'>
                          IdP HTTP timeout (ms)
                        </FormLabel>
                        <Input
                          size='sm'
                          type='number'
                          min={5000}
                          max={120000}
                          value={ssoForm.idp_http_timeout_ms}
                          onChange={e =>
                            setSsoForm(f => ({
                              ...f,
                              idp_http_timeout_ms:
                                Number(e.target.value) || 20000,
                            }))
                          }
                        />
                      </FormControl>
                      <FormControl
                        display='flex'
                        alignItems='center'
                        justifyContent='space-between'
                        isDisabled={ssoSettingLocked(
                          sso,
                          'allow_private_idp_urls'
                        )}
                      >
                        <Box flex={1} pr={4}>
                          <FormLabel mb={0}>Allow private IdP URLs</FormLabel>
                          <FormHelperText mt={0} fontSize='xs'>
                            Permit RFC1918 / localhost IdP endpoints (lab only).
                          </FormHelperText>
                        </Box>
                        <Switch
                          isChecked={!!ssoForm.allow_private_idp_urls}
                          onChange={e =>
                            setSsoForm(f => ({
                              ...f,
                              allow_private_idp_urls: e.target.checked,
                            }))
                          }
                        />
                      </FormControl>
                      <FormControl
                        isDisabled={ssoSettingLocked(sso, 'allowed_idp_cidrs')}
                      >
                        <FormLabel fontSize='sm'>Allowed IdP CIDRs</FormLabel>
                        <Input
                          size='sm'
                          placeholder='10.0.0.0/8, 192.168.1.0/24'
                          value={ssoForm.allowed_idp_cidrs}
                          onChange={e =>
                            setSsoForm(f => ({
                              ...f,
                              allowed_idp_cidrs: e.target.value,
                            }))
                          }
                        />
                        <FormHelperText fontSize='xs'>
                          Comma-separated IPv4 CIDRs allowed when private IdP
                          URLs are blocked. Leave empty to deny private ranges
                          unless &quot;Allow private IdP URLs&quot; is on.
                        </FormHelperText>
                        {ssoSettingLocked(sso, 'allowed_idp_cidrs') ? (
                          <Badge colorScheme='orange' variant='subtle' mt={1}>
                            Set via SSO_ALLOWED_IDP_CIDRS
                          </Badge>
                        ) : null}
                      </FormControl>
                      <Text fontSize='xs' color={muted}>
                        Ops-only (no UI): SSO_SECRETS_KEYRING*,
                        SSO_PROVIDERS_BOOTSTRAP_FILE, SSO_&lt;slug&gt;_*
                        secrets, SSO_RATE_LIMIT_*, SAML_CACHE_TTL_SEC.
                      </Text>
                    </VStack>
                  </Collapse>
                  <HStack justify='flex-end'>
                    <DashboardActionButton
                      colorScheme='blue'
                      isLoading={savingSso}
                      onClick={handleSaveSso}
                      w={{ base: '100%', md: 'auto' }}
                    >
                      Save SSO policy
                    </DashboardActionButton>
                  </HStack>
                </VStack>
              </Box>

              <Divider my={6} />

              <SsoGroupMappingsSection
                state={mappingsState}
                hint={wizardMappingHint}
              />
            </SettingsFormWidth>
          </SettingsIntegrationCard>

          <Box id='auto-sync'>
            <SettingsIntegrationCard
              title='Auto-sync'
              description='Override metric exposure and monitoring groups across integrations.'
              icon={<Icon as={FiRepeat} boxSize={6} color='blue.500' />}
              configured={autoSyncMetricsConfigured}
              isOpen={openIntegration === 'auto-sync'}
              onToggle={() =>
                setOpenIntegration(prev =>
                  prev === 'auto-sync' ? null : 'auto-sync'
                )
              }
            >
              <AutoSyncSystemMetricSettings
                onConfiguredChange={setAutoSyncMetricsConfigured}
              />
              {autoSyncMultiConfigEnabled === false ? (
                <AutoSyncMultiConfigPanel
                  onEnabledChange={setAutoSyncMultiConfigEnabled}
                />
              ) : null}
            </SettingsIntegrationCard>
          </Box>

          <SettingsIntegrationCard
            title='Email (SMTP)'
            description='Configure outgoing email delivery for alert notifications.'
            icon={<Icon as={FiMail} boxSize={6} color='blue.500' />}
            configured={smtp.configured}
            isOpen={openIntegration === 'smtp'}
            onToggle={() =>
              setOpenIntegration(prev => (prev === 'smtp' ? null : 'smtp'))
            }
          >
            <SettingsFormWidth maxW='100%'>
              <VStack align='stretch' spacing={3}>
                <Stack
                  direction={{ base: 'column', md: 'row' }}
                  spacing={4}
                  align='stretch'
                >
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
                </Stack>
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
                <Stack
                  direction={{ base: 'column', md: 'row' }}
                  spacing={4}
                  align='stretch'
                >
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
                </Stack>
                <Divider />
                <Stack
                  direction={{ base: 'column', md: 'row' }}
                  spacing={4}
                  align='stretch'
                >
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
                </Stack>
              </VStack>

              <HStack
                mt={4}
                spacing={3}
                justify='space-between'
                align='end'
                flexWrap='wrap'
                rowGap={3}
              >
                <HStack
                  spacing={3}
                  align='end'
                  flexWrap='wrap'
                  rowGap={2}
                  w={{ base: '100%', md: 'auto' }}
                >
                  <FormControl
                    w={{ base: '100%', md: '220px' }}
                    maxW={{ base: 'none', md: '220px' }}
                    isDisabled={!smtp.configured}
                  >
                    <FormLabel fontSize='sm' mb={1}>
                      Test recipient
                    </FormLabel>
                    <Input
                      size='sm'
                      placeholder={session?.email || 'recipient@example.com'}
                      value={smtpTestRecipient || testEmail}
                      aria-describedby={
                        smtpTestRecipient
                          ? 'smtp-test-recipient-guidance'
                          : undefined
                      }
                      isDisabled={!!smtpTestRecipient}
                      onChange={e => setTestEmail(e.target.value)}
                    />
                  </FormControl>
                  <DashboardActionButton
                    colorScheme='blue'
                    variant='outline'
                    isLoading={testingSmtp}
                    onClick={handleTestSmtp}
                    isDisabled={!smtp.configured}
                    w={{ base: '100%', md: 'auto' }}
                  >
                    Send test email
                  </DashboardActionButton>
                </HStack>
                <DashboardActionButton
                  colorScheme='blue'
                  isLoading={savingSmtp}
                  onClick={handleSaveSmtp}
                  w={{ base: '100%', md: 'auto' }}
                >
                  Save SMTP
                </DashboardActionButton>
              </HStack>
              {smtpTestRecipient && (
                <Text
                  id='smtp-test-recipient-guidance'
                  fontSize='xs'
                  mt={2}
                  color={muted}
                >
                  Recipient confirmation is enforced. This transport test goes
                  to the signed-in administrator.
                </Text>
              )}
            </SettingsFormWidth>
          </SettingsIntegrationCard>

          <SettingsIntegrationCard
            title='WhatsApp (Twilio)'
            description='Configure Twilio WhatsApp delivery and alert templates.'
            icon={<Icon as={FaWhatsapp} boxSize={6} color='#25D366' />}
            configured={whatsapp.configured}
            isOpen={openIntegration === 'whatsapp'}
            onToggle={() =>
              setOpenIntegration(prev =>
                prev === 'whatsapp' ? null : 'whatsapp'
              )
            }
          >
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

            <SettingsFormWidth maxW='100%'>
              <VStack align='stretch' spacing={3}>
                <Text fontWeight='semibold' fontSize='sm' color={muted}>
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
                <Stack
                  direction={{ base: 'column', md: 'row' }}
                  spacing={4}
                  align='stretch'
                >
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
                </Stack>

                <Divider />
                <Text fontWeight='semibold' fontSize='sm' color={muted}>
                  Content Templates
                </Text>
                <Stack
                  direction={{ base: 'column', md: 'row' }}
                  spacing={4}
                  align='stretch'
                >
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
                </Stack>
                <Stack
                  direction={{ base: 'column', md: 'row' }}
                  spacing={4}
                  align='stretch'
                >
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
                </Stack>
                <Stack
                  direction={{ base: 'column', md: 'row' }}
                  spacing={4}
                  align='stretch'
                >
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
                </Stack>
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
                  <TestWhatsappButton
                    onClick={handleTestWhatsapp}
                    isLoading={testingWhatsapp}
                    isDisabled={!whatsapp.configured || !testPhone.trim()}
                  />
                </HStack>
                <DashboardActionButton
                  colorScheme='blue'
                  isLoading={savingWhatsapp}
                  onClick={handleSaveWhatsapp}
                  w={{ base: '100%', md: 'auto' }}
                >
                  Save WhatsApp
                </DashboardActionButton>
              </HStack>
            </SettingsFormWidth>
          </SettingsIntegrationCard>
        </VStack>
      </DashboardPageLayout>
      <SsoGroupMappingModal state={mappingsState} />
    </>
  );
}
