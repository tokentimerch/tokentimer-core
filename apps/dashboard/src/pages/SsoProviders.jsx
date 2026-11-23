import { useCallback, useEffect, useState } from 'react';
import { useNavigate, useLocation } from 'react-router';
import {
  Box,
  Heading,
  Text,
  HStack,
  SimpleGrid,
  VStack,
} from '@chakra-ui/react';
import { FiPlus, FiRefreshCw, FiSettings } from 'react-icons/fi';
import apiClient from '../utils/apiClient';
import SsoAdminPageShell from '../components/SsoAdminPageShell.jsx';
import SsoProviderTestResults from '../components/SsoProviderTestResults.jsx';
import {
  DashboardActionButton,
  DashboardErrorAlert,
  DashboardPanel,
  DashboardState,
} from '../components/DashboardPrimitives';
import PrimaryButton from '../components/onboarding/PrimaryButton.jsx';
import {
  FactsList,
  StatusPanel,
  StatusTag,
} from '../components/onboarding/panels.jsx';
import { CopyBlock } from '../components/onboarding/blocks.jsx';
import { useDashboardTheme } from '../hooks/useDashboardTheme';
import { showSuccess, showWarning } from '../utils/toast.js';
import { SSO_RELOAD_REASON_LABELS } from '../lib/sso-ui-shared.js';

// Shown next to the status tags: who manages the provider's settings.
function managedLabel(provider) {
  const locked = Array.isArray(provider.locked_fields)
    ? provider.locked_fields.length
    : 0;
  if (locked === 0) return 'UI';
  return locked >= 3 ? 'Helm / Compose' : 'Partially managed';
}

function secretsText(provider) {
  const set = provider.secrets_set || [];
  if (set.length) return set.join(', ');
  return provider.type === 'saml' ? 'None required' : 'Missing required secret';
}

function ProviderCard({ provider: p, testing, testResult, onTest, onEdit }) {
  const { muted, border } = useDashboardTheme();
  const signInReady = p.runtime?.signInReady === true;
  const reasonLabel =
    SSO_RELOAD_REASON_LABELS[p.runtime?.lastReason] || p.runtime?.lastReason;
  const titleId = `sso-provider-${p.slug}-title`;

  return (
    <DashboardPanel
      as='article'
      aria-labelledby={titleId}
      data-testid={`sso-provider-${p.slug}`}
      p={5}
    >
      <VStack align='stretch' spacing={4}>
        <HStack justify='space-between' align='flex-start' spacing={3}>
          <Box minW={0}>
            <Heading as='h3' size='sm' id={titleId} overflowWrap='anywhere'>
              {p.displayName}
            </Heading>
            <Text
              fontSize='xs'
              color={muted}
              fontFamily='mono'
              mt={0.5}
              overflowWrap='anywhere'
            >
              {p.slug}
            </Text>
          </Box>
          <StatusTag tone='blue' textTransform='uppercase' flexShrink={0}>
            {p.type}
          </StatusTag>
        </HStack>

        <HStack flexWrap='wrap' spacing={0} gap={2}>
          <StatusTag tone={p.enabled ? 'green' : 'gray'}>
            {p.enabled ? 'Enabled' : 'Disabled'}
          </StatusTag>
          <StatusTag tone={signInReady ? 'green' : 'orange'}>
            {signInReady ? 'Sign-in ready' : 'Not ready'}
          </StatusTag>
          <StatusTag tone='gray' variant='outline'>
            {managedLabel(p)}
          </StatusTag>
        </HStack>

        {!signInReady && reasonLabel ? (
          <StatusPanel status='warning'>{reasonLabel}</StatusPanel>
        ) : null}

        <FactsList items={[{ label: 'Secrets', value: secretsText(p) }]} />

        {p.computed?.callback_url ? (
          <CopyBlock
            label='Callback URL'
            text={String(p.computed.callback_url)}
            onResult={ok =>
              ok
                ? showSuccess('Callback URL copied')
                : showWarning('Copy failed')
            }
          />
        ) : null}

        <HStack spacing={2} flexWrap='wrap'>
          <DashboardActionButton
            variant='outline'
            onClick={onTest}
            isLoading={testing}
            aria-describedby={titleId}
          >
            Test
          </DashboardActionButton>
          <DashboardActionButton
            colorScheme='blue'
            variant='outline'
            leftIcon={<FiSettings />}
            onClick={onEdit}
            aria-describedby={titleId}
          >
            Edit
          </DashboardActionButton>
        </HStack>

        {testResult ? (
          <Box pt={3} borderTop='1px solid' borderColor={border}>
            <Text fontSize='xs' fontWeight='semibold' color={muted} mb={2}>
              Last test results
            </Text>
            <SsoProviderTestResults result={testResult} />
          </Box>
        ) : null}
      </VStack>
    </DashboardPanel>
  );
}

export default function SsoProviders({ session, onLogout, onAccountClick }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [providers, setProviders] = useState([]);
  const [testPanel, setTestPanel] = useState(null);
  const [testingSlug, setTestingSlug] = useState(null);
  const load = useCallback(async () => {
    try {
      setLoading(true);
      setLoadError(null);
      const res = await apiClient.get('/api/admin/sso/providers', {
        params: { includeStatuses: true },
      });
      setProviders(
        Array.isArray(res.data?.providers) ? res.data.providers : res.data || []
      );
    } catch (e) {
      const message =
        e?.response?.data?.error || 'Failed to load SSO providers';
      showWarning(message);
      setLoadError(message);
      setProviders([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (location.state?.refreshProviders) {
      load();
      navigate(location.pathname, { replace: true, state: {} });
    }
  }, [location.state?.refreshProviders, load, navigate, location.pathname]);

  const [selectingSlug, setSelectingSlug] = useState(null);

  async function selectProvider(slug) {
    setSelectingSlug(slug);
    try {
      const { data } = await apiClient.put(`/api/admin/sso/providers/${slug}`, {
        enabled: true,
        selectForSignIn: true,
      });
      if (
        Array.isArray(data?.sso_reload_warnings) &&
        data.sso_reload_warnings.length
      ) {
        showWarning(
          data.sso_reload_warnings.map(warning => warning.message).join(' ')
        );
      } else {
        showSuccess('Sign-in provider selected');
      }
      await load();
    } catch (error) {
      showWarning(
        error?.response?.data?.error || 'Could not select sign-in provider'
      );
    } finally {
      setSelectingSlug(null);
    }
  }

  async function runTest(slug) {
    try {
      setTestingSlug(slug);
      const res = await apiClient.post(`/api/admin/sso/providers/${slug}/test`);
      setTestPanel({ slug, result: res.data });
      if (res.data?.ok) showSuccess(`${slug}: all checks passed`);
      else showWarning(res.data?.reason || `${slug}: test reported issues`);
      await load();
    } catch (e) {
      setTestPanel(null);
      showWarning(e?.response?.data?.error || 'Test failed');
    } finally {
      setTestingSlug(null);
    }
  }

  const enabledProviders = providers.filter(provider => provider.enabled);

  const headerActions = (
    <HStack spacing={2} flexWrap='wrap'>
      <DashboardActionButton
        leftIcon={<FiRefreshCw />}
        variant='outline'
        onClick={load}
        isLoading={loading}
      >
        Refresh
      </DashboardActionButton>
      <PrimaryButton
        leftIcon={<FiPlus />}
        onClick={() => navigate('/sso-providers/new')}
      >
        Add provider
      </PrimaryButton>
    </HStack>
  );

  return (
    <SsoAdminPageShell
      seoTitle='SSO Providers'
      title='SSO Providers'
      subtitle='Core supports one active SSO provider, either OIDC or SAML.'
      variant='wide'
      actions={headerActions}
      session={session}
      onLogout={onLogout}
      onAccountClick={onAccountClick}
    >
      {enabledProviders.length > 1 ? (
        <StatusPanel status='warning'>
          <VStack align='start'>
            <Text>
              Multiple SSO providers are enabled. Sign-in is paused. Select one
              provider to keep enabled for this installation.
            </Text>
            {enabledProviders.map(provider => (
              <DashboardActionButton
                key={provider.slug}
                isLoading={selectingSlug === provider.slug}
                isDisabled={!!selectingSlug}
                onClick={() => selectProvider(provider.slug)}
              >
                Select {provider.displayName || provider.slug}
              </DashboardActionButton>
            ))}
          </VStack>
        </StatusPanel>
      ) : null}
      {loading && providers.length === 0 ? (
        <DashboardPanel role='status' aria-busy='true'>
          <DashboardState type='loading' title='Loading providers...' />
        </DashboardPanel>
      ) : loadError ? (
        <DashboardErrorAlert>{loadError}</DashboardErrorAlert>
      ) : providers.length === 0 ? (
        <DashboardPanel borderStyle='dashed'>
          <VStack align='stretch' spacing={4} maxW='640px' mx='auto' py={4}>
            <StatusPanel status='info' title='No SSO providers yet'>
              Add Azure AD, Keycloak, Okta, or a generic OIDC / SAML IdP with
              the setup wizard.
            </StatusPanel>
            <Box textAlign='center'>
              <PrimaryButton
                leftIcon={<FiPlus />}
                onClick={() => navigate('/sso-providers/new')}
              >
                Add your first provider
              </PrimaryButton>
            </Box>
          </VStack>
        </DashboardPanel>
      ) : (
        <SimpleGrid columns={{ base: 1, xl: 2 }} spacing={4}>
          {providers.map(p => (
            <ProviderCard
              key={p.slug}
              provider={p}
              testing={testingSlug === p.slug}
              testResult={testPanel?.slug === p.slug ? testPanel.result : null}
              onTest={() => runTest(p.slug)}
              onEdit={() => navigate(`/sso-providers/${p.slug}`)}
            />
          ))}
        </SimpleGrid>
      )}
    </SsoAdminPageShell>
  );
}
