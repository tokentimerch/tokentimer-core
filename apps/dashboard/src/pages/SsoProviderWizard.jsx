import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router';
import {
  Box,
  Flex,
  FormControl,
  FormHelperText,
  FormLabel,
  Input,
  Select,
  Text,
  VStack,
  HStack,
  Checkbox,
  Code,
  Textarea,
} from '@chakra-ui/react';
import SsoAdminPageShell from '../components/SsoAdminPageShell.jsx';
import {
  DashboardActionButton,
  DashboardPanel,
} from '../components/DashboardPrimitives';
import StepFrame from '../components/onboarding/StepFrame.jsx';
import PrimaryButton from '../components/onboarding/PrimaryButton.jsx';
import {
  Callout,
  DetailsSection,
  FactsList,
  StatusPanel,
  StatusTag,
  StepCard,
} from '../components/onboarding/panels.jsx';
import { ContinueHint, CopyBlock } from '../components/onboarding/blocks.jsx';
import {
  CollapsibleSteps,
  JourneyRail,
} from '../components/onboarding/OnboardingPage.jsx';
import apiClient, { API_BASE_URL } from '../utils/apiClient';
import { showSuccess, showWarning } from '../utils/toast.js';
import {
  OIDC_WIZARD_TEMPLATES,
  SAML_WIZARD_TEMPLATES,
  defaultOidcClaimMapping,
  defaultSamlClaimMapping,
} from '../lib/sso-oidc-ui-helpers.js';
import { resolveSamlMetadataInput } from '../lib/saml-metadata-parser.js';
import {
  computedCallbackUrl,
  computedMetadataUrl,
  defaultSamlSpEntityId,
  slugFromDisplayName,
  resolvePublicApiBase,
  validateWizardConfigureStep,
  SSO_RELOAD_REASON_LABELS,
} from '../lib/sso-ui-shared.js';
import SsoWizardTestResults from '../components/SsoWizardTestResults.jsx';
import { useDashboardTheme } from '../hooks/useDashboardTheme';

const STEPS = ['type', 'template', 'configure', 'urls', 'test', 'enable'];
const STEP_LABELS = {
  type: 'Protocol',
  template: 'Template',
  configure: 'Provider details',
  urls: 'IdP registration',
  test: 'Verification',
  enable: 'Enable sign-in',
};

// Back and the main action of a step, in the order the old wizard had them.
function navActions({
  onBack,
  onNext,
  nextLabel = 'Continue',
  nextProps = {},
}) {
  return (
    <>
      {onBack ? (
        <DashboardActionButton variant='ghost' onClick={onBack}>
          Back
        </DashboardActionButton>
      ) : null}
      <PrimaryButton onClick={onNext} {...nextProps}>
        {nextLabel}
      </PrimaryButton>
    </>
  );
}

// The setup guide embeds the wizard without the page chrome and is told when
// the provider is enabled instead of being navigated away.
function EmbeddedShell({ children }) {
  return <>{children}</>;
}

export default function SsoProviderWizard({
  session,
  onLogout,
  onAccountClick,
  embedded = false,
  onEnabled,
}) {
  const navigate = useNavigate();
  const { muted } = useDashboardTheme();
  const [step, setStep] = useState(0);
  const [type, setType] = useState('oidc');
  const [templateId, setTemplateId] = useState('generic');
  const [slug, setSlug] = useState('');
  const [slugTouched, setSlugTouched] = useState(false);
  const [displayName, setDisplayName] = useState('');
  const [issuer, setIssuer] = useState('');
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [metadataUrl, setMetadataUrl] = useState('');
  const [metadataXml, setMetadataXml] = useState('');
  const [parsedSaml, setParsedSaml] = useState(null);
  const [testResult, setTestResult] = useState(null);
  const [providerPersisted, setProviderPersisted] = useState(false);
  const [forceEnable, setForceEnable] = useState(false);
  const stepRef = useRef(null);
  const firstRender = useRef(true);
  const [saving, setSaving] = useState(false);
  const [parsingMetadata, setParsingMetadata] = useState(false);
  const apiBase = useMemo(() => resolvePublicApiBase(API_BASE_URL), []);
  const effectiveSlug = slug || slugFromDisplayName(displayName) || 'provider';

  const callbackUrl = computedCallbackUrl(apiBase, type, effectiveSlug);
  const metadataSpUrl =
    type === 'saml' ? computedMetadataUrl(apiBase, effectiveSlug) : null;
  const samlSpEntityId =
    type === 'saml' ? defaultSamlSpEntityId(apiBase) : null;

  const onCopyResult = label => ok => {
    if (ok) showSuccess(`${label} copied`);
    else showWarning('Copy failed');
  };

  // Move focus to the new step so keyboard and screen reader users land on it.
  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    stepRef.current?.focus();
  }, [step]);

  function showReloadWarnings(payload) {
    const warnings = payload?.sso_reload_warnings;
    if (!Array.isArray(warnings) || warnings.length === 0) return;
    const text = warnings
      .map(w => SSO_RELOAD_REASON_LABELS[w.code] || w.message || w.code)
      .join(' ');
    showWarning(text);
  }

  async function fetchMetadataViaApi(url) {
    const res = await apiClient.post('/api/admin/sso/fetch-idp-metadata', {
      url,
    });
    return res.data?.xml;
  }

  function resolveSamlMetadata() {
    return resolveSamlMetadataInput({
      metadataUrl,
      metadataXml,
      fetchMetadataUrl: fetchMetadataViaApi,
    });
  }

  async function parseMetadata() {
    setParsingMetadata(true);
    try {
      const res = await resolveSamlMetadata();
      if (!res.ok) {
        showWarning(res.error);
        return;
      }
      setParsedSaml(res);
      showSuccess(
        metadataXml.trim() ? 'Metadata parsed' : 'Metadata parsed from URL'
      );
    } catch (e) {
      showWarning(
        e.response?.data?.error || e.message || 'Failed to fetch metadata'
      );
    } finally {
      setParsingMetadata(false);
    }
  }

  function buildProviderBody() {
    return {
      slug: effectiveSlug,
      type,
      displayName: displayName || effectiveSlug,
      enabled: false,
      config:
        type === 'oidc'
          ? {
              issuer: issuer.trim(),
              client_id: clientId.trim(),
              scopes: 'openid profile email',
            }
          : {
              entry_point: parsedSaml?.entryPoint || '',
              issuer: samlSpEntityId || defaultSamlSpEntityId(apiBase),
              cert: parsedSaml?.cert || '',
              secondary_cert: parsedSaml?.secondaryCert || '',
            },
      claim_mapping:
        type === 'oidc'
          ? defaultOidcClaimMapping(templateId)
          : defaultSamlClaimMapping(templateId),
      secrets:
        type === 'oidc' && clientSecret ? { client_secret: clientSecret } : {},
    };
  }

  async function continueFromConfigure() {
    let saml = parsedSaml;
    if (type === 'saml') {
      setParsingMetadata(true);
      try {
        const res = await resolveSamlMetadata();
        if (!res.ok) {
          showWarning(res.error);
          return;
        }
        saml = res;
        setParsedSaml(res);
      } catch (e) {
        showWarning(
          e.response?.data?.error || e.message || 'Failed to fetch metadata'
        );
        return;
      } finally {
        setParsingMetadata(false);
      }
    }
    const errors = validateWizardConfigureStep({
      type,
      displayName,
      effectiveSlug,
      issuer,
      clientId,
      clientSecret,
      parsedSaml: saml,
    });
    if (errors.length > 0) {
      showWarning(errors[0]);
      return;
    }
    setStep(3);
  }

  async function persistProvider() {
    const body = buildProviderBody();
    if (providerPersisted) {
      const res = await apiClient.put(
        `/api/admin/sso/providers/${effectiveSlug}`,
        {
          displayName: body.displayName,
          config: body.config,
          claim_mapping: body.claim_mapping,
          secrets: body.secrets,
        }
      );
      return res.data;
    }
    const res = await apiClient.post('/api/admin/sso/providers', body);
    setProviderPersisted(true);
    return res.data;
  }

  async function saveAndTest() {
    const configErrors = validateWizardConfigureStep({
      type,
      displayName,
      effectiveSlug,
      issuer,
      clientId,
      clientSecret,
      parsedSaml,
    });
    if (configErrors.length > 0) {
      showWarning(configErrors[0]);
      setStep(2);
      return;
    }
    try {
      setSaving(true);
      const saved = await persistProvider();
      showReloadWarnings(saved);
      const warnings = saved?.warnings;
      if (Array.isArray(warnings) && warnings.length > 0) {
        showWarning(warnings.map(w => w.message).join(' '));
      }
      const test = await apiClient.post(
        `/api/admin/sso/providers/${effectiveSlug}/test`
      );
      setTestResult(test.data);
      if (test.data?.ok) {
        showSuccess(
          warnings?.length
            ? 'Provider saved (secrets not stored; see warning). Connectivity test passed.'
            : 'Provider saved and test passed'
        );
        setStep(5);
      } else {
        showWarning(test.data?.reason || 'Test completed with issues');
      }
    } catch (e) {
      showWarning(
        e?.response?.data?.error || e?.message || 'Save or test failed'
      );
    } finally {
      setSaving(false);
    }
  }

  async function enableProvider() {
    if (!testResult?.ok && !forceEnable) {
      showWarning('Run a successful test first or enable the override');
      return;
    }
    try {
      setSaving(true);
      if (!providerPersisted) {
        const saved = await persistProvider();
        showReloadWarnings(saved);
      }
      const res = await apiClient.put(
        `/api/admin/sso/providers/${effectiveSlug}`,
        {
          enabled: true,
        }
      );
      showReloadWarnings(res.data);
      showSuccess('Provider enabled');
      if (embedded) {
        onEnabled?.(effectiveSlug);
      } else {
        navigate('/sso-providers', {
          replace: true,
          state: { refreshProviders: true },
        });
      }
    } catch (e) {
      showWarning(e?.response?.data?.error || 'Enable failed');
    } finally {
      setSaving(false);
    }
  }

  const templates =
    type === 'oidc' ? OIDC_WIZARD_TEMPLATES : SAML_WIZARD_TEMPLATES;

  const railSteps = STEPS.map((id, i) => ({
    id,
    title: STEP_LABELS[id],
    status: i < step ? 'done' : i === step ? 'current' : 'upcoming',
  }));
  const stepId = STEPS[step];
  const stepLabel = `Step ${step + 1} of ${STEPS.length}: ${STEP_LABELS[stepId]}`;

  const checksPassed = !!testResult?.ok;
  const enableBlocked = !checksPassed && !forceEnable;

  const Shell = embedded ? EmbeddedShell : SsoAdminPageShell;

  return (
    <Shell
      seoTitle='Add SSO Provider'
      title='Add SSO provider'
      subtitle='Step-by-step setup for a new OIDC or SAML identity provider.'
      session={session}
      onLogout={onLogout}
      onAccountClick={onAccountClick}
    >
      {
        <Flex
          direction={{ base: 'column', lg: 'row' }}
          gap={4}
          align='flex-start'
        >
          {/* The setup guide already shows its own progress rail. */}
          {embedded ? null : (
            <DashboardPanel
              as='aside'
              aria-label='Setup progress'
              w={{ base: 'full', lg: '300px' }}
              flexShrink={0}
            >
              <HStack
                justify='space-between'
                mb={3}
                display={{ base: 'none', lg: 'flex' }}
              >
                <Text fontWeight='bold' fontSize='sm'>
                  Your setup
                </Text>
                <StatusTag tone='blue'>{type.toUpperCase()}</StatusTag>
              </HStack>
              <CollapsibleSteps steps={railSteps} shownId={stepId}>
                {close => (
                  <JourneyRail
                    steps={railSteps}
                    shownId={stepId}
                    onSelect={id => {
                      close();
                      const target = STEPS.indexOf(id);
                      if (target >= 0 && target < step) setStep(target);
                      else stepRef.current?.focus();
                    }}
                  />
                )}
              </CollapsibleSteps>
            </DashboardPanel>
          )}

          <Box
            ref={stepRef}
            tabIndex={-1}
            flex='1'
            minW={0}
            w='full'
            outline='none'
            aria-busy={saving || parsingMetadata}
          >
            <Text
              fontSize='sm'
              fontWeight='medium'
              color={muted}
              mb={2}
              display={{ base: 'none', lg: 'block' }}
            >
              {stepLabel}
            </Text>

            {step === 0 && (
              <StepFrame
                kind='ui'
                title='Choose protocol'
                description='Select how users will authenticate with your identity provider.'
                actions={navActions({ onNext: () => setStep(1) })}
              >
                <FormControl>
                  <FormLabel>Protocol</FormLabel>
                  <Select
                    value={type}
                    onChange={e => setType(e.target.value)}
                    size='md'
                  >
                    <option value='oidc'>OpenID Connect (OIDC)</option>
                    <option value='saml'>SAML 2.0</option>
                  </Select>
                  <FormHelperText>
                    OIDC is typical for Azure AD, Okta, and Google. SAML suits
                    legacy enterprise IdPs.
                  </FormHelperText>
                </FormControl>
              </StepFrame>
            )}

            {step === 1 && (
              <StepFrame
                kind='ui'
                title='IdP template'
                description='Templates pre-fill claim mappings and endpoint hints for common providers.'
                actions={navActions({
                  onBack: () => setStep(0),
                  onNext: () => setStep(2),
                })}
              >
                <FormControl>
                  <FormLabel>Template</FormLabel>
                  <Select
                    value={templateId}
                    onChange={e => setTemplateId(e.target.value)}
                    size='md'
                  >
                    {templates.map(t => (
                      <option key={t.id} value={t.id}>
                        {t.name}
                      </option>
                    ))}
                  </Select>
                </FormControl>
              </StepFrame>
            )}

            {step === 2 && (
              <StepFrame
                kind='ui'
                title='Provider details'
                description='Basic identity and credentials from your IdP admin console.'
                actions={navActions({
                  onBack: () => setStep(1),
                  onNext: continueFromConfigure,
                  nextProps: {
                    isLoading: parsingMetadata,
                    isDisabled: parsingMetadata,
                  },
                })}
              >
                <VStack align='stretch' spacing={4}>
                  <FormControl isRequired>
                    <FormLabel>Display name</FormLabel>
                    <Input
                      placeholder='e.g. Azure AD Production'
                      value={displayName}
                      onChange={e => {
                        const value = e.target.value;
                        setDisplayName(value);
                        if (!slugTouched) setSlug(slugFromDisplayName(value));
                      }}
                    />
                  </FormControl>
                  <FormControl isRequired>
                    <FormLabel>Slug</FormLabel>
                    <Input
                      fontFamily='mono'
                      placeholder='entra-prod'
                      value={slug}
                      onChange={e => {
                        setSlugTouched(true);
                        setSlug(e.target.value.toLowerCase());
                      }}
                    />
                    <FormHelperText>
                      Used in URLs and env vars. Cannot be changed after
                      creation.
                    </FormHelperText>
                  </FormControl>

                  {type === 'oidc' ? (
                    <>
                      <FormControl isRequired>
                        <FormLabel>Issuer URL</FormLabel>
                        <Input
                          placeholder='https://login.microsoftonline.com/{tenant}/v2.0'
                          value={issuer}
                          onChange={e => setIssuer(e.target.value)}
                        />
                      </FormControl>
                      <FormControl isRequired>
                        <FormLabel>Client ID</FormLabel>
                        <Input
                          value={clientId}
                          onChange={e => setClientId(e.target.value)}
                        />
                      </FormControl>
                      <FormControl isRequired>
                        <FormLabel>Client secret</FormLabel>
                        <Input
                          type='password'
                          value={clientSecret}
                          onChange={e => setClientSecret(e.target.value)}
                        />
                        <FormHelperText>
                          Required for OIDC sign-in. Stored encrypted when the
                          SSO secrets keyring is configured.
                        </FormHelperText>
                      </FormControl>
                    </>
                  ) : (
                    <>
                      <FormControl>
                        <FormLabel>Metadata URL</FormLabel>
                        <Input
                          placeholder='https://idp.example.com/metadata'
                          value={metadataUrl}
                          onChange={e => {
                            setMetadataUrl(e.target.value);
                            setParsedSaml(null);
                          }}
                        />
                      </FormControl>
                      <FormControl>
                        <FormLabel>Or paste metadata XML</FormLabel>
                        <Textarea
                          rows={6}
                          fontFamily='mono'
                          fontSize='xs'
                          placeholder='Paste IdP metadata XML here…'
                          value={metadataXml}
                          onChange={e => {
                            setMetadataXml(e.target.value);
                            setParsedSaml(null);
                          }}
                        />
                        <FormHelperText>
                          Pasted XML takes precedence over the URL. Metadata is
                          parsed automatically when you continue.
                        </FormHelperText>
                      </FormControl>
                      <Box>
                        <DashboardActionButton
                          variant='outline'
                          onClick={parseMetadata}
                          isLoading={parsingMetadata}
                        >
                          Parse metadata
                        </DashboardActionButton>
                      </Box>
                      {parsedSaml?.ok !== false && parsedSaml && (
                        <VStack align='stretch' spacing={2}>
                          <StatusPanel
                            status='success'
                            title='Metadata parsed'
                            testId='sso-saml-parsed'
                          />
                          <FactsList
                            items={[
                              {
                                label: 'Entry point',
                                value: parsedSaml.entryPoint,
                                mono: true,
                              },
                              {
                                label: 'AuthnRequest binding',
                                value: parsedSaml.authnRequestBinding,
                              },
                            ]}
                          />
                        </VStack>
                      )}
                    </>
                  )}

                  <DetailsSection summary='Advanced options'>
                    <Text fontSize='sm' color={muted}>
                      Endpoint overrides, claim mapping, and security toggles
                      are available on the edit page after the provider is
                      created.
                    </Text>
                  </DetailsSection>
                </VStack>
              </StepFrame>
            )}

            {step === 3 && (
              <StepFrame
                kind='handoff'
                kindLabel='Done in your identity provider'
                title='Register URLs in your IdP'
                description='Copy these into your identity provider before running the connectivity test.'
                actions={navActions({
                  onBack: () => setStep(2),
                  onNext: () => setStep(4),
                })}
              >
                <VStack align='stretch' spacing={3}>
                  {samlSpEntityId ? (
                    <StepCard n={1} title='SP Entity ID'>
                      <CopyBlock
                        label='SP Entity ID (Entra: Identifier)'
                        text={samlSpEntityId}
                        onResult={onCopyResult(
                          'SP Entity ID (Entra: Identifier)'
                        )}
                      />
                      <Text fontSize='sm' color={muted}>
                        In Microsoft Entra, open your enterprise app → Single
                        sign-on → Basic SAML Configuration → set{' '}
                        <strong>Identifier (Entity ID)</strong> to this value
                        exactly. Do not use the IdP issuer from metadata (
                        <Code fontSize='xs'>sts.windows.net/...</Code>).
                      </Text>
                    </StepCard>
                  ) : null}
                  <StepCard
                    n={samlSpEntityId ? 2 : 1}
                    title={type === 'saml' ? 'ACS / Reply URL' : 'Callback URL'}
                  >
                    <CopyBlock
                      label={
                        type === 'saml'
                          ? 'ACS / Reply URL (Entra: Reply URL)'
                          : 'Callback URL'
                      }
                      text={callbackUrl}
                      onResult={onCopyResult(
                        type === 'saml'
                          ? 'ACS / Reply URL (Entra: Reply URL)'
                          : 'Callback URL'
                      )}
                    />
                  </StepCard>
                  {metadataSpUrl ? (
                    <DetailsSection
                      summary='SP metadata URL (optional)'
                      defaultOpen
                    >
                      <CopyBlock
                        label='SP metadata URL (optional)'
                        text={metadataSpUrl}
                        onResult={onCopyResult('SP metadata URL (optional)')}
                      />
                      <Text fontSize='sm' color={muted}>
                        Entra has no field for this URL. Use Identifier + Reply
                        URL above. Other IdPs may let you import federation
                        metadata from this URL or download the XML for upload.
                      </Text>
                    </DetailsSection>
                  ) : null}
                </VStack>
              </StepFrame>
            )}

            {step === 4 && (
              <StepFrame
                kind='verify'
                title='Verification'
                description={
                  testResult
                    ? 'Review connectivity checks. Fix configuration and retry, or continue if you accept the risk.'
                    : 'The provider is saved when you run the test. You can edit settings and retry without leaving the wizard.'
                }
                actions={
                  <>
                    <DashboardActionButton
                      variant='ghost'
                      onClick={() => setStep(3)}
                    >
                      Back
                    </DashboardActionButton>
                    {providerPersisted ? (
                      <DashboardActionButton
                        variant='outline'
                        onClick={() => setStep(2)}
                      >
                        Edit configuration
                      </DashboardActionButton>
                    ) : null}
                    {testResult ? (
                      <DashboardActionButton
                        colorScheme='blue'
                        variant='outline'
                        onClick={saveAndTest}
                        isLoading={saving}
                      >
                        Retry save and test
                      </DashboardActionButton>
                    ) : (
                      <PrimaryButton onClick={saveAndTest} isLoading={saving}>
                        Save and run test
                      </PrimaryButton>
                    )}
                    {testResult ? (
                      <PrimaryButton
                        onClick={() => {
                          if (!testResult.ok) {
                            showWarning(
                              'Some checks failed. You can continue setup, but fix issues before enabling sign-in.'
                            );
                          }
                          setStep(5);
                        }}
                      >
                        Continue
                      </PrimaryButton>
                    ) : null}
                  </>
                }
              >
                {!testResult ? (
                  <Callout kind='next'>
                    This saves the provider (disabled) and runs automated checks
                    against your IdP settings.
                  </Callout>
                ) : (
                  <SsoWizardTestResults result={testResult} />
                )}
              </StepFrame>
            )}

            {step === 5 && (
              <StepFrame
                kind='ui'
                title='Enable sign-in'
                actions={
                  <>
                    <DashboardActionButton
                      variant='ghost'
                      onClick={() => setStep(4)}
                    >
                      Back
                    </DashboardActionButton>
                    <PrimaryButton
                      isDisabled={enableBlocked}
                      isLoading={saving}
                      onClick={enableProvider}
                    >
                      Enable provider
                    </PrimaryButton>
                  </>
                }
                actionHint={
                  enableBlocked ? (
                    <ContinueHint>
                      run a successful test or tick the override above.
                    </ContinueHint>
                  ) : null
                }
              >
                <VStack align='stretch' spacing={3}>
                  <Callout kind='next'>
                    {embedded ? (
                      'The next step maps IdP groups to roles. Without mappings, SSO users join the shared Default workspace on first login.'
                    ) : (
                      <>
                        Enabling sign-in returns you to the provider list. New
                        SSO users join the shared Default workspace on first
                        login.
                      </>
                    )}
                  </Callout>
                  <StatusPanel status={checksPassed ? 'success' : 'warning'}>
                    {checksPassed
                      ? 'All checks passed. You can enable sign-in for this provider.'
                      : 'Some checks failed. Enable only if you understand the risk.'}
                  </StatusPanel>
                  {!checksPassed && (
                    <Checkbox
                      isChecked={forceEnable}
                      onChange={e => setForceEnable(e.target.checked)}
                    >
                      Enable anyway (override failed checks)
                    </Checkbox>
                  )}
                </VStack>
              </StepFrame>
            )}
          </Box>
        </Flex>
      }
    </Shell>
  );
}
