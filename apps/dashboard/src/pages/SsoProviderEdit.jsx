import { useCallback, useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router';
import {
  Box,
  Button,
  FormControl,
  FormHelperText,
  FormLabel,
  Input,
  Text,
  VStack,
  HStack,
  Collapse,
  Switch,
  Divider,
  Textarea,
  Modal,
  ModalOverlay,
  ModalHeader,
  ModalBody,
  ModalFooter,
  ModalCloseButton,
  useDisclosure,
  Select,
} from '@chakra-ui/react';
import { FiChevronDown, FiChevronUp, FiTrash2 } from 'react-icons/fi';
import SsoAdminPageShell from '../components/SsoAdminPageShell.jsx';
import SsoFormCard from '../components/SsoFormCard.jsx';
import SsoProviderTestResults from '../components/SsoProviderTestResults.jsx';
import {
  DashboardActionButton,
  DashboardPanel,
  DashboardState,
} from '../components/DashboardPrimitives';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../components/DashboardModalFrame.jsx';
import PrimaryButton from '../components/onboarding/PrimaryButton.jsx';
import { StatusPanel, StatusTag } from '../components/onboarding/panels.jsx';
import { WarnText, CopyBlock } from '../components/onboarding/blocks.jsx';
import { useDashboardTheme } from '../hooks/useDashboardTheme';
import apiClient from '../utils/apiClient';
import { showSuccess, showWarning } from '../utils/toast.js';
import {
  applyProviderEndpointTemplates,
  matchIssuerProviderHint,
  OVERRIDE_FIELD_HELP,
} from '../lib/sso-oidc-ui-helpers.js';
import { isFieldLocked, lockedFieldHint } from '../lib/sso-ui-shared.js';
import SsoGroupMappingSimulator from '../components/SsoGroupMappingSimulator.jsx';
import SsoClaimInspector from '../components/SsoClaimInspector.jsx';

function UrlCopyRow({ label, value, onCopy }) {
  if (!value) return null;
  return (
    <CopyBlock
      label={label}
      text={String(value)}
      onResult={ok => onCopy(ok, label)}
    />
  );
}

function LockedHint({ text }) {
  if (!text) return null;
  return <WarnText mt={1}>{text}</WarnText>;
}

function SecuritySwitch({ label, help, checked, onChange }) {
  return (
    <FormControl
      display='flex'
      alignItems='center'
      justifyContent='space-between'
    >
      <Box flex={1} pr={4}>
        <FormLabel mb={0}>{label}</FormLabel>
        {help ? (
          <FormHelperText mt={0} fontSize='xs'>
            {help}
          </FormHelperText>
        ) : null}
      </Box>
      <Switch isChecked={!!checked} onChange={onChange} />
    </FormControl>
  );
}

function setSecurityField(setForm, key, value) {
  setForm(f => ({
    ...f,
    security: { ...f.security, [key]: value },
  }));
}

function policyOverrideValue(security, key) {
  const raw = security?.[key];
  if (raw === true) return 'true';
  if (raw === false) return 'false';
  return 'inherit';
}

function setPolicyOverride(setForm, key, choice) {
  setForm(f => {
    const next = { ...(f.security || {}) };
    if (choice === 'inherit') {
      delete next[key];
    } else {
      next[key] = choice === 'true';
    }
    return { ...f, security: next };
  });
}

export default function SsoProviderEdit({ session, onLogout, onAccountClick }) {
  const { slug } = useParams();
  const navigate = useNavigate();
  const { muted, border } = useDashboardTheme();
  const [provider, setProvider] = useState(null);
  const [form, setForm] = useState({});
  const [secretDraft, setSecretDraft] = useState('');
  const [signingKeyDraft, setSigningKeyDraft] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [impact, setImpact] = useState(null);
  const [pendingAction, setPendingAction] = useState(null);
  const [identityPolicy, setIdentityPolicy] = useState('');
  const [membershipPolicy, setMembershipPolicy] = useState('');
  const dependencyCounts = impact?.dependency_counts;
  const hasDependencies = Object.values(dependencyCounts || {}).some(
    count => count > 0
  );
  const needsIdentityPolicy = dependencyCounts?.identities_count > 0;
  const needsMembershipPolicy = dependencyCounts?.memberships_count > 0;
  const needsLocalRecovery =
    impact?.requires_local_admin && !impact?.has_usable_local_admin;
  const isDeleting = pendingAction === 'delete';
  const { isOpen, onOpen, onClose } = useDisclosure();
  const modalProps = useDashboardModalProps();

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const res = await apiClient.get(`/api/admin/sso/providers/${slug}`);
      const p = res.data;
      setProvider(p);
      setForm({
        displayName: p.displayName,
        enabled: p.enabled,
        config: { ...(p.config || {}) },
        claim_mapping: { ...(p.claim_mapping || {}) },
        security: { ...(p.security || {}) },
      });
    } catch (e) {
      showWarning(e?.response?.data?.error || 'Failed to load provider');
    } finally {
      setLoading(false);
    }
  }, [slug]);

  useEffect(() => {
    load();
  }, [load]);

  function lockHelp(path) {
    return lockedFieldHint(provider, path);
  }

  function notifyCopy(ok, label) {
    if (ok) showSuccess(`${label} copied`);
    else showWarning('Copy failed');
  }

  async function runTest() {
    try {
      const res = await apiClient.post(`/api/admin/sso/providers/${slug}/test`);
      setTestResult(res.data);
      if (res.data?.ok) showSuccess('All checks passed');
      else showWarning(res.data?.reason || 'Test reported issues');
    } catch (e) {
      showWarning(e?.response?.data?.error || 'Test failed');
    }
  }

  async function save(patch = {}) {
    const body = {
      displayName: form.displayName,
      ...(form.enabled !== provider.enabled ? { enabled: form.enabled } : {}),
      config: form.config,
      claim_mapping: form.claim_mapping,
      security: form.security,
      ...patch,
    };
    if (secretDraft) {
      body.secrets =
        provider.type === 'oidc'
          ? { client_secret: secretDraft }
          : { decryption_key: secretDraft };
    }
    if (signingKeyDraft) {
      body.secrets = { ...(body.secrets || {}), signing_key: signingKeyDraft };
    }
    try {
      setSaving(true);
      const res = await apiClient.put(`/api/admin/sso/providers/${slug}`, body);
      setProvider(res.data);
      setForm(f => ({
        ...f,
        displayName: res.data.displayName,
        enabled: res.data.enabled,
      }));
      setSecretDraft('');
      setSigningKeyDraft('');
      showSuccess('Provider saved');
      return res.data;
    } catch (e) {
      showWarning(e?.response?.data?.error || 'Save failed');
      return null;
    } finally {
      setSaving(false);
    }
  }

  function closeImpactModal(revertDisable = false) {
    if (revertDisable && pendingAction === 'disable') {
      setForm(f => ({ ...f, enabled: true }));
    }
    setPendingAction(null);
    setImpact(null);
    setIdentityPolicy('');
    setMembershipPolicy('');
    onClose();
  }

  async function confirmImpact() {
    if (!isDeleting) {
      closeImpactModal(false);
      const saved = await save({ enabled: false });
      if (!saved) setForm(f => ({ ...f, enabled: true }));
      return;
    }

    try {
      setSaving(true);
      const options = hasDependencies
        ? {
            params: {
              confirmRetirement: true,
              ...(needsIdentityPolicy ? { identityPolicy } : {}),
              ...(needsMembershipPolicy ? { membershipPolicy } : {}),
            },
          }
        : undefined;
      await apiClient.delete(`/api/admin/sso/providers/${slug}`, options);
      navigate('/sso-providers');
    } catch (e) {
      const code = e?.response?.data?.code;
      showWarning(
        code === 'last_login_method'
          ? 'Keep a working administrator sign-in method before deleting this provider.'
          : e?.response?.data?.error || 'Delete failed'
      );
    } finally {
      setSaving(false);
    }
  }

  async function previewImpact(change) {
    try {
      setPendingAction(
        change.delete ? 'delete' : change.enabled === false ? 'disable' : null
      );
      const res = await apiClient.post(
        `/api/admin/sso/providers/${slug}/impact`,
        change
      );
      setImpact(res.data);
      onOpen();
    } catch (e) {
      setPendingAction(null);
      showWarning(e?.response?.data?.error || 'Impact preview failed');
    }
  }

  function applySuggestedEndpoints() {
    const hint = matchIssuerProviderHint(form.config?.issuer);
    if (!hint) {
      showWarning('No template matched this issuer');
      return;
    }
    const templates = applyProviderEndpointTemplates(hint, form.config.issuer);
    if (!templates) {
      showWarning('This IdP uses discovery; leave overrides empty');
      return;
    }
    setForm(prev => ({
      ...prev,
      config: { ...prev.config, ...templates },
    }));
    showSuccess('Suggested endpoints applied (review before save)');
  }

  const shellProps = {
    session,
    onLogout,
    onAccountClick,
  };

  if (loading || !provider) {
    return (
      <SsoAdminPageShell
        seoTitle='Edit SSO Provider'
        title='Edit provider'
        subtitle='Loading…'
        {...shellProps}
      >
        <DashboardPanel>
          <DashboardState type='loading' title='Loading provider…' />
        </DashboardPanel>
      </SsoAdminPageShell>
    );
  }

  const callbackUrl = provider.computed?.callback_url;
  const metadataUrl = provider.computed?.metadata_url;

  return (
    <SsoAdminPageShell
      seoTitle={`Edit ${provider.displayName}`}
      title={provider.displayName}
      subtitle={`${provider.slug} · ${provider.type.toUpperCase()}`}
      {...shellProps}
    >
      <VStack align='stretch' spacing={5}>
        <HStack spacing={2} flexWrap='wrap' data-testid='sso-edit-status'>
          <StatusTag tone='blue'>{provider.type.toUpperCase()}</StatusTag>
          <StatusTag tone={provider.enabled ? 'green' : 'gray'}>
            {provider.enabled ? 'Enabled' : 'Disabled'}
          </StatusTag>
        </HStack>

        {callbackUrl || metadataUrl ? (
          <SsoFormCard title='Registration URLs'>
            <VStack align='stretch' spacing={3}>
              <UrlCopyRow
                label='Callback URL'
                value={callbackUrl}
                onCopy={notifyCopy}
              />
              <UrlCopyRow
                label='SP metadata URL'
                value={metadataUrl}
                onCopy={notifyCopy}
              />
            </VStack>
          </SsoFormCard>
        ) : null}

        <SsoFormCard title='General'>
          <VStack align='stretch' spacing={4}>
            <FormControl>
              <FormLabel>Display name</FormLabel>
              <Input
                value={form.displayName || ''}
                onChange={e =>
                  setForm(f => ({ ...f, displayName: e.target.value }))
                }
              />
            </FormControl>
            <FormControl
              display='flex'
              alignItems='center'
              justifyContent='space-between'
              gap={4}
              borderWidth='1px'
              borderColor={border}
              borderRadius='md'
              px={3}
              py={2.5}
            >
              <Box minW={0}>
                <FormLabel mb={0}>Enabled</FormLabel>
                <FormHelperText mt={0}>
                  Allow users to sign in with this provider
                </FormHelperText>
              </Box>
              <Switch
                isChecked={!!form.enabled}
                onChange={e => {
                  const next = e.target.checked;
                  if (!next) {
                    setForm(f => ({ ...f, enabled: false }));
                    previewImpact({ enabled: false });
                  } else {
                    setForm(f => ({ ...f, enabled: true }));
                  }
                }}
              />
            </FormControl>
          </VStack>
        </SsoFormCard>

        <SsoFormCard
          title={provider.type === 'oidc' ? 'OpenID Connect' : 'SAML 2.0'}
          description='Credentials and endpoints from your identity provider.'
        >
          <VStack align='stretch' spacing={4}>
            {provider.type === 'oidc' && (
              <>
                <FormControl
                  isDisabled={isFieldLocked(provider, 'config.issuer')}
                >
                  <FormLabel>Issuer</FormLabel>
                  <Input
                    value={form.config?.issuer || ''}
                    onChange={e =>
                      setForm(f => ({
                        ...f,
                        config: { ...f.config, issuer: e.target.value },
                      }))
                    }
                  />
                  <LockedHint text={lockHelp('config.issuer')} />
                </FormControl>
                <FormControl
                  isDisabled={isFieldLocked(provider, 'config.client_id')}
                >
                  <FormLabel>Client ID</FormLabel>
                  <Input
                    value={form.config?.client_id || ''}
                    onChange={e =>
                      setForm(f => ({
                        ...f,
                        config: { ...f.config, client_id: e.target.value },
                      }))
                    }
                  />
                  <LockedHint text={lockHelp('config.client_id')} />
                </FormControl>
                <FormControl>
                  <FormLabel>Client secret</FormLabel>
                  <Input
                    type='password'
                    placeholder='Leave blank to keep unchanged'
                    value={secretDraft}
                    onChange={e => setSecretDraft(e.target.value)}
                    isDisabled={isFieldLocked(
                      provider,
                      'secrets.client_secret'
                    )}
                  />
                  <LockedHint text={lockHelp('secrets.client_secret')} />
                </FormControl>
              </>
            )}

            {provider.type === 'saml' && (
              <>
                <FormControl
                  isDisabled={isFieldLocked(provider, 'config.issuer')}
                >
                  <FormLabel>SP Entity ID</FormLabel>
                  <Input
                    value={form.config?.issuer || ''}
                    onChange={e =>
                      setForm(f => ({
                        ...f,
                        config: { ...f.config, issuer: e.target.value },
                      }))
                    }
                  />
                  <FormHelperText fontSize='xs'>
                    Entra Identifier (Entity ID). Must match Basic SAML
                    Configuration in your enterprise app, not the IdP issuer
                    from metadata.
                  </FormHelperText>
                  <LockedHint text={lockHelp('config.issuer')} />
                </FormControl>
                <FormControl
                  isDisabled={isFieldLocked(provider, 'config.entry_point')}
                >
                  <FormLabel>Entry point</FormLabel>
                  <Input
                    value={form.config?.entry_point || ''}
                    onChange={e =>
                      setForm(f => ({
                        ...f,
                        config: { ...f.config, entry_point: e.target.value },
                      }))
                    }
                  />
                  <LockedHint text={lockHelp('config.entry_point')} />
                </FormControl>
                <FormControl
                  isDisabled={isFieldLocked(provider, 'config.cert')}
                >
                  <FormLabel>IdP certificate (PEM)</FormLabel>
                  <Textarea
                    rows={5}
                    fontFamily='mono'
                    fontSize='xs'
                    value={form.config?.cert || ''}
                    onChange={e =>
                      setForm(f => ({
                        ...f,
                        config: { ...f.config, cert: e.target.value },
                      }))
                    }
                  />
                  <LockedHint text={lockHelp('config.cert')} />
                </FormControl>
              </>
            )}
          </VStack>
        </SsoFormCard>

        <SsoFormCard title='Advanced'>
          <VStack align='stretch' spacing={3}>
            <Button
              size='sm'
              variant='ghost'
              alignSelf='flex-start'
              rightIcon={showAdvanced ? <FiChevronUp /> : <FiChevronDown />}
              onClick={() => setShowAdvanced(v => !v)}
            >
              {showAdvanced ? 'Hide advanced options' : 'Show advanced options'}
            </Button>
            <Collapse in={showAdvanced}>
              <VStack align='stretch' spacing={4} pt={2}>
                {provider.type === 'oidc' && (
                  <>
                    <Button
                      size='sm'
                      variant='outline'
                      alignSelf='flex-start'
                      onClick={applySuggestedEndpoints}
                    >
                      Apply suggested endpoints
                    </Button>
                    <Text fontSize='sm' color={muted}>
                      {OVERRIDE_FIELD_HELP}
                    </Text>
                    {[
                      'authorization_url',
                      'token_url',
                      'userinfo_url',
                      'jwks_uri',
                    ].map(key => (
                      <FormControl key={key}>
                        <FormLabel fontSize='sm'>
                          {key.replace(/_/g, ' ')}
                        </FormLabel>
                        <Input
                          size='sm'
                          value={form.config?.[key] || ''}
                          onChange={e =>
                            setForm(f => ({
                              ...f,
                              config: { ...f.config, [key]: e.target.value },
                            }))
                          }
                        />
                      </FormControl>
                    ))}
                  </>
                )}
                {provider.type === 'saml' && (
                  <>
                    <FormControl
                      display='flex'
                      alignItems='center'
                      justifyContent='space-between'
                    >
                      <FormLabel mb={0}>Sign AuthnRequest</FormLabel>
                      <Switch
                        isChecked={!!form.security?.sign_authn_requests}
                        onChange={e =>
                          setSecurityField(
                            setForm,
                            'sign_authn_requests',
                            e.target.checked
                          )
                        }
                      />
                    </FormControl>
                    {form.security?.sign_authn_requests && (
                      <>
                        <FormControl>
                          <FormLabel fontSize='sm'>
                            SP signing key (PEM)
                          </FormLabel>
                          <Textarea
                            rows={4}
                            fontFamily='mono'
                            fontSize='xs'
                            placeholder='Leave blank to keep unchanged'
                            value={signingKeyDraft}
                            onChange={e => setSigningKeyDraft(e.target.value)}
                            isDisabled={isFieldLocked(
                              provider,
                              'secrets.signing_key'
                            )}
                          />
                          <LockedHint text={lockHelp('secrets.signing_key')} />
                        </FormControl>
                        <FormControl>
                          <FormLabel fontSize='sm'>
                            SP signing certificate (PEM, optional)
                          </FormLabel>
                          <Textarea
                            rows={3}
                            fontFamily='mono'
                            fontSize='xs'
                            value={form.config?.signing_cert || ''}
                            onChange={e =>
                              setForm(f => ({
                                ...f,
                                config: {
                                  ...f.config,
                                  signing_cert: e.target.value,
                                },
                              }))
                            }
                          />
                        </FormControl>
                      </>
                    )}
                  </>
                )}
                <Divider />
                <Text fontSize='sm' fontWeight='semibold'>
                  Security &amp; identity
                </Text>
                <Text fontSize='xs' color={muted}>
                  Auto-link and strict sync inherit from System Settings unless
                  overridden below.
                </Text>
                <FormControl>
                  <FormLabel fontSize='sm'>Allow auto-link by email</FormLabel>
                  <Select
                    size='sm'
                    value={policyOverrideValue(
                      form.security,
                      'allow_auto_link_local_accounts'
                    )}
                    onChange={e =>
                      setPolicyOverride(
                        setForm,
                        'allow_auto_link_local_accounts',
                        e.target.value
                      )
                    }
                  >
                    <option value='inherit'>
                      Use global default (System Settings)
                    </option>
                    <option value='true'>Enabled for this provider</option>
                    <option value='false'>Disabled for this provider</option>
                  </Select>
                </FormControl>
                <FormControl>
                  <FormLabel fontSize='sm'>Strict membership sync</FormLabel>
                  <Select
                    size='sm'
                    value={policyOverrideValue(
                      form.security,
                      'strict_membership_sync'
                    )}
                    onChange={e =>
                      setPolicyOverride(
                        setForm,
                        'strict_membership_sync',
                        e.target.value
                      )
                    }
                  >
                    <option value='inherit'>
                      Use global default (System Settings)
                    </option>
                    <option value='true'>Enabled for this provider</option>
                    <option value='false'>Disabled for this provider</option>
                  </Select>
                  <FormHelperText fontSize='xs'>
                    Revokes SSO-derived workspace memberships no longer matched
                    by the current group mapping, and refuses a login outright
                    when it resolves to zero grants (no admin, no workspace
                    grants) and the user has no pre-existing workspace
                    membership.
                  </FormHelperText>
                </FormControl>
                <FormControl>
                  <FormLabel fontSize='sm'>Clock skew (seconds)</FormLabel>
                  <Input
                    size='sm'
                    type='number'
                    min={0}
                    max={600}
                    value={form.security?.clock_skew_sec ?? 60}
                    onChange={e =>
                      setSecurityField(
                        setForm,
                        'clock_skew_sec',
                        Number(e.target.value) || 0
                      )
                    }
                  />
                  <FormHelperText fontSize='xs'>
                    Tolerance for IdP clock drift when validating tokens or SAML
                    assertions.
                  </FormHelperText>
                </FormControl>
                {provider.type === 'oidc' && (
                  <>
                    <SecuritySwitch
                      label='Use PKCE'
                      help='Authorization Code flow with PKCE (recommended).'
                      checked={form.security?.pkce !== false}
                      onChange={e =>
                        setSecurityField(setForm, 'pkce', e.target.checked)
                      }
                    />
                    <SecuritySwitch
                      label='Disable OIDC discovery'
                      help='Skip /.well-known/openid-configuration and use manual endpoint URLs only.'
                      checked={!!form.security?.disable_discovery}
                      onChange={e =>
                        setSecurityField(
                          setForm,
                          'disable_discovery',
                          e.target.checked
                        )
                      }
                    />
                  </>
                )}
                {provider.type === 'saml' && (
                  <FormControl>
                    <FormLabel fontSize='sm'>InResponseTo validation</FormLabel>
                    <Select
                      size='sm'
                      value={form.config?.validate_in_response_to || 'always'}
                      onChange={e =>
                        setForm(f => ({
                          ...f,
                          config: {
                            ...f.config,
                            validate_in_response_to: e.target.value,
                          },
                        }))
                      }
                    >
                      <option value='always'>always (recommended)</option>
                      <option value='ifpresent'>ifPresent</option>
                      <option value='never'>never</option>
                    </Select>
                    <FormHelperText fontSize='xs'>
                      Correlates SAML responses to the AuthnRequest. Use never
                      only if the IdP cannot echo InResponseTo.
                    </FormHelperText>
                  </FormControl>
                )}
                <FormControl>
                  <FormLabel fontSize='sm'>Bootstrap admin groups</FormLabel>
                  <Input
                    size='sm'
                    placeholder='e.g. Global-Admins, IT-Ops'
                    value={form.config?.bootstrap_admin_groups || ''}
                    onChange={e =>
                      setForm(f => ({
                        ...f,
                        config: {
                          ...f.config,
                          bootstrap_admin_groups: e.target.value,
                        },
                      }))
                    }
                  />
                  <FormHelperText fontSize='xs'>
                    Comma-separated IdP group names that grant system admin on
                    first matching login (before group mappings run).
                  </FormHelperText>
                </FormControl>
                <Divider />
                <SsoClaimInspector
                  provider={{ ...provider, claim_mapping: form.claim_mapping }}
                />
                <SsoGroupMappingSimulator
                  providers={[provider]}
                  defaultProviderSlug={slug}
                />
              </VStack>
            </Collapse>
          </VStack>
        </SsoFormCard>

        {testResult && (
          <SsoFormCard title='Last test result'>
            <VStack align='stretch' spacing={3}>
              <Box>
                <StatusTag tone={testResult.ok ? 'green' : 'red'}>
                  {testResult.ok ? 'Passed' : 'Failed'}
                </StatusTag>
              </Box>
              <SsoProviderTestResults result={testResult} />
            </VStack>
          </SsoFormCard>
        )}

        <Box pt={4} mt={2} borderTop='1px solid' borderColor={border}>
          <HStack justify='space-between' flexWrap='wrap' spacing={3}>
            <DashboardActionButton
              variant='outline'
              colorScheme='red'
              leftIcon={<FiTrash2 />}
              onClick={() => previewImpact({ delete: true })}
            >
              Delete provider
            </DashboardActionButton>
            <HStack spacing={2}>
              <DashboardActionButton variant='outline' onClick={runTest}>
                Test
              </DashboardActionButton>
              <PrimaryButton isLoading={saving} onClick={() => save()}>
                Save
              </PrimaryButton>
            </HStack>
          </HStack>
        </Box>
      </VStack>

      <Modal
        isOpen={isOpen}
        onClose={() => closeImpactModal(!isDeleting)}
        closeOnEsc={!saving}
        closeOnOverlayClick={!saving}
      >
        <ModalOverlay {...modalProps.overlayProps} />
        <DashboardModalFrame type='danger'>
          <ModalHeader {...modalProps.headerProps}>
            <DashboardModalTitle>
              {isDeleting
                ? hasDependencies
                  ? 'Retire SSO provider'
                  : 'Delete SSO provider'
                : 'Disable SSO provider'}
            </DashboardModalTitle>
            <DashboardModalDescription>
              {provider.displayName}
            </DashboardModalDescription>
          </ModalHeader>
          <ModalCloseButton
            {...modalProps.closeButtonProps}
            isDisabled={saving}
          />
          <ModalBody fontSize='sm' {...modalProps.bodyProps}>
            {impact ? (
              <VStack align='stretch' spacing={3}>
                {impact.is_last_login_method && !needsLocalRecovery && (
                  <StatusPanel status='error'>
                    Keep a working administrator sign-in method before removing
                    this provider. Confirm a local administrator can sign in
                    with a password or verify another provider’s administrator
                    access.
                  </StatusPanel>
                )}
                {needsLocalRecovery && (
                  <StatusPanel status='error'>
                    Retiring a provider with dependencies requires a local
                    administrator who can sign in with a password. Set up and
                    verify that sign-in before continuing.
                  </StatusPanel>
                )}
                {isDeleting && hasDependencies && (
                  <Text color={muted}>
                    Retiring this provider removes its group mappings and
                    provider-managed administrator grants.
                  </Text>
                )}
                <VStack
                  align='stretch'
                  spacing={1}
                  borderWidth='1px'
                  borderColor={border}
                  borderRadius='md'
                  px={3}
                  py={2}
                >
                  <Text>
                    Linked identities: {impact.linked_identities_count}
                  </Text>
                  <Text>Users affected: {impact.affected_users}</Text>
                  {isDeleting && dependencyCounts && (
                    <>
                      <Text>
                        SSO workspace memberships:{' '}
                        {dependencyCounts.memberships_count}
                      </Text>
                      <Text>
                        Group mappings: {dependencyCounts.group_mappings_count}
                      </Text>
                      <Text>
                        Provider-managed administrator grants:{' '}
                        {dependencyCounts.admin_grants_count}
                      </Text>
                    </>
                  )}
                </VStack>
                {isDeleting && needsIdentityPolicy && (
                  <FormControl isRequired>
                    <FormLabel>Linked identity cleanup</FormLabel>
                    <Select
                      placeholder='Choose how to handle linked identities'
                      value={identityPolicy}
                      onChange={event => setIdentityPolicy(event.target.value)}
                      isDisabled={saving}
                    >
                      <option value='archive'>Archive linked identities</option>
                      <option value='drop'>
                        Permanently delete linked identities
                      </option>
                    </Select>
                  </FormControl>
                )}
                {isDeleting && needsMembershipPolicy && (
                  <FormControl isRequired>
                    <FormLabel>Workspace membership cleanup</FormLabel>
                    <Select
                      placeholder='Choose how to handle SSO access'
                      value={membershipPolicy}
                      onChange={event =>
                        setMembershipPolicy(event.target.value)
                      }
                      isDisabled={saving}
                    >
                      <option value='convert-to-manual'>
                        Keep access as manual memberships
                      </option>
                      <option value='delete'>
                        Remove SSO workspace access
                      </option>
                    </Select>
                  </FormControl>
                )}
                {impact.runtime_breakage_likely && (
                  <Box>
                    <StatusTag tone='orange'>Runtime breakage likely</StatusTag>
                  </Box>
                )}
              </VStack>
            ) : (
              <Text>No preview data.</Text>
            )}
          </ModalBody>
          <ModalFooter {...modalProps.footerProps}>
            <Button
              onClick={() => closeImpactModal(!isDeleting)}
              {...modalProps.outlineButtonProps}
              isDisabled={saving}
            >
              Cancel
            </Button>
            <Button
              {...(pendingAction === 'delete'
                ? modalProps.dangerButtonProps
                : modalProps.primaryButtonProps)}
              isLoading={saving}
              isDisabled={
                !impact ||
                impact.is_last_login_method ||
                (isDeleting &&
                  (needsLocalRecovery ||
                    (needsIdentityPolicy && !identityPolicy) ||
                    (needsMembershipPolicy && !membershipPolicy)))
              }
              onClick={confirmImpact}
            >
              {isDeleting
                ? hasDependencies
                  ? 'Retire provider'
                  : 'Delete provider'
                : 'Disable provider'}
            </Button>
          </ModalFooter>
        </DashboardModalFrame>
      </Modal>
    </SsoAdminPageShell>
  );
}
