import { useEffect, useState } from 'react';
import { Navigate, useLocation } from 'react-router';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Box,
  Checkbox,
  FormControl,
  FormLabel,
  HStack,
  Select,
  Stack,
  Text,
} from '@chakra-ui/react';
import SEO from '../components/SEO.jsx';
import { AccessibleSpinner } from '../components/Accessibility';
import {
  DashboardActionButton,
  DashboardPanel,
  DashboardPanelHeader,
} from '../components/DashboardPrimitives';
import { useDashboardTheme } from '../hooks/useDashboardTheme.js';
import apiClient from '../utils/apiClient.js';
import { validMcpAuthorizationId } from '../utils/mcpAuthorization.js';
import { takeMcpSetupPreference } from '../utils/mcpSetupPreference.js';

const options = signal => ({
  signal,
  _suppressLog: true,
  _suppressToast: true,
});

export default function McpAuthorizePage({ session }) {
  const location = useLocation();
  const requestId = new URLSearchParams(location.search).get('request');
  const { muted } = useDashboardTheme();
  const [details, setDetails] = useState(null);
  const [workspaceId, setWorkspaceId] = useState('');
  const [renewals, setRenewals] = useState(false);
  const [agentHealth, setAgentHealth] = useState(false);
  const [inventoryImport, setInventoryImport] = useState(false);
  const [inventoryUpdate, setInventoryUpdate] = useState(false);
  const [contactCreate, setContactCreate] = useState(false);
  const [webhookCreate, setWebhookCreate] = useState(false);
  const [groupCreate, setGroupCreate] = useState(false);
  const [memberInvite, setMemberInvite] = useState(false);
  const [issuance, setIssuance] = useState(false);
  const [days, setDays] = useState('30');
  const [noExpiryAcknowledged, setNoExpiryAcknowledged] = useState(false);
  const [error, setError] = useState('');
  const [expired, setExpired] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setDetails(null);
    setWorkspaceId('');
    setRenewals(false);
    setAgentHealth(false);
    setInventoryImport(false);
    setInventoryUpdate(false);
    setContactCreate(false);
    setWebhookCreate(false);
    setGroupCreate(false);
    setMemberInvite(false);
    setIssuance(false);
    setDays('30');
    setNoExpiryAcknowledged(false);
    setError('');
    setExpired(false);
    if (!session?.id) return undefined;
    if (!validMcpAuthorizationId(requestId)) {
      setError(
        'This connection request is invalid. Restart sign-in from your MCP client.'
      );
      return undefined;
    }
    const controller = new AbortController();
    let expiryTimer;
    apiClient
      .get(
        `/api/v1/mcp/oauth/requests/${requestId}`,
        options(controller.signal)
      )
      .then(response => {
        if (controller.signal.aborted) return;
        setDetails(response.data);
        const preference = takeMcpSetupPreference(
          session.id,
          response.data.workspaces
        );
        if (preference) {
          setWorkspaceId(preference.workspaceId);
          setRenewals(preference.renewals);
          setAgentHealth(preference.agentHealth);
          setInventoryImport(preference.inventoryImport);
          setInventoryUpdate(preference.inventoryUpdate);
          setContactCreate(preference.contactCreate);
          setWebhookCreate(preference.webhookCreate);
          setGroupCreate(preference.groupCreate);
          setMemberInvite(preference.memberInvite);
          setIssuance(preference.issuance);
          setDays(
            preference.noExpiry ? 'never' : String(preference.lifetimeDays)
          );
        } else if (response.data.workspaces.length === 1)
          setWorkspaceId(response.data.workspaces[0].id);
        expiryTimer = setTimeout(
          () => setExpired(true),
          Math.max(0, new Date(response.data.expiresAt).getTime() - Date.now())
        );
      })
      .catch(() => {
        if (!controller.signal.aborted)
          setError(
            'Could not open this connection request. Restart sign-in from your MCP client.'
          );
      });
    return () => {
      controller.abort();
      clearTimeout(expiryTimer);
    };
  }, [requestId, session?.id]);

  if (!session)
    return (
      <Navigate
        to={
          validMcpAuthorizationId(requestId)
            ? `/login?returnTo=${encodeURIComponent(`/mcp/authorize?request=${requestId}`)}`
            : '/login'
        }
        replace
      />
    );
  const workspace = details?.workspaces.find(item => item.id === workspaceId);
  const canRequest = workspace?.canRequestRenewals === true;
  const decide = async decision => {
    if (
      busy ||
      expired ||
      (decision === 'approve' && days === 'never' && !noExpiryAcknowledged)
    )
      return;
    setBusy(true);
    setError('');
    try {
      const result = await apiClient.post(
        `/api/v1/mcp/oauth/requests/${requestId}/decision`,
        {
          decision,
          workspaceId,
          lifetimeDays: days === 'never' ? null : Number(days),
          ...(days === 'never' ? { noExpiry: true } : {}),
          renewals: canRequest && renewals,
          agentHealth: canRequest && (agentHealth || renewals || issuance),
          inventoryImport: canRequest && inventoryImport,
          inventoryUpdate: canRequest && inventoryUpdate,
          contactCreate: canRequest && contactCreate,
          webhookCreate: canRequest && webhookCreate,
          groupCreate: canRequest && groupCreate,
          memberInvite: canRequest && memberInvite,
          issuance: canRequest && issuance,
        },
        options()
      );
      const redirect = new URL(result.data.redirectUrl);
      if (
        redirect.origin !== details.redirectOrigin ||
        !['https:', 'http:'].includes(redirect.protocol)
      )
        throw new Error('Invalid return address');
      window.location.assign(redirect.href);
    } catch (failure) {
      const code = failure.response?.data?.error;
      setError(
        code === 'plan_required'
          ? 'This workspace’s plan does not include MCP access.'
          : code === 'workspace_frozen'
            ? 'This workspace is frozen. Ask an administrator before connecting.'
            : code === 'connection_limit'
              ? 'Revoke an unused connection in Preferences, then try again.'
              : 'Could not confirm the connection. Restart sign-in from your MCP client.'
      );
      setBusy(false);
    }
  };

  return (
    <Box maxW='44rem' mx='auto' px={{ base: 4, md: 6 }} py={{ base: 5, md: 8 }}>
      <SEO title='Connect an MCP assistant' noindex />
      <DashboardPanel>
        <DashboardPanelHeader
          title='Connect an MCP assistant'
          description='Choose the workspace and access you want to share.'
        />
        <Stack spacing={5} mt={4}>
          <Text fontSize='sm' color={muted}>
            Signed in as {session.email || 'your TokenTimer account'}.
          </Text>
          {error ? (
            <Alert status='error' borderRadius='md'>
              <AlertIcon />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : null}
          {expired ? (
            <Alert status='warning' borderRadius='md'>
              <AlertIcon />
              <AlertDescription>
                This request expired. Restart sign-in from your MCP client.
              </AlertDescription>
            </Alert>
          ) : null}
          {!details && !error ? (
            <AccessibleSpinner label='Loading connection request…' />
          ) : null}
          {details ? (
            <>
              <Box>
                <Text fontWeight='semibold'>{details.clientName}</Text>
                <Text fontSize='sm' color={muted}>
                  Returns to {details.redirectOrigin}
                </Text>
                <Text fontSize='xs' color={muted} mt={1}>
                  {details.identityVerified
                    ? `App identity: ${new URL(details.clientId).origin}`
                    : 'The app supplied its name. Check the return address before connecting.'}
                </Text>
              </Box>
              {!details.workspaces.length ? (
                <Text>
                  You need workspace membership to connect an assistant. Join or
                  create a workspace, then restart sign-in.
                </Text>
              ) : null}
              <FormControl isRequired>
                <FormLabel htmlFor='mcp-consent-workspace'>Workspace</FormLabel>
                <Select
                  id='mcp-consent-workspace'
                  value={workspaceId}
                  isDisabled={busy || expired}
                  placeholder='Choose a workspace'
                  onChange={event => {
                    setWorkspaceId(event.target.value);
                    setRenewals(false);
                    setAgentHealth(false);
                    setInventoryImport(false);
                    setInventoryUpdate(false);
                    setContactCreate(false);
                    setWebhookCreate(false);
                    setGroupCreate(false);
                    setMemberInvite(false);
                    setIssuance(false);
                    setNoExpiryAcknowledged(false);
                  }}
                >
                  {details.workspaces.map(item => (
                    <option key={item.id} value={item.id}>
                      {item.name}
                    </option>
                  ))}
                </Select>
              </FormControl>
              <Box>
                <Text fontWeight='semibold' fontSize='sm'>
                  {(renewals ||
                    inventoryImport ||
                    inventoryUpdate ||
                    contactCreate ||
                    webhookCreate ||
                    groupCreate ||
                    memberInvite ||
                    issuance) &&
                  canRequest
                    ? 'Selected capabilities'
                    : 'Read-only access'}
                </Text>
                <Text color={muted} fontSize='sm'>
                  Read token inventory, certificate and job status in this
                  workspace. Private keys and credentials are never shared.
                </Text>
              </Box>
              {canRequest ? (
                <Stack spacing={3}>
                  <FormControl>
                    <FormLabel htmlFor='mcp-consent-access'>
                      Access level
                    </FormLabel>
                    <Select
                      id='mcp-consent-access'
                      value={
                        inventoryImport ||
                        inventoryUpdate ||
                        renewals ||
                        contactCreate ||
                        webhookCreate ||
                        groupCreate ||
                        memberInvite ||
                        issuance
                          ? 'read-write'
                          : 'read-only'
                      }
                      isDisabled={busy || expired}
                      onChange={event => {
                        const writeAccess = event.target.value === 'read-write';
                        setInventoryImport(writeAccess);
                        if (!writeAccess) {
                          setRenewals(false);
                          setInventoryUpdate(false);
                          setContactCreate(false);
                          setWebhookCreate(false);
                          setGroupCreate(false);
                          setMemberInvite(false);
                          setIssuance(false);
                        }
                      }}
                    >
                      <option value='read-only'>Read-only</option>
                      <option value='read-write'>Read-write</option>
                    </Select>
                  </FormControl>
                  <Checkbox
                    isChecked={inventoryImport}
                    isDisabled={busy || expired}
                    onChange={event => setInventoryImport(event.target.checked)}
                  >
                    Allow reviewed inventory imports
                  </Checkbox>
                  <Checkbox
                    isChecked={inventoryUpdate}
                    isDisabled={busy || expired}
                    onChange={event => setInventoryUpdate(event.target.checked)}
                  >
                    Allow reviewed inventory updates
                  </Checkbox>
                  <Checkbox
                    isChecked={contactCreate}
                    isDisabled={busy || expired}
                    onChange={event => setContactCreate(event.target.checked)}
                  >
                    Allow reviewed contact creation
                  </Checkbox>
                  <Checkbox
                    isChecked={webhookCreate}
                    isDisabled={busy || expired}
                    onChange={event => setWebhookCreate(event.target.checked)}
                  >
                    Allow reviewed webhook creation
                  </Checkbox>
                  <Checkbox
                    isChecked={groupCreate}
                    isDisabled={busy || expired}
                    onChange={event => setGroupCreate(event.target.checked)}
                  >
                    Allow reviewed contact group creation and listing recipient
                    names
                  </Checkbox>
                  <Checkbox
                    isChecked={memberInvite}
                    isDisabled={busy || expired}
                    onChange={event => setMemberInvite(event.target.checked)}
                  >
                    Allow reviewed viewer invitations by email
                  </Checkbox>
                  <Checkbox
                    isChecked={issuance}
                    isDisabled={busy || expired}
                    onChange={event => setIssuance(event.target.checked)}
                  >
                    Allow certificate issuance requests
                  </Checkbox>
                  <Checkbox
                    isChecked={agentHealth || renewals || issuance}
                    isDisabled={busy || expired || renewals || issuance}
                    onChange={event => setAgentHealth(event.target.checked)}
                  >
                    Include agent health
                  </Checkbox>
                  <Checkbox
                    isChecked={renewals}
                    isDisabled={busy || expired}
                    onChange={event => setRenewals(event.target.checked)}
                  >
                    Allow renewal requests
                  </Checkbox>
                  <Text fontSize='sm' color={muted}>
                    Renewal and issuance permissions include agent health.
                    Requests follow CertOps Job approval and workspace controls.
                    This connection cannot approve jobs or change settings.
                  </Text>
                  <Text fontSize='sm' color={muted}>
                    {inventoryImport
                      ? 'Read-write includes reviewed metadata imports. Existing records are kept and secrets are rejected.'
                      : inventoryUpdate
                        ? 'Reviewed updates are enabled; inventory imports are not enabled.'
                        : contactCreate
                          ? 'Reviewed contact creation is enabled; inventory imports are not enabled.'
                          : webhookCreate
                            ? 'Reviewed webhook creation is enabled; inventory imports are not enabled.'
                            : groupCreate
                              ? 'Reviewed contact group creation is enabled; inventory imports are not enabled.'
                              : memberInvite
                                ? 'Reviewed viewer invitations are enabled; inventory imports are not enabled.'
                                : issuance
                                  ? 'Issuance requests are enabled; inventory imports are not enabled.'
                                  : renewals
                                    ? 'Renewal requests are enabled; inventory imports are not enabled.'
                                    : 'Read-only cannot import inventory or request renewals.'}
                  </Text>
                </Stack>
              ) : null}
              <FormControl>
                <FormLabel htmlFor='mcp-consent-lifetime'>
                  Access expires after
                </FormLabel>
                <Select
                  id='mcp-consent-lifetime'
                  value={days}
                  isDisabled={busy || expired}
                  onChange={event => {
                    setDays(event.target.value);
                    setNoExpiryAcknowledged(false);
                  }}
                >
                  {[1, 7, 30, 90, 180, 365].map(day => (
                    <option key={day} value={String(day)}>
                      {day} {day === 1 ? 'day' : 'days'}
                    </option>
                  ))}
                  <option value='never'>No expiry</option>
                </Select>
              </FormControl>
              {days === 'never' ? (
                <Stack spacing={2}>
                  <Text fontSize='sm' color={muted}>
                    No expiry increases the risk of unattended access.
                  </Text>
                  <Checkbox
                    isChecked={noExpiryAcknowledged}
                    isDisabled={busy || expired}
                    onChange={event =>
                      setNoExpiryAcknowledged(event.target.checked)
                    }
                  >
                    Keep this connection active until I revoke it.
                  </Checkbox>
                </Stack>
              ) : null}
              <Text fontSize='sm' color={muted}>
                Revoke access anytime in Preferences → MCP assistants.
              </Text>
              <HStack justify='flex-end' flexWrap='wrap'>
                <DashboardActionButton
                  variant='outline'
                  isDisabled={busy || expired}
                  onClick={() => decide('deny')}
                >
                  Cancel
                </DashboardActionButton>
                <DashboardActionButton
                  colorScheme='blue'
                  isLoading={busy}
                  isDisabled={
                    !workspaceId ||
                    expired ||
                    (days === 'never' && !noExpiryAcknowledged)
                  }
                  onClick={() => decide('approve')}
                >
                  Connect
                </DashboardActionButton>
              </HStack>
            </>
          ) : null}
        </Stack>
      </DashboardPanel>
    </Box>
  );
}
