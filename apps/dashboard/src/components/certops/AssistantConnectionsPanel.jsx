import { useEffect, useRef, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
  Box,
  Button,
  Checkbox,
  FormControl,
  FormHelperText,
  FormLabel,
  HStack,
  Input,
  Link,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Radio,
  RadioGroup,
  Select,
  Stack,
  Text,
} from '@chakra-ui/react';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { API_BASE_URL } from '../../utils/apiClient.js';
import { MCP_SETUP_DOCS } from '../../utils/docsUrls.js';
import { rememberMcpSetupPreference } from '../../utils/mcpSetupPreference.js';
import {
  useDashboardTheme,
  useDashboardThemeColors,
} from '../../hooks/useDashboardTheme.js';
import LearnMorePanel, { INFO_NOTE_PROPS } from '../LearnMorePanel.jsx';
import {
  DashboardActionButton,
  DashboardPanel,
  DashboardPanelHeader,
} from '../DashboardPrimitives';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import CopyableCodeBlock from '../CopyableCodeBlock.jsx';
import AssistantConnectionsModal from './AssistantConnectionsModal.jsx';
import { assistantSetupCommand } from './assistantSetupCommand.js';
import {
  useCertOpsCanManage,
  useCertOpsIsWorkspaceAdmin,
} from './useCertOps.js';
import {
  createAssistantSetup,
  loadAssistantConnections,
  revokeAssistantAccess,
} from './assistantConnectionsApi.js';

function dateLabel(value) {
  return value ? new Date(value).toLocaleString() : 'Not used yet';
}

function accessError(error) {
  const status = error?.response?.status;
  if (status === 404)
    return 'The MCP interface is not enabled on this server. Ask your administrator about availability.';
  if (status === 402 || status === 403)
    return 'MCP access is unavailable for this workspace or account. Check your role and plan with an administrator.';
  return 'Could not load assistant access. Retry before creating or changing a connection.';
}

function ConnectionsForWorkspace({ workspaceId, userId }) {
  const canManage = useCertOpsCanManage();
  const isAdmin = useCertOpsIsWorkspaceAdmin();
  const { muted } = useDashboardTheme();
  const { dashboard } = useDashboardThemeColors();
  const modal = useDashboardModalProps();
  const methodCardProps = (selected, disabled = false) => ({
    flex: 1,
    sx: {
      '.chakra-radio': {
        width: '100%',
        height: '100%',
        alignItems: 'flex-start',
        p: 3,
        borderWidth: '1px',
        borderRadius: 'md',
        borderColor: selected
          ? dashboard.accent.interactiveBorder
          : dashboard.border.subtle,
        bg: selected ? dashboard.accent.interactiveSurface : 'transparent',
        opacity: disabled ? 0.55 : 1,
        cursor: disabled ? 'not-allowed' : 'pointer',
        _focusWithin: { boxShadow: 'outline' },
      },
    },
  });
  const alive = useRef(false);
  const codeTimer = useRef(null);
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);
  const [manageOpen, setManageOpen] = useState(false);
  const [method, setMethod] = useState('remote');
  const [step, setStep] = useState('method');
  const [urlCopied, setUrlCopied] = useState(false);
  const [name, setName] = useState('My local assistant');
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
  const [setup, setSetup] = useState(null);
  const [copied, setCopied] = useState(false);
  const [notice, setNotice] = useState('');

  useEffect(() => {
    alive.current = true;
    const controller = new AbortController();
    loadAssistantConnections(workspaceId, controller.signal)
      .then(value => {
        if (alive.current) setData(value);
      })
      .catch(err => {
        if (alive.current) setError(accessError(err));
      });
    return () => {
      alive.current = false;
      controller.abort();
      clearTimeout(codeTimer.current);
    };
  }, [workspaceId]);

  const refresh = async () => {
    setBusy(true);
    try {
      const value = await loadAssistantConnections(workspaceId);
      if (!alive.current) return;
      setData(value);
      setError('');
      const grant = value.enrollments.find(
        item => item.id === setup?.enrollment.id
      );
      if (grant?.status === 'redeemed') {
        clearTimeout(codeTimer.current);
        setSetup(null);
        setNotice(
          'Connection created. Add the configuration printed by enrollment to your MCP client, then ask it to run tt_whoami.'
        );
        setOpen(false);
      } else if (setup && grant?.status !== 'pending') {
        clearTimeout(codeTimer.current);
        setSetup(null);
        setNotice(
          'This setup code is no longer usable. Create a new code to continue.'
        );
      }
    } catch (err) {
      if (alive.current) {
        setData(null);
        setError(accessError(err));
        setNotice(
          'Could not check the connection. Close this dialog and retry before continuing.'
        );
      }
    } finally {
      if (alive.current) setBusy(false);
    }
  };

  const create = async () => {
    if (days === 'never' && !noExpiryAcknowledged) return;
    setBusy(true);
    setNotice('');
    try {
      const scopes = [
        'mcp:identity:read',
        'mcp:certs:read',
        'mcp:jobs:read',
        'mcp:tokens:read',
      ];
      if ((renewals || agentHealth || issuance) && canManage)
        scopes.push('mcp:agents:read');
      if ((renewals || issuance) && canManage) scopes.push('mcp:requests:read');
      if (renewals && canManage) scopes.push('mcp:renew:request');
      if (inventoryImport && canManage) scopes.push('mcp:inventory:import');
      if (inventoryUpdate && canManage) scopes.push('mcp:inventory:update');
      if (contactCreate && canManage) scopes.push('mcp:contacts:create');
      if (webhookCreate && canManage) scopes.push('mcp:webhooks:create');
      if (groupCreate && canManage) scopes.push('mcp:groups:create');
      if (memberInvite && canManage) scopes.push('mcp:members:invite');
      if (issuance && canManage) scopes.push('mcp:issue:request');
      const value = await createAssistantSetup(workspaceId, {
        name: name.trim(),
        scopes,
        roleCeiling:
          (renewals ||
            agentHealth ||
            inventoryImport ||
            inventoryUpdate ||
            contactCreate ||
            webhookCreate ||
            groupCreate ||
            memberInvite ||
            issuance) &&
          canManage
            ? 'workspace_manager'
            : 'viewer',
        ...(days === 'never'
          ? { noExpiry: true }
          : { connectionLifetimeDays: Number(days) }),
      });
      if (!alive.current) return;
      setSetup(value);
      setCopied(false);
      setData(previous => ({
        ...previous,
        enrollments: [value.enrollment, ...previous.enrollments],
      }));
      clearTimeout(codeTimer.current);
      codeTimer.current = setTimeout(
        () => {
          if (alive.current) {
            setSetup(null);
            setNotice('The setup code expired. Create a new code to continue.');
          }
        },
        Math.max(0, new Date(value.enrollment.expiresAt).getTime() - Date.now())
      );
    } catch {
      if (alive.current) {
        setData(null);
        setNotice(
          'Setup could not be confirmed. Close this dialog, retry loading connections and revoke any unused setup code in Manage connections before starting again.'
        );
      }
    } finally {
      if (alive.current) setBusy(false);
    }
  };

  const revoke = async (kind, id) => {
    setBusy(true);
    try {
      await revokeAssistantAccess(workspaceId, kind, id);
      if (!alive.current) return;
      if (setup?.enrollment.id === id) {
        clearTimeout(codeTimer.current);
        setSetup(null);
      }
      const value = await loadAssistantConnections(workspaceId);
      if (alive.current) {
        setData(value);
        setNotice(
          kind === 'enrollments'
            ? 'Setup code revoked.'
            : 'Connection revoked. New calls are refused; work already held by an agent may continue.'
        );
      }
    } catch {
      if (alive.current) {
        setData(null);
        setError(
          'Could not confirm revocation. Refresh and check the status before continuing.'
        );
      }
    } finally {
      if (alive.current) setBusy(false);
    }
  };

  const close = () => {
    if (busy) return;
    setOpen(false);
    setSetup(null);
    setUrlCopied(false);
    setNotice('');
    clearTimeout(codeTimer.current);
  };
  const command = assistantSetupCommand(API_BASE_URL, window.location.origin);
  const copyRemoteUrl = async () => {
    if (days === 'never' && !noExpiryAcknowledged) return;
    rememberMcpSetupPreference({
      userId,
      workspaceId,
      renewals: canManage && renewals,
      agentHealth: canManage && (agentHealth || renewals || issuance),
      inventoryImport: canManage && inventoryImport,
      inventoryUpdate: canManage && inventoryUpdate,
      contactCreate: canManage && contactCreate,
      webhookCreate: canManage && webhookCreate,
      groupCreate: canManage && groupCreate,
      memberInvite: canManage && memberInvite,
      issuance: canManage && issuance,
      lifetimeDays: days === 'never' ? null : Number(days),
      noExpiry: days === 'never',
    });
    try {
      await navigator.clipboard.writeText(data.remote.serverUrl);
      setUrlCopied(true);
      setNotice(
        'Server URL copied. Add a remote server in your MCP client, then choose Sign in.'
      );
    } catch {
      setNotice('Select and copy the server URL above.');
    }
  };

  return (
    <DashboardPanel id='mcp-assistants' scrollMarginTop={4}>
      <DashboardPanelHeader
        title='MCP assistants'
        description='Connect an assistant with access to one workspace. Read-only access is the default; your current permissions still apply.'
      />
      <Stack spacing={4}>
        <LearnMorePanel
          variant='compact'
          links={[{ url: MCP_SETUP_DOCS, label: 'MCP setup guide' }]}
        />
        {error && !manageOpen ? (
          <Alert status='warning' borderRadius='md'>
            <AlertIcon />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}
        {error && !manageOpen ? (
          <Button
            alignSelf='start'
            variant='outline'
            onClick={refresh}
            isLoading={busy}
          >
            Retry connections
          </Button>
        ) : null}
        {!data && !error ? (
          <Text fontSize='sm' color={muted}>
            Checking assistant access...
          </Text>
        ) : null}
        {notice && !open && !manageOpen ? (
          <Alert status='info' borderRadius='md'>
            <AlertIcon />
            <AlertDescription>{notice}</AlertDescription>
          </Alert>
        ) : null}
        {data ? (
          <>
            <Box>
              <HStack spacing={3} flexWrap='wrap'>
                {!data.frozenWorkspaceName ? (
                  <DashboardActionButton
                    colorScheme='blue'
                    onClick={() => {
                      setNotice('');
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
                      setUrlCopied(false);
                      setMethod(data.remote?.enabled ? 'remote' : 'local');
                      setStep('method');
                      setOpen(true);
                    }}
                  >
                    Connect an MCP assistant
                  </DashboardActionButton>
                ) : null}
                <DashboardActionButton
                  variant='outline'
                  onClick={() => {
                    setNotice('');
                    setManageOpen(true);
                    refresh();
                  }}
                >
                  Manage connections
                </DashboardActionButton>
              </HStack>
              <Text fontSize='sm' color={muted} mt={2}>
                {data.frozenWorkspaceName
                  ? `${data.frozenWorkspaceName} is frozen. You can still revoke access and setup codes.`
                  : 'Choose remote HTTP with browser sign-in, or a local adapter for clients that only support stdio.'}
              </Text>
            </Box>
          </>
        ) : null}
      </Stack>
      <AssistantConnectionsModal
        isOpen={manageOpen}
        onClose={() => {
          if (!busy) {
            setManageOpen(false);
            setNotice('');
          }
        }}
        data={data}
        busy={busy}
        error={error}
        notice={notice}
        isAdmin={isAdmin}
        onRefresh={refresh}
        onRevoke={revoke}
      />
      <Modal
        isOpen={open}
        onClose={close}
        closeOnOverlayClick={false}
        scrollBehavior='inside'
        size='2xl'
      >
        <ModalOverlay />
        <DashboardModalFrame
          maxW='2xl'
          my={0}
          minH={0}
          maxH={{ base: 'calc(100dvh - 32px)', md: 'calc(100dvh - 64px)' }}
        >
          <ModalHeader>
            <DashboardModalTitle>Connect an MCP assistant</DashboardModalTitle>
            <DashboardModalDescription>
              Choose a method, then permissions and access duration.
            </DashboardModalDescription>
          </ModalHeader>
          <ModalCloseButton
            aria-label='Close assistant setup'
            isDisabled={busy}
          />
          <ModalBody>
            <Stack spacing={3}>
              {notice ? (
                <Alert
                  status={urlCopied ? 'success' : 'warning'}
                  borderRadius='md'
                >
                  <AlertIcon />
                  <AlertDescription>{notice}</AlertDescription>
                </Alert>
              ) : null}
              {!setup ? (
                <>
                  {step === 'method' ? (
                    <>
                      <FormControl>
                        <FormLabel id='mcp-method-label' {...modal.labelProps}>
                          Connection method
                        </FormLabel>
                        <RadioGroup
                          aria-labelledby='mcp-method-label'
                          value={method}
                          onChange={value => {
                            setMethod(value);
                            setNotice('');
                            setUrlCopied(false);
                          }}
                        >
                          <Stack
                            direction={{ base: 'column', md: 'row' }}
                            align='stretch'
                            spacing={3}
                          >
                            <Box
                              {...methodCardProps(
                                method === 'remote',
                                !data?.remote?.enabled
                              )}
                            >
                              <Radio
                                value='remote'
                                inputProps={{
                                  'aria-label': 'Remote HTTP (recommended)',
                                }}
                                isDisabled={!data?.remote?.enabled}
                              >
                                <Text
                                  as='span'
                                  display='block'
                                  fontSize='sm'
                                  fontWeight='semibold'
                                >
                                  Remote HTTP{' '}
                                  <Badge ml={1} colorScheme='blue'>
                                    Recommended
                                  </Badge>
                                </Text>
                                <Text
                                  as='span'
                                  display='block'
                                  fontSize='sm'
                                  color={muted}
                                  mt={2}
                                >
                                  No installation. Connect by URL and sign in
                                  with your account. Requires a client
                                  supporting Streamable HTTP and OAuth.
                                </Text>
                              </Radio>
                            </Box>
                            <Box {...methodCardProps(method === 'local')}>
                              <Radio
                                value='local'
                                inputProps={{
                                  'aria-label': 'Local adapter (stdio)',
                                }}
                              >
                                <Text
                                  as='span'
                                  display='block'
                                  fontSize='sm'
                                  fontWeight='semibold'
                                >
                                  Local adapter (stdio)
                                </Text>
                                <Text
                                  as='span'
                                  display='block'
                                  fontSize='sm'
                                  color={muted}
                                  mt={2}
                                >
                                  For stdio-only clients. Keeps a credential
                                  file on your computer. Requires Node 24 and a
                                  reviewed Core checkout.
                                </Text>
                              </Radio>
                            </Box>
                          </Stack>
                        </RadioGroup>
                        {!data?.remote?.enabled ? (
                          <FormHelperText>
                            Remote sign-in is not enabled on this server. Ask
                            your administrator about availability.
                          </FormHelperText>
                        ) : null}
                      </FormControl>
                      <LearnMorePanel
                        variant='compact'
                        title='Connection help'
                        links={[
                          {
                            url: MCP_SETUP_DOCS,
                            label: 'MCP setup guide and client requirements',
                          },
                        ]}
                      />
                    </>
                  ) : (
                    <>
                      <Text fontWeight='semibold' fontSize='sm'>
                        {method === 'remote'
                          ? 'Remote HTTP · Browser sign-in'
                          : 'Local adapter · One-time enrollment'}
                      </Text>
                      {method === 'remote' ? (
                        <Box>
                          <FormControl>
                            <FormLabel {...modal.labelProps}>
                              MCP server URL
                            </FormLabel>
                            <Input
                              {...modal.fieldProps}
                              value={data?.remote?.serverUrl || ''}
                              isReadOnly
                            />
                          </FormControl>
                          <Alert
                            {...INFO_NOTE_PROPS}
                            role='note'
                            alignItems='flex-start'
                            mt={3}
                          >
                            <AlertIcon boxSize={4} mt={1} />
                            <AlertDescription fontSize='sm' minW={0}>
                              <Stack spacing={1}>
                                <Text>
                                  1. Add this URL as a Streamable HTTP server in
                                  your client.
                                </Text>
                                <Text>
                                  2. Sign in and review the app, workspace and
                                  access.
                                </Text>
                                <Text>
                                  3. Run tt_whoami in the client to verify the
                                  connection.
                                </Text>
                                <Text fontSize='xs'>
                                  Access is granted during browser sign-in.
                                  These settings are suggestions.
                                </Text>
                              </Stack>
                            </AlertDescription>
                          </Alert>
                        </Box>
                      ) : null}
                      {method === 'local' && !command ? (
                        <Text fontSize='sm'>
                          The configured API address cannot be used in a
                          terminal command. Ask your administrator to check it
                          before creating a setup code.
                        </Text>
                      ) : null}
                      {method === 'local' ? (
                        <FormControl>
                          <FormLabel {...modal.labelProps}>
                            Connection name
                          </FormLabel>
                          <Input
                            {...modal.fieldProps}
                            value={name}
                            onChange={e => setName(e.target.value)}
                            maxLength={128}
                            autoComplete='off'
                          />
                        </FormControl>
                      ) : null}
                      <Stack direction='column' align='stretch' spacing={4}>
                        <FormControl>
                          <FormLabel
                            id='mcp-access-label'
                            {...modal.labelProps}
                          >
                            Permissions
                          </FormLabel>
                          <Stack spacing={2}>
                            <Text fontSize='sm' color={muted}>
                              Read token inventory, certificates and jobs.
                            </Text>
                            {canManage ? (
                              <>
                                <FormControl>
                                  <FormLabel
                                    htmlFor='mcp-access-mode'
                                    {...modal.labelProps}
                                  >
                                    Access level
                                  </FormLabel>
                                  <Select
                                    id='mcp-access-mode'
                                    {...modal.fieldProps}
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
                                    onChange={event => {
                                      const writeAccess =
                                        event.target.value === 'read-write';
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
                                    <option value='read-write'>
                                      Read-write
                                    </option>
                                  </Select>
                                </FormControl>
                                <Checkbox
                                  isChecked={inventoryImport}
                                  onChange={event =>
                                    setInventoryImport(event.target.checked)
                                  }
                                >
                                  Allow reviewed inventory imports
                                </Checkbox>
                                <Checkbox
                                  isChecked={inventoryUpdate}
                                  onChange={event =>
                                    setInventoryUpdate(event.target.checked)
                                  }
                                >
                                  Allow reviewed inventory updates
                                </Checkbox>
                                <Checkbox
                                  isChecked={contactCreate}
                                  onChange={event =>
                                    setContactCreate(event.target.checked)
                                  }
                                >
                                  Allow reviewed contact creation
                                </Checkbox>
                                <Checkbox
                                  isChecked={webhookCreate}
                                  onChange={event =>
                                    setWebhookCreate(event.target.checked)
                                  }
                                >
                                  Allow reviewed webhook creation
                                </Checkbox>
                                <Checkbox
                                  isChecked={groupCreate}
                                  onChange={event =>
                                    setGroupCreate(event.target.checked)
                                  }
                                >
                                  Create contact groups and list recipient names
                                </Checkbox>
                                <Checkbox
                                  isChecked={memberInvite}
                                  onChange={event =>
                                    setMemberInvite(event.target.checked)
                                  }
                                >
                                  Review and invite viewers by email
                                </Checkbox>
                                <Checkbox
                                  isChecked={issuance}
                                  onChange={event =>
                                    setIssuance(event.target.checked)
                                  }
                                >
                                  Allow certificate issuance requests
                                </Checkbox>
                                <Checkbox
                                  isChecked={renewals}
                                  onChange={event =>
                                    setRenewals(event.target.checked)
                                  }
                                >
                                  Allow certificate renewal requests
                                </Checkbox>
                              </>
                            ) : null}
                            {canManage ? (
                              <Checkbox
                                isChecked={agentHealth || renewals || issuance}
                                isDisabled={renewals || issuance}
                                onChange={e => setAgentHealth(e.target.checked)}
                              >
                                View CertOps agent health
                              </Checkbox>
                            ) : null}
                          </Stack>
                        </FormControl>
                        <FormControl>
                          <FormLabel {...modal.labelProps}>
                            Connection expires after
                          </FormLabel>
                          <Select
                            {...modal.fieldProps}
                            value={days}
                            onChange={e => {
                              setDays(e.target.value);
                              setNoExpiryAcknowledged(false);
                            }}
                          >
                            <option value='1'>1 day</option>
                            <option value='7'>7 days</option>
                            <option value='30'>30 days</option>
                            <option value='90'>90 days</option>
                            <option value='180'>180 days</option>
                            <option value='365'>365 days</option>
                            <option value='never'>No expiry</option>
                          </Select>
                        </FormControl>
                      </Stack>
                      {days === 'never' ? (
                        <Stack spacing={2}>
                          <Text fontSize='sm' color={muted}>
                            No expiry increases the risk of unattended access.
                          </Text>
                          <Checkbox
                            isChecked={noExpiryAcknowledged}
                            onChange={event =>
                              setNoExpiryAcknowledged(event.target.checked)
                            }
                          >
                            Keep this connection active until I revoke it.
                          </Checkbox>
                        </Stack>
                      ) : null}
                      {(renewals || issuance) && canManage ? (
                        <Text fontSize='sm' color={muted}>
                          Renewal and issuance requests include agent health and
                          follow CertOps Job approval. This never grants job
                          approval or settings access.
                        </Text>
                      ) : null}
                      {inventoryImport && canManage ? (
                        <Text fontSize='sm' color={muted}>
                          Read-write adds reviewed inventory metadata imports. A
                          preview is required; existing records are kept and
                          secrets are rejected.
                        </Text>
                      ) : null}
                      {renewals && canManage && !data?.writesEnabled ? (
                        <Text fontSize='sm' color={muted}>
                          Renewal requests are off for this workspace. An owner
                          or manager can enable them in{' '}
                          <Link
                            href={`/certops/settings?workspace=${encodeURIComponent(workspaceId)}#workspace-controls`}
                          >
                            Workspace controls
                          </Link>
                          .
                        </Text>
                      ) : null}
                      {method === 'local' ? (
                        <Text fontSize='sm' color={muted}>
                          Install the Core checkout’s pinned dependencies before
                          creating the code.
                        </Text>
                      ) : null}
                    </>
                  )}
                </>
              ) : (
                <>
                  <Text fontSize='sm' fontWeight='semibold'>
                    2. Enroll on your computer
                  </Text>
                  <Text fontSize='sm'>
                    From the Core checkout, run this command. Paste the code
                    only at its hidden prompt.
                  </Text>
                  <CopyableCodeBlock
                    code={command}
                    label='Local terminal command'
                  />
                  <FormControl>
                    <FormLabel {...modal.labelProps}>
                      One-time setup code
                    </FormLabel>
                    <Input
                      {...modal.fieldProps}
                      type='password'
                      value={setup.grant}
                      isReadOnly
                      autoComplete='off'
                      data-private='true'
                    />
                    <FormHelperText>
                      Expires {dateLabel(setup.enrollment.expiresAt)}. Never
                      paste it into an assistant chat or client configuration.
                    </FormHelperText>
                  </FormControl>
                  <Button
                    variant='outline'
                    size='sm'
                    onClick={async () => {
                      try {
                        await navigator.clipboard.writeText(setup.grant);
                        setCopied(true);
                      } catch {
                        setNotice(
                          'Copy failed. Select the code field and copy it manually.'
                        );
                      }
                    }}
                  >
                    {copied ? 'Code copied' : 'Copy setup code'}
                  </Button>
                  <Text fontSize='sm' fontWeight='semibold'>
                    3. Add your client and verify
                  </Text>
                  <Stack as='ol' pl={5} spacing={1} fontSize='sm'>
                    <Text as='li'>
                      Save the command, arguments and environment printed by
                      enrollment in your MCP client.
                    </Text>
                    <Text as='li'>
                      Restart the client and ask it to run{' '}
                      <Text as='code'>tt_whoami</Text>.
                    </Text>
                    <Text as='li'>
                      Confirm the workspace and role before asking for
                      certificate details.
                    </Text>
                  </Stack>
                  <Text fontSize='xs' color={muted}>
                    Renewal tools also need TOKENTIMER_MCP_ENABLE_WRITES=true in
                    the client environment. Closing this dialog hides the code;
                    its pending grant remains revocable in Manage connections.
                  </Text>
                </>
              )}
            </Stack>
          </ModalBody>
          <ModalFooter {...modal.footerProps}>
            <Button
              {...modal.outlineButtonProps}
              onClick={close}
              isDisabled={busy}
            >
              Close
            </Button>
            {!setup && step === 'access' ? (
              <Button
                {...modal.outlineButtonProps}
                onClick={() => {
                  setStep('method');
                  setNotice('');
                  setUrlCopied(false);
                }}
                isDisabled={busy}
              >
                Back
              </Button>
            ) : null}
            {setup ? (
              <Button
                {...modal.primaryButtonProps}
                onClick={refresh}
                isLoading={busy}
              >
                Check connection
              </Button>
            ) : step === 'method' ? (
              <Button
                {...modal.primaryButtonProps}
                onClick={() => setStep('access')}
                isDisabled={
                  !data || (method === 'remote' && !data.remote?.enabled)
                }
              >
                Continue
              </Button>
            ) : method === 'remote' ? (
              <Button
                {...modal.primaryButtonProps}
                onClick={copyRemoteUrl}
                isDisabled={
                  !data?.remote?.enabled ||
                  (days === 'never' && !noExpiryAcknowledged)
                }
              >
                Copy server URL
              </Button>
            ) : (
              <Button
                {...modal.primaryButtonProps}
                onClick={create}
                isLoading={busy}
                isDisabled={
                  !name.trim() ||
                  !data ||
                  !command ||
                  (days === 'never' && !noExpiryAcknowledged)
                }
              >
                Create setup code
              </Button>
            )}
          </ModalFooter>
        </DashboardModalFrame>
      </Modal>
    </DashboardPanel>
  );
}

export default function AssistantConnectionsPanel({ userId }) {
  const { workspaceId } = useWorkspace();
  useEffect(() => {
    if (workspaceId && window.location.hash === '#mcp-assistants') {
      document
        .getElementById('mcp-assistants')
        ?.scrollIntoView?.({ block: 'start' });
    }
  }, [workspaceId]);
  return workspaceId ? (
    <ConnectionsForWorkspace
      key={`${userId}:${workspaceId}`}
      workspaceId={workspaceId}
      userId={userId}
    />
  ) : null;
}
