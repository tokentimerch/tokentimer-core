import { useCallback, useRef, useState } from 'react';
import {
  Link as RouterLink,
  useOutletContext,
  useSearchParams,
} from 'react-router';
import {
  Alert,
  AlertIcon,
  AlertDialog,
  AlertDialogOverlay,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogBody,
  AlertDialogFooter,
  Badge,
  Box,
  Button,
  Checkbox,
  FormControl,
  FormLabel,
  HStack,
  Input,
  Link,
  Select,
  SimpleGrid,
  Stack,
  Table,
  TableContainer,
  Tbody,
  Td,
  Text,
  Th,
  Thead,
  Tr,
} from '@chakra-ui/react';
import {
  DashboardPanel,
  DashboardPanelHeader,
  DashboardState,
} from '../../components/DashboardPrimitives';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { useCertOpsCanManage } from '../../components/certops/useCertOps.js';
import useDistributionRead, {
  serverClockOffset,
} from '../../components/certops/useDistributionRead.js';
import { verificationDeadline } from '../../components/certops/distributionFormat.js';
import { distributionApi } from '../../components/certops/distributionApi.js';
import { diagnosticExplanation } from '../../components/certops/distributionDiagnostics.js';
import { formatDateTime } from '../../components/certops/certopsFormat.js';

const label = value => String(value || 'Unknown').replaceAll('_', ' ');
const jobsLink = (workspaceId, id) =>
  `/certops/jobs?workspace=${encodeURIComponent(workspaceId)}&job=${encodeURIComponent(id)}`;
function Field({ name, children }) {
  return (
    <FormControl>
      <FormLabel fontSize='sm'>{name}</FormLabel>
      {children}
    </FormControl>
  );
}
function NumberField({ name, value, onChange, min = 1, max = 604800 }) {
  return (
    <Field name={name}>
      <Input
        aria-label={name}
        type='number'
        min={min}
        max={max}
        value={value}
        onChange={event => onChange(Number(event.target.value))}
      />
    </Field>
  );
}
function JobLink({ workspaceId, id, children }) {
  return id ? (
    <Link as={RouterLink} to={jobsLink(workspaceId, id)} color='blue.500'>
      {children || 'View job'}
    </Link>
  ) : null;
}

function PolicyForm({ data, disabled, onSave }) {
  const [policy, setPolicy] = useState(() =>
    structuredClone(data.policy?.policy || data.defaults)
  );
  const set = (section, key, value) =>
    setPolicy(previous =>
      section
        ? { ...previous, [section]: { ...previous[section], [key]: value } }
        : { ...previous, [key]: value }
    );
  return (
    <Box
      as='form'
      onSubmit={event => {
        event.preventDefault();
        onSave(policy, data.policy?.revision || 0);
      }}
    >
      <Stack spacing={4}>
        <SimpleGrid columns={{ base: 1, md: 3 }} spacing={3}>
          <Field name='After publication'>
            <Select
              aria-label='After publication'
              value={policy.mode}
              onChange={event => set(null, 'mode', event.target.value)}
            >
              <option value='manual'>Manual rollout (default)</option>
              <option value='approval_request'>
                Request approval automatically
              </option>
              <option value='preauthorized'>Reviewed automatic rollout</option>
            </Select>
          </Field>
          <NumberField
            name='Maximum parallel deployments'
            value={policy.maxParallel}
            max={16}
            onChange={value => set(null, 'maxParallel', value)}
          />
          <Field name='Standing authorization expires (ISO time, maximum 30 days)'>
            <Input
              aria-label='Standing authorization expires'
              placeholder='2026-11-01T18:00:00Z'
              value={policy.authorizationExpiresAt || ''}
              onChange={event =>
                set(null, 'authorizationExpiresAt', event.target.value || null)
              }
            />
          </Field>
        </SimpleGrid>
        <Text fontSize='sm'>
          Reviewed automatic rollout creates a policy approval in Jobs. Changes
          to destinations, revisions, activation policy or workspace
          authorization invalidate that approval. Mandatory workspace approval
          still applies.
        </Text>
        <Checkbox
          isChecked={policy.verification.enabled}
          onChange={event =>
            set('verification', 'enabled', event.target.checked)
          }
        >
          Recurring verification
        </Checkbox>
        <SimpleGrid columns={{ base: 1, md: 3 }} spacing={3}>
          <NumberField
            name='Verification interval (seconds)'
            value={policy.verification.intervalSeconds}
            min={300}
            onChange={value => set('verification', 'intervalSeconds', value)}
          />
          <NumberField
            name='Maximum verification backoff (seconds)'
            value={policy.verification.maxBackoffSeconds}
            min={300}
            onChange={value => set('verification', 'maxBackoffSeconds', value)}
          />
          <NumberField
            name='Failure escalation threshold'
            value={policy.verification.failureThreshold}
            max={20}
            onChange={value => set('verification', 'failureThreshold', value)}
          />
        </SimpleGrid>
        <Checkbox
          isChecked={policy.alerts.enabled}
          onChange={event => set('alerts', 'enabled', event.target.checked)}
        >
          Distribution incidents and notifications
        </Checkbox>
        <SimpleGrid columns={{ base: 1, md: 3 }} spacing={3}>
          <NumberField
            name='Offline threshold (seconds)'
            value={policy.alerts.offlineSeconds}
            min={60}
            onChange={value => set('alerts', 'offlineSeconds', value)}
          />
          <NumberField
            name='Stuck rollout threshold (seconds)'
            value={policy.alerts.stuckSeconds}
            min={60}
            onChange={value => set('alerts', 'stuckSeconds', value)}
          />
          <NumberField
            name='Convergence deadline (seconds)'
            value={policy.alerts.convergenceSeconds}
            min={60}
            onChange={value => set('alerts', 'convergenceSeconds', value)}
          />
          <NumberField
            name='Deployed expiry warning (days)'
            value={policy.alerts.expiryWarningDays}
            min={0}
            max={90}
            onChange={value => set('alerts', 'expiryWarningDays', value)}
          />
          <NumberField
            name='Incident reminder interval (seconds)'
            value={policy.alerts.repeatSeconds}
            min={3600}
            onChange={value => set('alerts', 'repeatSeconds', value)}
          />
          <NumberField
            name='Stale verification job threshold (seconds)'
            value={policy.verification.staleJobSeconds}
            min={300}
            max={86400}
            onChange={value => set('verification', 'staleJobSeconds', value)}
          />
        </SimpleGrid>
        <Field name='Notification contact groups (workspace default when none selected)'>
          <Stack>
            {data.contactGroups?.map(group => (
              <Checkbox
                key={group.id}
                isChecked={policy.alerts.contactGroupIds.includes(group.id)}
                onChange={event =>
                  set(
                    'alerts',
                    'contactGroupIds',
                    event.target.checked
                      ? [...policy.alerts.contactGroupIds, group.id]
                      : policy.alerts.contactGroupIds.filter(
                          id => id !== group.id
                        )
                  )
                }
              >
                {group.name || group.id}
              </Checkbox>
            ))}
          </Stack>
        </Field>
        <Text fontSize='sm'>
          Email, webhooks and configured WhatsApp templates use existing channel
          delivery rules. Incidents resolve only after fresh consumer
          verification.
        </Text>
        <SimpleGrid columns={{ base: 1, md: 3 }} spacing={3}>
          <NumberField
            name='Minimum retention (seconds)'
            value={policy.retention.minimumSeconds}
            min={86400}
            max={315360000}
            onChange={value => set('retention', 'minimumSeconds', value)}
          />
          <NumberField
            name='Minimum retained versions'
            value={policy.retention.minimumVersions}
            min={2}
            max={1000}
            onChange={value => set('retention', 'minimumVersions', value)}
          />
          <NumberField
            name='Rollback preservation (seconds)'
            value={policy.retention.rollbackSeconds}
            min={86400}
            max={31536000}
            onChange={value => set('retention', 'rollbackSeconds', value)}
          />
        </SimpleGrid>
        <Text fontSize='sm'>
          Cleanup is report-only. Provider deletion is unavailable until its
          customer-side operation is qualified.
        </Text>
        <Button
          alignSelf='start'
          type='submit'
          colorScheme='blue'
          isDisabled={disabled}
        >
          Save distribution policy
        </Button>
      </Stack>
    </Box>
  );
}

function ConsumerForm({ consumer, agents, disabled, onSave, onCancel }) {
  const [binding, setBinding] = useState(() =>
    consumer
      ? {
          agentId: consumer.assigned_agent_id,
          deploymentProfileRef: consumer.deployment_profile_ref,
          profileRevision: consumer.profile_revision,
          required: consumer.required,
          wave: consumer.wave,
          verificationPolicy: consumer.verification_policy,
          freshnessSeconds: consumer.freshness_seconds,
          state: consumer.binding_state,
        }
      : {
          agentId: '',
          deploymentProfileRef: '',
          profileRevision: 1,
          required: true,
          wave: 0,
          verificationPolicy: 'served',
          freshnessSeconds: 3600,
          state: 'active',
        }
  );
  const set = (key, value) =>
    setBinding(previous => ({ ...previous, [key]: value }));
  return (
    <Box
      as='form'
      onSubmit={event => {
        event.preventDefault();
        onSave(consumer?.binding_id || crypto.randomUUID(), binding);
      }}
    >
      <Stack spacing={3}>
        <Text fontWeight='semibold'>
          {consumer ? 'Edit consumer' : 'Add consumer'}
        </Text>
        <SimpleGrid columns={{ base: 1, md: 3 }} spacing={3}>
          <Field name='Registered agent'>
            <Select
              aria-label='Registered agent'
              value={binding.agentId}
              onChange={event => set('agentId', event.target.value)}
              isRequired
            >
              <option value=''>Select agent</option>
              {agents.map(agent => (
                <option key={agent.id} value={agent.id}>
                  {agent.name || agent.hostname || agent.id} ({agent.status})
                </option>
              ))}
            </Select>
          </Field>
          <Field name='Customer-local deployment profile'>
            <Input
              aria-label='Customer-local deployment profile'
              value={binding.deploymentProfileRef}
              pattern='[A-Za-z0-9_-]{1,64}'
              isRequired
              onChange={event =>
                set('deploymentProfileRef', event.target.value)
              }
            />
          </Field>
          <NumberField
            name='Local profile revision'
            value={binding.profileRevision}
            max={2147483647}
            onChange={value => set('profileRevision', value)}
          />
          <NumberField
            name='Rollout wave (0 is canary)'
            value={binding.wave}
            min={0}
            max={1000}
            onChange={value => set('wave', value)}
          />
          <Field name='Verification assurance'>
            <Select
              aria-label='Verification assurance'
              value={binding.verificationPolicy}
              onChange={event => set('verificationPolicy', event.target.value)}
            >
              <option value='installed'>Installed files only</option>
              <option value='served'>Served certificate</option>
              <option value='trust'>Served and trusted</option>
            </Select>
          </Field>
          <NumberField
            name='Proof freshness (seconds)'
            value={binding.freshnessSeconds}
            min={60}
            onChange={value => set('freshnessSeconds', value)}
          />
        </SimpleGrid>
        <Checkbox
          isChecked={binding.required}
          onChange={event => set('required', event.target.checked)}
        >
          Required destination
        </Checkbox>
        <Checkbox
          isChecked={binding.state === 'active'}
          onChange={event =>
            set('state', event.target.checked ? 'active' : 'removed')
          }
        >
          Consumer enabled
        </Checkbox>
        <Text fontSize='sm'>
          The agent resolves paths, credentials, reload commands and probes from
          its approved local configuration. Reassignment is blocked while the
          previous agent has live or uncertain work.
        </Text>
        <HStack>
          <Button type='submit' isDisabled={disabled}>
            Save consumer
          </Button>
          <Button variant='ghost' onClick={onCancel}>
            Cancel
          </Button>
        </HStack>
      </Stack>
    </Box>
  );
}

function MaintenanceForm({ consumer, disabled, onSave, onCancel }) {
  const [policy, setPolicy] = useState(() =>
    structuredClone(
      consumer.activation_policy || {
        method:
          consumer.verification_policy === 'installed' ? 'none' : 'reload',
        disruptive: false,
        requiresApproval: false,
        timezone: 'UTC',
        windows: [],
        blackouts: [],
        validUntil: null,
        emergency: null,
      }
    )
  );
  const set = (key, value) =>
    setPolicy(previous => ({ ...previous, [key]: value }));
  const windowChange = (index, key, value) =>
    set(
      'windows',
      policy.windows.map((window, i) =>
        i === index ? { ...window, [key]: value } : window
      )
    );
  return (
    <Box
      as='form'
      onSubmit={event => {
        event.preventDefault();
        onSave(consumer, policy);
      }}
    >
      <Stack spacing={3}>
        <Text fontWeight='semibold'>
          Activation and maintenance: {consumer.deployment_profile_ref}
        </Text>
        <SimpleGrid columns={{ base: 1, md: 3 }} spacing={3}>
          <Field name='Activation method'>
            <Select
              aria-label='Activation method'
              value={policy.method}
              onChange={event => set('method', event.target.value)}
            >
              <option value='none'>None (installed files only)</option>
              <option value='reload'>Reload (Linux connector)</option>
              <option value='manual'>Manual activation</option>
              <option value='rebind' disabled>
                Rebind (connector unavailable)
              </option>
              <option value='no-restart-refresh' disabled>
                No-restart refresh (unavailable)
              </option>
              <option value='controlled-restart' disabled>
                Controlled restart (unavailable)
              </option>
            </Select>
          </Field>
          <Field name='IANA time zone'>
            <Input
              aria-label='IANA time zone'
              value={policy.timezone}
              onChange={event => set('timezone', event.target.value)}
            />
          </Field>
          <Field name='Activation authorization expires (ISO time)'>
            <Input
              aria-label='Activation authorization expires'
              value={policy.validUntil || ''}
              onChange={event => set('validUntil', event.target.value || null)}
            />
          </Field>
        </SimpleGrid>
        <Checkbox
          isChecked={policy.disruptive}
          onChange={event => set('disruptive', event.target.checked)}
        >
          Disruptive activation
        </Checkbox>
        <Checkbox
          isChecked={policy.requiresApproval}
          onChange={event => set('requiresApproval', event.target.checked)}
        >
          Require explicit rollout approval
        </Checkbox>
        {policy.windows.map((window, index) => (
          <Box key={index} borderWidth='1px' p={3} borderRadius='md'>
            <HStack flexWrap='wrap'>
              {['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map(
                (day, number) => (
                  <Checkbox
                    key={day}
                    isChecked={window.days.includes(number)}
                    onChange={event =>
                      windowChange(
                        index,
                        'days',
                        event.target.checked
                          ? [...window.days, number]
                          : window.days.filter(value => value !== number)
                      )
                    }
                  >
                    {day}
                  </Checkbox>
                )
              )}
            </HStack>
            <HStack mt={2}>
              <Input
                aria-label={`Window ${index + 1} start`}
                type='time'
                value={window.start}
                onChange={event =>
                  windowChange(index, 'start', event.target.value)
                }
              />
              <Input
                aria-label={`Window ${index + 1} end`}
                type='time'
                value={window.end}
                onChange={event =>
                  windowChange(index, 'end', event.target.value)
                }
              />
              <Button
                onClick={() =>
                  set(
                    'windows',
                    policy.windows.filter((_, i) => i !== index)
                  )
                }
              >
                Remove
              </Button>
            </HStack>
          </Box>
        ))}
        <Button
          alignSelf='start'
          onClick={() =>
            set('windows', [
              ...policy.windows,
              { days: [0], start: '01:00', end: '02:00' },
            ])
          }
        >
          Add allowed window
        </Button>
        {policy.blackouts.map((period, index) => (
          <HStack key={index}>
            <Input
              aria-label={`Blackout ${index + 1} start ISO`}
              placeholder='Start: 2026-11-01T00:00:00Z'
              value={period.start}
              onChange={event =>
                set(
                  'blackouts',
                  policy.blackouts.map((value, i) =>
                    i === index
                      ? { ...value, start: event.target.value }
                      : value
                  )
                )
              }
            />
            <Input
              aria-label={`Blackout ${index + 1} end ISO`}
              placeholder='End: 2026-11-02T00:00:00Z'
              value={period.end}
              onChange={event =>
                set(
                  'blackouts',
                  policy.blackouts.map((value, i) =>
                    i === index ? { ...value, end: event.target.value } : value
                  )
                )
              }
            />
            <Button
              onClick={() =>
                set(
                  'blackouts',
                  policy.blackouts.filter((_, i) => i !== index)
                )
              }
            >
              Remove
            </Button>
          </HStack>
        ))}
        <Button
          alignSelf='start'
          onClick={() =>
            set('blackouts', [...policy.blackouts, { start: '', end: '' }])
          }
        >
          Add blackout
        </Button>
        <Text fontSize='sm'>
          Blackouts take precedence. Disruptive activation needs an allowed
          window. Saving changes the authorization revision and requires a new
          rollout request. Publication can finish before activation is allowed.
        </Text>
        {policy.emergency ? (
          <Alert status='warning'>
            <AlertIcon />
            An administrator emergency authorization exists. Review its scope in
            audit evidence before replacing this policy.
          </Alert>
        ) : null}
        <HStack>
          <Button type='submit' isDisabled={disabled}>
            Save activation policy
          </Button>
          <Button variant='ghost' onClick={onCancel}>
            Cancel
          </Button>
        </HStack>
      </Stack>
    </Box>
  );
}

function Management({ workspaceId, groupId, canManage, paused }) {
  const read = useCallback(
    async (signal, startedAt) => {
      const data = await distributionApi.management(
        workspaceId,
        groupId,
        signal
      );
      const clockOffset = serverClockOffset(data, startedAt);
      return {
        ...data,
        clockOffset,
        deadlines: data.consumers
          .map(verificationDeadline)
          .filter(value => value !== null)
          .map(value => value + clockOffset),
      };
    },
    [workspaceId, groupId]
  );
  const state = useDistributionRead(`${workspaceId}/${groupId}`, read);
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(''),
    [notice, setNotice] = useState('');
  const [editor, setEditor] = useState(null),
    [maintenance, setMaintenance] = useState(null),
    [version, setVersion] = useState('');
  const [preflight, setPreflight] = useState(null),
    [retention, setRetention] = useState(null),
    [confirmation, setConfirmation] = useState(null);
  const cancelRef = useRef(null),
    keys = useRef(new Map());
  const { data } = state,
    disabled =
      busy ||
      Boolean(state.error) ||
      paused ||
      !canManage ||
      data?.group.state !== 'active' ||
      Boolean(data?.group.ended_at);
  const run = async (task, success) => {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const result = await task();
      setNotice(typeof success === 'function' ? success(result) : success);
      state.refresh();
      return result;
    } catch (failure) {
      setError(
        `${failure.response?.data?.error || 'Operation failed. Refresh the page, inspect the job and check customer-local policy.'}${failure.response?.data?.code ? ` (${failure.response.data.code})` : ''}`
      );
      return null;
    } finally {
      setBusy(false);
    }
  };
  if (state.loading)
    return (
      <DashboardState type='loading' title='Loading distribution management' />
    );
  if (!data)
    return (
      <DashboardState
        type='error'
        title='Distribution unavailable'
        description={state.error}
        action={<Button onClick={state.refresh}>Retry</Button>}
      />
    );
  const selectedVersion =
    version || data.group.latest_material_version_id || '';
  const retained = selectedVersion !== data.group.latest_material_version_id;
  const requestRollout = verificationOnly => {
    const signature = `${groupId}:${selectedVersion}:${verificationOnly}:${data.group.generation}`;
    if (!keys.current.has(signature))
      keys.current.set(signature, crypto.randomUUID());
    return run(
      () =>
        distributionApi.rollout(
          workspaceId,
          groupId,
          {
            materialVersionId: selectedVersion,
            maxParallel: data.policy?.policy.maxParallel || 1,
            verificationOnly,
            requiresApproval: !verificationOnly && retained,
          },
          keys.current.get(signature)
        ),
      result =>
        result.status === 'pending_approval'
          ? 'Request created. Review and approve the exact version in Jobs.'
          : 'Rollout requested. Consumer job evidence will confirm installation and verification.'
    );
  };
  const confirm = (title, description, action) =>
    setConfirmation({ title, description, action });
  return (
    <Stack spacing={4}>
      {state.error ? (
        <Alert status='warning'>
          <AlertIcon />
          Cached distribution data may be stale. Refresh before making changes.{' '}
          <Button size='sm' ml={2} onClick={state.refresh}>
            Retry
          </Button>
        </Alert>
      ) : null}
      {paused ? (
        <Alert status='warning'>
          <AlertIcon />
          Certificate operations are paused for this workspace.
        </Alert>
      ) : null}
      {error ? (
        <Alert status='error'>
          <AlertIcon />
          {error}
        </Alert>
      ) : null}
      {notice ? (
        <Alert status='info'>
          <AlertIcon />
          {notice}
        </Alert>
      ) : null}
      <DashboardPanel>
        <DashboardPanelHeader
          title='Publication and rollout'
          description={`Customer-local store: ${data.group.material_store_ref}. Publication does not prove service activation.`}
          action={
            <Button
              size='sm'
              onClick={state.refresh}
              isLoading={state.refreshing}
            >
              Refresh
            </Button>
          }
        />
        <Stack spacing={3}>
          <Text fontSize='sm'>
            Latest publication: {data.versions[0]?.state || 'Not published'} ·
            Evaluated {formatDateTime(data.evaluated_at)}
          </Text>
          <Field name='Exact published version'>
            <Select
              aria-label='Exact published version'
              value={selectedVersion}
              onChange={event => setVersion(event.target.value)}
            >
              <option value=''>Select version</option>
              {data.versions
                .filter(value => value.state === 'published')
                .map(value => (
                  <option key={value.id} value={value.id}>
                    {value.provider_version} · {value.id} · expires{' '}
                    {formatDateTime(value.valid_to)}
                    {value.id !== data.group.latest_material_version_id
                      ? ' (retained rollback version)'
                      : ''}
                  </option>
                ))}
            </Select>
          </Field>
          <Text fontSize='sm'>
            Destinations:{' '}
            {
              data.consumers.filter(value => value.binding_state === 'active')
                .length
            }
            . Canary waves and required destinations gate progression; maximum
            parallel deployments: {data.policy?.policy.maxParallel || 1}.
          </Text>
          {canManage ? (
            <HStack flexWrap='wrap'>
              <Button
                isDisabled={disabled || !selectedVersion}
                colorScheme='blue'
                onClick={() =>
                  confirm(
                    retained
                      ? 'Request retained-version rollback'
                      : 'Request certificate rollout',
                    `Authorize exact version ${selectedVersion} for the listed destinations. Disruptive activation follows its approved maintenance policy. Retained versions require explicit approval.`,
                    () => requestRollout(false)
                  )
                }
              >
                {retained ? 'Request rollback approval' : 'Request rollout'}
              </Button>
              <Button
                isDisabled={disabled || !selectedVersion}
                onClick={() => requestRollout(true)}
              >
                Verify only
              </Button>
            </HStack>
          ) : null}
          <Button
            alignSelf='start'
            isDisabled={busy}
            onClick={() =>
              run(async () => {
                const result = await distributionApi.preflight(
                  workspaceId,
                  groupId,
                  selectedVersion
                );
                setPreflight(result);
              }, 'Preflight checks loaded. Customer-local checks remain necessary.')
            }
          >
            Run safe preflight
          </Button>
          {preflight ? (
            <Box>
              <Text fontWeight='semibold'>Non-mutating preflight</Text>
              <Text fontSize='sm'>
                These checks cover control-plane metadata. Run the
                customer-local dry run to check store authorization, pinned
                material, filesystem permissions, service targets and probes.
              </Text>
              {preflight.consumers.map(value => (
                <Text key={value.bindingId} fontSize='sm'>
                  {value.bindingId}:{' '}
                  {value.diagnostics
                    .map(item => diagnosticExplanation(item.code))
                    .join('; ')}
                </Text>
              ))}
            </Box>
          ) : null}
        </Stack>
      </DashboardPanel>
      <DashboardPanel>
        <DashboardPanelHeader
          title='Consumers'
          description='Installed files, served identity, trust and proof freshness are separate evidence.'
          action={
            canManage ? (
              <Button
                size='sm'
                isDisabled={disabled}
                onClick={() => setEditor({})}
              >
                Add consumer
              </Button>
            ) : null
          }
        />
        {!data.consumers.length ? (
          <Text>
            No consumers configured. Add an agent destination after completing
            customer-local setup.
          </Text>
        ) : (
          <TableContainer>
            <Table size='sm'>
              <Thead>
                <Tr>
                  <Th>Consumer / agent</Th>
                  <Th>Status / versions</Th>
                  <Th>Proof / deployed expiry</Th>
                  <Th>Policy</Th>
                  <Th>Actions</Th>
                </Tr>
              </Thead>
              <Tbody>
                {data.consumers.map(consumer => (
                  <Tr key={consumer.binding_id}>
                    <Td>
                      {consumer.deployment_profile_ref}
                      <Text fontSize='xs'>
                        {consumer.agent_name} · {consumer.agent_status}
                      </Text>
                      <Text fontSize='xs'>{consumer.binding_state}</Text>
                    </Td>
                    <Td>
                      <Badge>
                        {label(
                          state.error
                            ? 'stale_data'
                            : [
                                  'up_to_date_fresh',
                                  'installed_not_proven_served',
                                ].includes(consumer.health_status) &&
                                (verificationDeadline(consumer) === null ||
                                  verificationDeadline(consumer) +
                                    data.clockOffset <=
                                    state.now)
                              ? 'verification_overdue'
                              : consumer.health_status
                        )}
                      </Badge>
                      {consumer.latest_deployment?.jobStatus ===
                      'pending_approval' ? (
                        <Badge colorScheme='purple' ml={1}>
                          Approval pending
                        </Badge>
                      ) : null}
                      <Text fontSize='xs'>
                        Desired {consumer.desired_version || 'Unknown'} /
                        observed {consumer.observed_version || 'Unknown'}
                      </Text>
                    </Td>
                    <Td>
                      {label(consumer.verification_method)}
                      <Text fontSize='xs'>
                        Proof {formatDateTime(consumer.observed_at)}
                      </Text>
                      <Text fontSize='xs'>
                        Deployed expiry{' '}
                        {formatDateTime(consumer.observed_valid_to)}
                      </Text>
                    </Td>
                    <Td>
                      {consumer.required ? 'Required' : 'Optional'} · wave{' '}
                      {consumer.wave}
                      <Text fontSize='xs'>
                        Authorization revision {consumer.authorization_revision}{' '}
                        / local profile {consumer.profile_revision}
                      </Text>
                    </Td>
                    <Td>
                      <Stack align='start' spacing={1}>
                        <JobLink
                          workspaceId={workspaceId}
                          id={consumer.latest_deployment?.jobId}
                        />
                        {canManage ? (
                          <>
                            <Button
                              size='xs'
                              isDisabled={disabled}
                              onClick={() => setEditor(consumer)}
                            >
                              Edit consumer
                            </Button>
                            <Button
                              size='xs'
                              isDisabled={disabled}
                              onClick={() => setMaintenance(consumer)}
                            >
                              Maintenance
                            </Button>
                            {[
                              'failed',
                              'blocked',
                              'orphaned_unknown_effect',
                            ].includes(
                              consumer.latest_deployment?.jobStatus
                            ) ? (
                              <Button
                                size='xs'
                                isDisabled={disabled}
                                onClick={() =>
                                  confirm(
                                    'Retry original signed job',
                                    'Inspect job evidence and run preflight. Reconcile on the customer host before retrying an uncertain operation. The original version, generation and approval stay pinned.',
                                    () =>
                                      run(
                                        () =>
                                          distributionApi.retry(
                                            workspaceId,
                                            consumer.latest_deployment.jobId
                                          ),
                                        'Original job retry requested. Resume the rollout after reconciliation, then obtain fresh verification.'
                                      )
                                  )
                                }
                              >
                                Retry original job
                              </Button>
                            ) : null}
                          </>
                        ) : null}
                      </Stack>
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          </TableContainer>
        )}
        {editor ? (
          <Box mt={4}>
            <ConsumerForm
              key={editor.binding_id || 'new'}
              consumer={editor.binding_id ? editor : null}
              agents={data.agents || []}
              disabled={disabled}
              onCancel={() => setEditor(null)}
              onSave={(id, binding) =>
                run(async () => {
                  await distributionApi.consumer(
                    workspaceId,
                    groupId,
                    id,
                    binding
                  );
                  setEditor(null);
                }, 'Consumer saved. Approvals and customer-local authorization must use the new revision.')
              }
            />
          </Box>
        ) : null}
        {maintenance ? (
          <Box mt={4}>
            <MaintenanceForm
              key={`${maintenance.binding_id}/${maintenance.authorization_revision}`}
              consumer={maintenance}
              disabled={disabled}
              onCancel={() => setMaintenance(null)}
              onSave={(consumer, policy) =>
                run(async () => {
                  await distributionApi.activation(
                    workspaceId,
                    groupId,
                    consumer.binding_id,
                    policy,
                    consumer.authorization_revision
                  );
                  setMaintenance(null);
                }, 'Activation policy saved. Request a fresh rollout approval.')
              }
            />
          </Box>
        ) : null}
      </DashboardPanel>
      <DashboardPanel>
        <DashboardPanelHeader
          title='Rollouts and approvals'
          description='A request or approval is distinct from completed consumer verification.'
        />
        {!data.rollouts.length ? (
          <Text>No rollouts yet.</Text>
        ) : (
          <Stack spacing={3}>
            {data.rollouts.map(rollout => (
              <HStack key={rollout.id} flexWrap='wrap'>
                <Badge>{rollout.state}</Badge>
                <Text fontSize='sm'>
                  Generation {rollout.generation} ·{' '}
                  {rollout.verification_only
                    ? 'Verification only'
                    : 'Deployment'}
                </Text>
                <JobLink
                  workspaceId={workspaceId}
                  id={rollout.approval_job_id}
                />
                {canManage &&
                ['pending', 'deploying', 'paused'].includes(rollout.state) ? (
                  <Button
                    size='xs'
                    isDisabled={
                      busy ||
                      Boolean(state.error) ||
                      (rollout.state === 'paused' && paused)
                    }
                    onClick={() =>
                      confirm(
                        rollout.state === 'paused'
                          ? 'Resume rollout'
                          : 'Pause rollout',
                        'Resuming revalidates current revisions, generation, policy and maintenance authorization.',
                        () =>
                          run(
                            () =>
                              distributionApi.state(
                                workspaceId,
                                groupId,
                                rollout.id,
                                rollout.state === 'paused'
                                  ? 'deploying'
                                  : 'paused'
                              ),
                            'Rollout state updated.'
                          )
                      )
                    }
                  >
                    {rollout.state === 'paused' ? 'Resume' : 'Pause'}
                  </Button>
                ) : null}
              </HStack>
            ))}
          </Stack>
        )}
        {data.approvals
          .filter(job => job.status === 'pending_approval')
          .map(job => (
            <Text key={job.id} fontSize='sm' mt={2}>
              Pending approval:{' '}
              <JobLink workspaceId={workspaceId} id={job.id}>
                Review exact intent in Jobs
              </JobLink>
            </Text>
          ))}
      </DashboardPanel>
      <DashboardPanel>
        <DashboardPanelHeader
          title='Automation, verification and alert policy'
          description={`Policy revision ${data.policy?.revision || 0}. Authority: ${label(data.authorization?.state || data.policy?.policy.mode || 'manual')}. Recurring verification: ${label(data.schedule?.last_outcome || 'disabled')}.`}
        />
        {data.policy?.approval_job_id ? (
          <Text mb={3}>
            Standing authorization:{' '}
            <JobLink workspaceId={workspaceId} id={data.policy.approval_job_id}>
              Review policy approval in Jobs
            </JobLink>
          </Text>
        ) : null}
        {canManage ? (
          <PolicyForm
            key={`${groupId}/${data.policy?.revision || 0}`}
            data={data}
            disabled={disabled}
            onSave={(policy, revision) =>
              run(
                () =>
                  distributionApi.policy(
                    workspaceId,
                    groupId,
                    policy,
                    revision
                  ),
                'Distribution policy saved. Review any pending policy approval in Jobs.'
              )
            }
          />
        ) : (
          <Text>
            Mode: {label(data.policy?.policy.mode || 'manual')}. A workspace
            manager can configure automation and maintenance.
          </Text>
        )}
      </DashboardPanel>
      <DashboardPanel>
        <DashboardPanelHeader
          title='Incidents and recovery'
          description='Source renewal cannot resolve a consumer incident. Fresh evidence must prove the relevant condition cleared.'
        />
        {!data.incidents.length ? (
          <Text>No distribution incidents recorded.</Text>
        ) : (
          <Stack spacing={2}>
            {data.incidents.map(incident => (
              <Box key={incident.id}>
                <Badge colorScheme={incident.resolved_at ? 'green' : 'orange'}>
                  {incident.resolved_at ? 'Resolved' : 'Open'}
                </Badge>{' '}
                {label(incident.code)}
                <Text fontSize='xs'>
                  Opened {formatDateTime(incident.opened_at)} · updated{' '}
                  {formatDateTime(incident.updated_at)}
                </Text>
                <JobLink
                  workspaceId={workspaceId}
                  id={incident.evidence?.jobId}
                />
              </Box>
            ))}
          </Stack>
        )}
        <Text mt={3} fontSize='sm'>
          Recovery: inspect the affected job and public evidence; run preflight;
          reconcile locally without stealing a live lock; retry the original
          signed job; resume when authorized; obtain fresh consumer
          verification.
        </Text>
      </DashboardPanel>
      <DashboardPanel>
        <DashboardPanelHeader
          title='Discovery coverage'
          description='Coverage is partial. A certificate in a machine store does not establish that every service has been discovered.'
        />
        {!data.discoveries.length ? (
          <Text>
            No matching service relationships observed. Configured consumers
            remain visible above; unknown coverage is not healthy coverage.
          </Text>
        ) : (
          data.discoveries.map(service => (
            <Text key={service.id} fontSize='sm'>
              {service.source_kind}: {service.service_identity} ·{' '}
              {label(service.confidence)} · last observed{' '}
              {formatDateTime(service.last_observed_at)}
            </Text>
          ))
        )}
        <Text mt={2} fontSize='sm'>
          Linux file installation and allowlisted reload are supported.
          Additional Windows shared-material connectors require their merged
          extension and protected qualification.
        </Text>
      </DashboardPanel>
      <DashboardPanel>
        <DashboardPanelHeader
          title='Retention and cleanup preview'
          description='Referenced material, pending approvals, paused rollouts and uncertain operations remain protected.'
        />
        <Button
          size='sm'
          isDisabled={busy}
          onClick={() =>
            run(async () => {
              setRetention(
                await distributionApi.retention(workspaceId, groupId)
              );
            }, 'Retention preview loaded. No material was deleted.')
          }
        >
          Preview retained versions
        </Button>
        {retention ? (
          <Stack mt={3} spacing={2}>
            <Text fontSize='sm'>
              Report-only. Destructive cleanup is unavailable for this build.
            </Text>
            {retention.versions.map(value => (
              <Text key={value.id} fontSize='sm'>
                Version {value.provider_version || value.id}:{' '}
                {value.retainedReasons.length
                  ? value.retainedReasons.map(label).join(', ')
                  : 'Metadata eligible; cleanup authorization and provider qualification still required'}
              </Text>
            ))}
          </Stack>
        ) : null}
      </DashboardPanel>
      <AlertDialog
        isOpen={Boolean(confirmation)}
        leastDestructiveRef={cancelRef}
        onClose={() => setConfirmation(null)}
      >
        <AlertDialogOverlay />
        <AlertDialogContent>
          <AlertDialogHeader>{confirmation?.title}</AlertDialogHeader>
          <AlertDialogBody>{confirmation?.description}</AlertDialogBody>
          <AlertDialogFooter>
            <Button ref={cancelRef} onClick={() => setConfirmation(null)}>
              Cancel
            </Button>
            <Button
              ml={3}
              colorScheme='blue'
              onClick={() => {
                const { action } = confirmation;
                setConfirmation(null);
                action();
              }}
            >
              Confirm
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Stack>
  );
}

export default function CertOpsDistribution() {
  const { workspaceId } = useWorkspace(),
    canManage = useCertOpsCanManage(),
    { certOpsPaused } = useOutletContext() || {};
  const [params, setParams] = useSearchParams();
  const read = useCallback(
    signal => distributionApi.groups(workspaceId, signal),
    [workspaceId]
  );
  const state = useDistributionRead(
    workspaceId ? `distribution-groups/${workspaceId}` : null,
    read
  );
  const groups = state.data?.groups || [],
    groupId = groups.some(group => group.id === params.get('group'))
      ? params.get('group')
      : groups[0]?.id;
  return (
    <Stack spacing={4}>
      <DashboardPanel>
        <DashboardPanelHeader
          title='Distribution Management'
          description='Configure destinations, coordinate approved activation and monitor consumer evidence.'
        />
        <Link as={RouterLink} to='/onboarding?area=certops' color='blue.500'>
          Open first-distribution setup guide
        </Link>
        <Text fontSize='sm' mt={2}>
          Shared private keys require explicit opt-in in the setup guide. Store
          credentials remain on customer agents. Enter only store and deployment
          profile aliases here.
        </Text>
        {groups.length ? (
          <Field name='Distribution source'>
            <Select
              aria-label='Distribution source'
              value={groupId}
              onChange={event =>
                setParams(previous => {
                  const next = new URLSearchParams(previous);
                  next.set('group', event.target.value);
                  return next;
                })
              }
            >
              {groups.map(group => (
                <option key={group.id} value={group.id}>
                  {group.material_store_ref} · {group.id} ({group.state})
                </option>
              ))}
            </Select>
          </Field>
        ) : null}
      </DashboardPanel>
      {state.loading ? (
        <DashboardState type='loading' title='Loading distribution sources' />
      ) : state.error ? (
        <DashboardState
          type='error'
          title='Distribution sources unavailable'
          action={<Button onClick={state.refresh}>Retry</Button>}
        />
      ) : !groups.length ? (
        <DashboardState
          title='No distribution sources configured'
          description='Complete the first-distribution setup guide to publish into a customer-controlled store.'
        />
      ) : (
        <Management
          key={`${workspaceId}/${groupId}`}
          workspaceId={workspaceId}
          groupId={groupId}
          canManage={canManage}
          paused={Boolean(certOpsPaused)}
        />
      )}
    </Stack>
  );
}
