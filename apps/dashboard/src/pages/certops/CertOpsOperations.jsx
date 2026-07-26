import { useEffect, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Box,
  Button,
  ButtonGroup,
  Checkbox,
  Collapse,
  FormControl,
  FormHelperText,
  FormLabel,
  HStack,
  Icon,
  Input,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalContent,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Select,
  SimpleGrid,
  Text,
  Textarea,
  VStack,
  useColorModeValue,
} from '@chakra-ui/react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import CopyableId from '../../components/CopyableId.jsx';
import DashboardShell from '../../components/DashboardShell';
import { useDashboardShellProps } from '../../hooks/useDashboardShellProps';
import SEO from '../../components/SEO.jsx';
import ApiTokenPanel from '../../components/certops/ApiTokenPanel.jsx';
import AgentFleetPanel from '../../components/certops/AgentFleetPanel.jsx';
import DeployAgentPanel from '../../components/certops/DeployAgentPanel.jsx';
import WorkspaceKillSwitchPanel from '../../components/certops/WorkspaceKillSwitchPanel.jsx';
import EvidenceTimeline from '../../components/certops/EvidenceTimeline.jsx';
import JobStatusBadge from '../../components/certops/JobStatusBadge.jsx';
import {
  CERTOPS_JOB_OPERATIONS,
  CERTOPS_SUBJECT_TYPES,
  approveJob,
  createJob,
  rejectJob,
} from '../../components/certops/certopsJobsApi.js';
import {
  listCertificates,
  listCertificateTargets,
  listWorkspaceCertificateInstances,
} from '../../components/certops/certopsApi.js';
import {
  formatDateTime,
  formatRelativeDateTime,
  jobOperationLabel,
  subjectTypeLabel,
  truncateId,
} from '../../components/certops/certopsJobsFormat';
import {
  useCertOpsAvailability,
  useCertOpsCanManage,
} from '../../components/certops/useCertOps.js';
import { useCertOpsJobs } from '../../components/certops/useCertOpsJobs.js';
import { useCertOpsAgents } from '../../components/certops/useCertOpsAgents.js';
import { truncationSummary } from '../../components/certops/certopsPagination.js';
import {
  DashboardActionButton,
  DashboardPanel,
  DashboardPanelHeader,
  DashboardState,
} from '../../components/DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { showError, showSuccess } from '../../utils/toast.js';

const JOB_LIST_LIMIT = 20;
const SUBJECT_ID_MAX_LENGTH = 128;
const MANUAL_JOB_SUBJECT_SUGGESTIONS_LIST_ID =
  'certops-manual-job-subject-suggestions';

// Manual jobs are an exception path for driving certificate operations
// (renew/deploy/reload/revoke); "token" is declared in the shared
// CERTOPS_SUBJECT_TYPES enum for future use but nothing in the job/executor
// pipeline acts on it today (see apps/api/services/certops/jobs.js), so it's
// hidden here to avoid implying it triggers real automation. The remaining
// non-certificate types (domain, endpoint, external) stay available for
// manual audit trail jobs even though they're free text.
const MANUAL_JOB_SUBJECT_TYPES = CERTOPS_SUBJECT_TYPES.filter(
  type => type !== 'token'
);

// Per-subject-type hint for the free-text Subject ID input; shown for every
// subject type, whether or not a live suggestion list is available below.
const SUBJECT_ID_PLACEHOLDERS = {
  managed_certificate: 'e.g. a managed certificate ID',
  certificate_instance: 'e.g. a certificate instance ID',
  certificate_target: 'e.g. a certificate target ID',
  domain: 'e.g. example.com',
  endpoint: 'e.g. https://example.com or host:port',
  external: 'e.g. a reference from an external system',
};
const DEFAULT_SUBJECT_ID_PLACEHOLDER = 'e.g. a managed certificate ID';

// Subject types that are always free-text/manual references (a human typed
// them in, or they came from an external system): a job against one of
// these can never be claimed by an agent (agents only match against
// declared target selectors, which are certificate/instance/target-backed),
// so pinning an agent to them would be misleading and is hidden.
const MANUAL_ONLY_SUBJECT_TYPES = ['domain', 'endpoint', 'external'];

// Mirrors SUBJECT_REQUIRED_OPERATIONS in
// apps/api/services/certops/jobs.js: these operations act on an existing
// entity, so the API rejects them without a subjectType/subjectId pair.
// "issue" forbids a subject (nothing exists yet) and "noop" stays optional.
const SUBJECT_REQUIRED_OPERATIONS = new Set([
  'renew',
  'deploy',
  'reload',
  'revoke',
]);

// Shown as the JSON textarea's placeholder for both "issue" (where these
// keys are required) and every other operation (where they're optional but
// this is still the shape a renew/deploy/reload job reads), so switching
// to JSON mode never loses the example that guided the structured fields.
const PAYLOAD_JSON_EXAMPLE = `{
  "target": { "type": "domain", "reference": "example.com" },
  "sans": ["example.com"],
  "commandRef": "certbot-csr",
  "caEndpoint": "https://acme-v02.api.letsencrypt.org/directory",
  "dnsZone": "example.com",
  "dnsProvider": "cloudflare",
  "certPath": "/etc/ssl/example/example.com.pem"
}`;

// Only subject types backed by an existing, workspace-scoped list endpoint
// get live suggestions; the rest (domain, endpoint, external) stay a plain
// text input by design, since they're free-form references.
const SUBJECT_ID_SUGGESTION_LOADERS = {
  managed_certificate: async (workspaceId, { signal } = {}) => {
    const data = await listCertificates(workspaceId, { limit: 100, signal });
    const items = Array.isArray(data?.items) ? data.items : [];
    return items.map(cert => ({
      id: cert.id,
      label: cert.commonName
        ? `${cert.commonName} (${truncateId(cert.id)})`
        : cert.id,
    }));
  },
  certificate_target: async (workspaceId, { signal } = {}) => {
    const data = await listCertificateTargets(workspaceId, {
      limit: 100,
      signal,
    });
    const items = Array.isArray(data?.items) ? data.items : [];
    return items.map(target => ({
      id: target.id,
      label: target.name
        ? `${target.name} (${truncateId(target.id)})`
        : target.id,
    }));
  },
  certificate_instance: async (workspaceId, { signal } = {}) => {
    const data = await listWorkspaceCertificateInstances(workspaceId, {
      limit: 100,
      signal,
    });
    const items = Array.isArray(data?.items) ? data.items : [];
    return items.map(instance => ({
      id: instance.id,
      label: instance.observedSubject
        ? `${instance.observedSubject} (${truncateId(instance.id)})`
        : instance.id,
    }));
  },
};

/**
 * Agent selector label: `name` (an operator-chosen label set at install
 * time, see the agent-configuration doc) when present, otherwise
 * `hostname`. Always appends the full, untruncated `agentId` in
 * parentheses: multiple agents can run on the same host (e.g. one per
 * environment or one per certificate domain) and share the same
 * name/hostname, and the part of a default `candidate-<hostname>-<pid>` id
 * that actually disambiguates them is the pid at the *end*, not the start,
 * so this deliberately does not truncate it the way short-id displays
 * elsewhere in the app do (a native <select>'s options aren't clipped the
 * way a table cell is, so there's no layout reason to shorten it).
 */
function agentSelectLabel(agent) {
  const id = agent?.agentId || agent?.id || '';
  const primary = agent?.name || agent?.hostname || id || 'Unnamed agent';
  const idSuffix = primary === id || !id ? '' : ` (${id})`;
  const offlineSuffix = agent?.status === 'offline' ? ' (offline)' : '';
  return `${primary}${idSuffix}${offlineSuffix}`;
}

function createJobErrorMessage(err) {
  const code = err?.response?.data?.code;
  const status = err?.response?.status;
  if (status === 403 || code === 'INSUFFICIENT_ROLE') {
    return 'You need workspace manager permission to create a job.';
  }
  if (code === 'PRIVATE_KEY_MATERIAL_REJECTED') {
    return 'Private key or secret material is not accepted in job fields.';
  }
  if (code === 'CERTOPS_JOB_IDEMPOTENCY_CONFLICT') {
    return 'This idempotency key was already used with different job details.';
  }
  return err?.response?.data?.error || err?.message || 'Could not create job.';
}

/**
 * Maps approve/reject failures to a message that explains the specific
 * gate that fired (see docs/certops's approvals guide: the non-requester
 * rule only applies to approve, and a job can legitimately race out of
 * pending_approval before the decision lands).
 */
function approvalDecisionErrorMessage(err, decision) {
  const code = err?.response?.data?.code;
  const status = err?.response?.status;
  if (code === 'CERTOPS_APPROVAL_SELF_APPROVAL_FORBIDDEN') {
    return 'You requested this job, so you cannot approve it yourself. Ask another workspace manager or admin to review it.';
  }
  if (code === 'CERTOPS_APPROVAL_JOB_NOT_PENDING_APPROVAL') {
    return 'This job already left "Pending approval" (someone else may have just decided it). Refreshing the list.';
  }
  if (status === 403 || code === 'INSUFFICIENT_ROLE') {
    return `You need workspace manager permission to ${decision} a job.`;
  }
  return (
    err?.response?.data?.error ||
    err?.message ||
    `Could not ${decision} this job.`
  );
}

/**
 * Manual job creation modal: the exception path for creating
 * a CertOps job before the certops-scheduler exists. Always posts with
 * source "api"; the server never accepts a client-supplied source.
 */
function CreateManualJobModal({ isOpen, onClose, onCreated }) {
  const { workspaceId } = useWorkspace();
  const { agents } = useCertOpsAgents();
  const [operation, setOperation] = useState('');
  const [subjectType, setSubjectType] = useState('');
  const [subjectId, setSubjectId] = useState('');
  const [idempotencyKey, setIdempotencyKey] = useState('');
  const [assignedAgentId, setAssignedAgentId] = useState('');
  const [payloadMode, setPayloadMode] = useState('fields');
  const [payloadText, setPayloadText] = useState('');
  const [payloadError, setPayloadError] = useState('');
  const [fieldTarget, setFieldTarget] = useState('');
  const [fieldSans, setFieldSans] = useState('');
  const [fieldCommandRef, setFieldCommandRef] = useState('');
  const [fieldCaEndpoint, setFieldCaEndpoint] = useState('');
  const [fieldDnsZone, setFieldDnsZone] = useState('');
  const [fieldDnsProvider, setFieldDnsProvider] = useState('');
  const [fieldCertPath, setFieldCertPath] = useState('');
  const [requiresApproval, setRequiresApproval] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [subjectSuggestions, setSubjectSuggestions] = useState([]);

  // "issue" has no existing subject to act on (ADR-0008): the control
  // plane creates the managed_certificate row itself, so passing
  // subjectType/subjectId is a validation error. idempotencyKey is
  // mandatory on issue because the request has a side effect beyond the
  // job (the new inventory row) and must not be duplicated by a retry.
  const isIssue = operation === 'issue';

  // renew/deploy/reload/revoke always act on something that already
  // exists, so the API requires subjectType+subjectId for these (see
  // SUBJECT_REQUIRED_OPERATIONS in services/certops/jobs.js). noop is the
  // only other operation that stays optional, since it exists purely to
  // exercise the pipeline without a real target.
  const subjectRequiredForOperation = SUBJECT_REQUIRED_OPERATIONS.has(operation);

  // Only agents that can still be handed a job: a retired agent can never
  // claim anything, so pinning to one would silently strand the job.
  const assignableAgents = agents.filter(agent => agent.status !== 'retired');

  // domain/endpoint/external subjects are free-text references an agent
  // can never match against (see MANUAL_ONLY_SUBJECT_TYPES above), so the
  // pin-to-agent control would imply a capability that doesn't exist here.
  const hidesAgentField =
    !isIssue && MANUAL_ONLY_SUBJECT_TYPES.includes(subjectType);

  // Clears a stale pin left over from a previous subjectType selection so a
  // hidden field can never silently submit a leftover assignedAgentId.
  useEffect(() => {
    if (hidesAgentField) setAssignedAgentId('');
  }, [hidesAgentField]);

  const resetForm = () => {
    setOperation('');
    setSubjectType('');
    setSubjectId('');
    setIdempotencyKey('');
    setAssignedAgentId('');
    setPayloadMode('fields');
    setPayloadText('');
    setPayloadError('');
    setFieldTarget('');
    setFieldSans('');
    setFieldCommandRef('');
    setFieldCaEndpoint('');
    setFieldDnsZone('');
    setFieldDnsProvider('');
    setFieldCertPath('');
    setRequiresApproval(false);
    setSubjectSuggestions([]);
  };

  const handleClose = () => {
    if (submitting) return;
    resetForm();
    onClose();
  };

  // Suggestions adapt to the selected subject type: each type with an
  // existing workspace-scoped list endpoint gets its own loader (see
  // SUBJECT_ID_SUGGESTION_LOADERS above); types without one (domain,
  // endpoint, external, certificate_instance, certificate_target) stay a
  // plain, unassisted text input. Loaded lazily, once per subject-type
  // change, native datalist, same pattern as the workspace-contacts
  // suggestions in TokenDetailModal.jsx.
  useEffect(() => {
    setSubjectSuggestions([]);
    const loadSuggestions = SUBJECT_ID_SUGGESTION_LOADERS[subjectType];
    if (!isOpen || !loadSuggestions || !workspaceId) return undefined;
    let cancelled = false;
    const controller = new AbortController();
    loadSuggestions(workspaceId, { signal: controller.signal })
      .then(items => {
        if (!cancelled) setSubjectSuggestions(items);
      })
      .catch(() => {
        // Suggestions are a convenience, not a requirement: a failed fetch
        // just leaves the field as a plain, unassisted text input.
      });
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [isOpen, subjectType, workspaceId]);

  const subjectPairComplete =
    (!subjectType || Boolean(subjectId.trim())) &&
    (!subjectId.trim() || Boolean(subjectType)) &&
    (!subjectRequiredForOperation || Boolean(subjectType && subjectId.trim()));

  const fieldsRequiredForIssueMet =
    payloadMode !== 'fields' ||
    !isIssue ||
    Boolean(
      fieldTarget.trim() &&
        fieldCommandRef.trim() &&
        fieldCaEndpoint.trim() &&
        fieldDnsZone.trim() &&
        fieldDnsProvider.trim() &&
        fieldCertPath.trim()
    );

  const canSubmit =
    Boolean(operation) &&
    Boolean(workspaceId) &&
    !submitting &&
    fieldsRequiredForIssueMet &&
    (isIssue
      ? Boolean(idempotencyKey.trim()) &&
        (payloadMode === 'fields' || !payloadError)
      : subjectPairComplete && (payloadMode === 'fields' || !payloadError));

  const handlePayloadChange = event => {
    const text = event.target.value;
    setPayloadText(text);
    if (!text.trim()) {
      setPayloadError('');
      return;
    }
    try {
      JSON.parse(text);
      setPayloadError('');
    } catch {
      setPayloadError('Payload must be valid JSON.');
    }
  };

  // Structured fields cover the common execution payload shape (target,
  // SANs, ACME command/CA, DNS-01 zone/provider, deploy path) so an operator
  // does not have to hand-write JSON for the everyday case; the JSON
  // textarea stays available for anything the fields do not cover (custom
  // metadata, less common execution keys, etc).
  const buildFieldsPayload = () => {
    const payload = {};
    if (fieldTarget.trim()) {
      payload.target = { type: 'domain', reference: fieldTarget.trim() };
    }
    const sans = fieldSans
      .split(/[\n,]+/)
      .map(value => value.trim())
      .filter(Boolean);
    if (sans.length) payload.sans = sans;
    if (fieldCommandRef.trim()) payload.commandRef = fieldCommandRef.trim();
    if (fieldCaEndpoint.trim()) payload.caEndpoint = fieldCaEndpoint.trim();
    if (fieldDnsZone.trim()) payload.dnsZone = fieldDnsZone.trim();
    if (fieldDnsProvider.trim()) payload.dnsProvider = fieldDnsProvider.trim();
    if (fieldCertPath.trim()) payload.certPath = fieldCertPath.trim();
    return payload;
  };

  const handleOperationChange = event => {
    const nextOperation = event.target.value;
    setOperation(nextOperation);
    if (nextOperation === 'issue') {
      // A subject on issue is a validation error (ADR-0008): the
      // certificate does not exist yet, so there is nothing to point at.
      setSubjectType('');
      setSubjectId('');
    }
  };

  const handleSubmit = async () => {
    if (!canSubmit) return;
    setSubmitting(true);
    try {
      const body = { operation };
      if (!isIssue && subjectType) body.subjectType = subjectType;
      if (!isIssue && subjectId.trim()) body.subjectId = subjectId.trim();
      if (idempotencyKey.trim()) body.idempotencyKey = idempotencyKey.trim();
      if (assignedAgentId) body.assignedAgentId = assignedAgentId;
      const payload =
        payloadMode === 'fields' ? buildFieldsPayload() : JSON.parse(payloadText || '{}');
      if (Object.keys(payload).length) body.payload = payload;
      if (requiresApproval) body.requiresApproval = true;
      const { job } = await createJob(workspaceId, body);
      showSuccess(
        'Job created',
        job?.id
          ? requiresApproval
            ? `Job ID: ${truncateId(job.id)} (awaiting approval)`
            : `Job ID: ${truncateId(job.id)}`
          : undefined
      );
      resetForm();
      onClose();
      onCreated?.();
    } catch (err) {
      showError('Create failed', createJobErrorMessage(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={handleClose} isCentered size='lg'>
      <ModalOverlay />
      <ModalContent>
        <ModalHeader>Create manual job</ModalHeader>
        <ModalCloseButton isDisabled={submitting} />
        <ModalBody>
          <VStack align='stretch' spacing={4}>
            <Alert status='info' variant='subtle' borderRadius='md'>
              <AlertIcon boxSize={4} />
              <AlertDescription fontSize='sm'>
                Manual job creation is an exception path for driving certificate
                operations before automated scheduling ships. The job is
                recorded with source &quot;api&quot; and appears at the start of
                the job&apos;s history.
              </AlertDescription>
            </Alert>
            <FormControl isRequired>
              <FormLabel fontSize='sm'>Operation</FormLabel>
              <Select
                size='sm'
                placeholder='Select an operation'
                value={operation}
                onChange={handleOperationChange}
              >
                {CERTOPS_JOB_OPERATIONS.map(op => (
                  <option key={op} value={op}>
                    {jobOperationLabel(op)}
                  </option>
                ))}
              </Select>
              {isIssue ? (
                <FormHelperText>
                  Issue creates a new managed certificate; TokenTimer assigns
                  its ID once the request is accepted, so subject fields
                  below are hidden.
                </FormHelperText>
              ) : null}
            </FormControl>
            {isIssue ? null : (
              <>
                <FormControl
                  isRequired={subjectRequiredForOperation || Boolean(subjectId.trim())}
                >
                  <FormLabel fontSize='sm'>Subject type</FormLabel>
                  <Select
                    size='sm'
                    placeholder='No subject'
                    value={subjectType}
                    onChange={event => {
                      setSubjectType(event.target.value);
                      setSubjectId('');
                    }}
                  >
                    {MANUAL_JOB_SUBJECT_TYPES.map(type => (
                      <option key={type} value={type}>
                        {subjectTypeLabel(type)}
                      </option>
                    ))}
                  </Select>
                  <FormHelperText>
                    {subjectRequiredForOperation
                      ? 'Required for this operation, together with subject ID.'
                      : 'Required together with subject ID, or leave both empty.'}
                  </FormHelperText>
                </FormControl>
                <FormControl
                  isRequired={subjectRequiredForOperation || Boolean(subjectType)}
                >
                  <FormLabel fontSize='sm'>Subject ID</FormLabel>
                  <Input
                    size='sm'
                    value={subjectId}
                    onChange={event => setSubjectId(event.target.value)}
                    maxLength={SUBJECT_ID_MAX_LENGTH}
                    placeholder={
                      SUBJECT_ID_PLACEHOLDERS[subjectType] ||
                      DEFAULT_SUBJECT_ID_PLACEHOLDER
                    }
                    list={
                      subjectSuggestions.length
                        ? MANUAL_JOB_SUBJECT_SUGGESTIONS_LIST_ID
                        : undefined
                    }
                    autoComplete='off'
                  />
                  <FormHelperText>
                    {subjectRequiredForOperation
                      ? 'Required for this operation, together with subject type.'
                      : 'Required together with subject type, or leave both empty.'}
                  </FormHelperText>
                  {subjectSuggestions.length ? (
                    <datalist id={MANUAL_JOB_SUBJECT_SUGGESTIONS_LIST_ID}>
                      {subjectSuggestions.map(item => (
                        <option
                          key={item.id}
                          value={item.id}
                          label={item.label}
                        />
                      ))}
                    </datalist>
                  ) : null}
                </FormControl>
              </>
            )}
            {hidesAgentField ? null : (
              <FormControl>
                <FormLabel fontSize='sm'>Agent</FormLabel>
                <Select
                  size='sm'
                  placeholder='Any eligible agent (default)'
                  value={assignedAgentId}
                  onChange={event => setAssignedAgentId(event.target.value)}
                >
                  {assignableAgents.map(agent => (
                    <option key={agent.id} value={agent.id}>
                      {agentSelectLabel(agent)}
                    </option>
                  ))}
                </Select>
                <FormHelperText>
                  Optional. Leave unset to let any agent whose declared
                  selectors/profiles/DNS providers match claim the job first;
                  pin to one agent to force a specific host to run it.
                </FormHelperText>
              </FormControl>
            )}
            <FormControl isRequired={isIssue}>
              <FormLabel fontSize='sm'>Idempotency key</FormLabel>
              <Input
                size='sm'
                value={idempotencyKey}
                onChange={event => setIdempotencyKey(event.target.value)}
                placeholder='e.g. a client-generated request id'
                autoComplete='off'
              />
              <FormHelperText>
                {isIssue
                  ? 'Required for issue: a retried request with the same key returns the existing job instead of provisioning a second certificate.'
                  : 'Optional. Reusing a key returns the existing job instead of creating a duplicate.'}
              </FormHelperText>
            </FormControl>
            <FormControl isInvalid={payloadMode === 'json' && Boolean(payloadError)}>
              <HStack justify='space-between' align='center' mb={1}>
                <FormLabel fontSize='sm' mb={0}>
                  Payload
                </FormLabel>
                <ButtonGroup size='sm' isAttached variant='outline'>
                  <Button
                    colorScheme={payloadMode === 'fields' ? 'blue' : undefined}
                    variant={payloadMode === 'fields' ? 'solid' : 'outline'}
                    onClick={() => setPayloadMode('fields')}
                  >
                    Fields
                  </Button>
                  <Button
                    colorScheme={payloadMode === 'json' ? 'blue' : undefined}
                    variant={payloadMode === 'json' ? 'solid' : 'outline'}
                    onClick={() => {
                      // Switching to JSON seeds the textarea from whatever
                      // was entered in the fields tab, so nothing is lost
                      // and an operator can start from the structured
                      // fields and drop into raw JSON only to add what the
                      // fields do not cover.
                      const seeded = buildFieldsPayload();
                      if (Object.keys(seeded).length && !payloadText.trim()) {
                        setPayloadText(JSON.stringify(seeded, null, 2));
                      }
                      setPayloadMode('json');
                    }}
                  >
                    JSON
                  </Button>
                </ButtonGroup>
              </HStack>
              {payloadMode === 'fields' ? (
                <VStack align='stretch' spacing={2}>
                  <FormControl isRequired={isIssue}>
                    <FormLabel fontSize='xs' mb={0.5}>
                      Target domain
                    </FormLabel>
                    <Input
                      size='sm'
                      value={fieldTarget}
                      onChange={event => setFieldTarget(event.target.value)}
                      placeholder='e.g. example.com'
                      autoComplete='off'
                    />
                  </FormControl>
                  <FormControl>
                    <FormLabel fontSize='xs' mb={0.5}>
                      SANs
                    </FormLabel>
                    <Input
                      size='sm'
                      value={fieldSans}
                      onChange={event => setFieldSans(event.target.value)}
                      placeholder='Comma or newline separated (defaults to target)'
                      autoComplete='off'
                    />
                  </FormControl>
                  <SimpleGrid columns={2} spacing={2}>
                    <FormControl isRequired={isIssue}>
                      <FormLabel fontSize='xs' mb={0.5}>
                        Command ref
                      </FormLabel>
                      <Input
                        size='sm'
                        value={fieldCommandRef}
                        onChange={event => setFieldCommandRef(event.target.value)}
                        placeholder='e.g. certbot-csr'
                        autoComplete='off'
                      />
                    </FormControl>
                    <FormControl isRequired={isIssue}>
                      <FormLabel fontSize='xs' mb={0.5}>
                        DNS provider
                      </FormLabel>
                      <Input
                        size='sm'
                        value={fieldDnsProvider}
                        onChange={event => setFieldDnsProvider(event.target.value)}
                        placeholder='e.g. cloudflare'
                        autoComplete='off'
                      />
                    </FormControl>
                  </SimpleGrid>
                  <FormControl isRequired={isIssue}>
                    <FormLabel fontSize='xs' mb={0.5}>
                      CA endpoint
                    </FormLabel>
                    <Input
                      size='sm'
                      value={fieldCaEndpoint}
                      onChange={event => setFieldCaEndpoint(event.target.value)}
                      placeholder='e.g. https://acme-v02.api.letsencrypt.org/directory'
                      autoComplete='off'
                    />
                  </FormControl>
                  <SimpleGrid columns={2} spacing={2}>
                    <FormControl isRequired={isIssue}>
                      <FormLabel fontSize='xs' mb={0.5}>
                        DNS zone
                      </FormLabel>
                      <Input
                        size='sm'
                        value={fieldDnsZone}
                        onChange={event => setFieldDnsZone(event.target.value)}
                        placeholder='e.g. example.com'
                        autoComplete='off'
                      />
                    </FormControl>
                    <FormControl isRequired={isIssue}>
                      <FormLabel fontSize='xs' mb={0.5}>
                        Cert file path
                      </FormLabel>
                      <Input
                        size='sm'
                        value={fieldCertPath}
                        onChange={event => setFieldCertPath(event.target.value)}
                        placeholder='e.g. /etc/ssl/example.com.pem'
                        autoComplete='off'
                      />
                    </FormControl>
                  </SimpleGrid>
                  <FormHelperText>
                    {isIssue
                      ? 'Required for issue: target, command ref, CA endpoint, DNS zone, DNS provider, and cert path.'
                      : 'Optional. Fills the same execution payload keys a renew/deploy job reads. Switch to JSON for anything not listed here.'}
                  </FormHelperText>
                </VStack>
              ) : (
                <>
                  <Textarea
                    size='sm'
                    fontFamily='mono'
                    fontSize='xs'
                    rows={6}
                    value={payloadText}
                    onChange={handlePayloadChange}
                    placeholder={PAYLOAD_JSON_EXAMPLE}
                  />
                  <FormHelperText>
                    {payloadError ||
                      (isIssue
                        ? 'Required: target, commandRef, caEndpoint, dnsZone, dnsProvider, and certPath. sans defaults to [target] when omitted.'
                        : 'Optional. Free-form JSON merged into the job payload.')}
                  </FormHelperText>
                </>
              )}
            </FormControl>
            <FormControl>
              <Checkbox
                size='sm'
                isChecked={requiresApproval}
                onChange={event => setRequiresApproval(event.target.checked)}
              >
                <Text as='span' fontSize='sm'>
                  Require approval before this job can run
                </Text>
              </Checkbox>
              <FormHelperText>
                The job starts at &quot;Pending approval&quot; instead of
                claimable; an authorized workspace member other than you must
                approve it from this page before an agent can pick it up.
              </FormHelperText>
            </FormControl>
          </VStack>
        </ModalBody>
        <ModalFooter>
          <Button onClick={handleClose} isDisabled={submitting} mr={3}>
            Cancel
          </Button>
          <Button
            colorScheme='blue'
            onClick={handleSubmit}
            isDisabled={!canSubmit}
            isLoading={submitting}
            loadingText='Creating'
          >
            Create job
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
}

/**
 * Confirm dialog for approving or rejecting a job at `pending_approval`.
 * `reason` is optional free text recorded on the approval/rejection job-log
 * entry and audit row (see docs/certops's approvals guide).
 */
function ApprovalDecisionModal({ isOpen, onClose, job, decision, onDecide }) {
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setReason('');
      setSubmitting(false);
    }
  }, [isOpen]);

  const approving = decision === 'approve';

  const handleClose = () => {
    if (submitting) return;
    onClose();
  };

  const handleConfirm = async () => {
    if (submitting) return;
    setSubmitting(true);
    try {
      await onDecide(reason.trim() || undefined);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={handleClose} isCentered size='md'>
      <ModalOverlay />
      <ModalContent>
        <ModalHeader>{approving ? 'Approve job' : 'Reject job'}</ModalHeader>
        <ModalCloseButton isDisabled={submitting} />
        <ModalBody>
          <VStack align='stretch' spacing={3}>
            {job ? (
              <Text fontSize='sm'>
                {jobOperationLabel(job.operation)} job{' '}
                <Text as='span' fontFamily='mono' fontSize='xs'>
                  {truncateId(job.id)}
                </Text>
                {job.subjectId
                  ? ` (${subjectTypeLabel(job.subjectType) || 'Subject'}: ${job.subjectId})`
                  : ''}
              </Text>
            ) : null}
            <Text fontSize='sm' color='gray.500'>
              {approving
                ? 'The job moves to "Pending" and becomes claimable by an agent.'
                : 'The job moves directly to the terminal "Rejected" status. This cannot be undone.'}
            </Text>
            <Box>
              <Text fontSize='sm' mb={1}>
                Reason (optional)
              </Text>
              <Textarea
                size='sm'
                rows={2}
                value={reason}
                onChange={event => setReason(event.target.value)}
                placeholder={
                  approving
                    ? 'e.g. confirmed with the domain owner'
                    : 'e.g. wrong certificate target'
                }
              />
            </Box>
          </VStack>
        </ModalBody>
        <ModalFooter>
          <Button onClick={handleClose} isDisabled={submitting} mr={3}>
            Cancel
          </Button>
          <Button
            colorScheme={approving ? 'green' : 'red'}
            onClick={handleConfirm}
            isLoading={submitting}
            loadingText={approving ? 'Approving' : 'Rejecting'}
          >
            {approving ? 'Approve' : 'Reject'}
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
}

/**
 * Executor-reported job list with expandable evidence timelines.
 * Read-only surface backed by the workspace job/log/evidence APIs, plus a
 * manager-only manual job creation entry point (exception path) and
 * manager-only approve/reject actions on jobs at `pending_approval`.
 */
function ExecutorJobsPanel() {
  const { muted, border } = useDashboardTheme();
  const rowHoverBg = useColorModeValue('gray.50', 'whiteAlpha.50');
  const expandedBg = useColorModeValue('gray.50', 'whiteAlpha.50');
  const canManage = useCertOpsCanManage();
  const { workspaceId } = useWorkspace();
  const { jobs, pagination, loading, error, refresh } = useCertOpsJobs({
    limit: JOB_LIST_LIMIT,
  });
  const [expandedId, setExpandedId] = useState(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [decisionTarget, setDecisionTarget] = useState(null);
  const jobsTruncation = truncationSummary({
    shown: jobs?.length || 0,
    pagination,
    noun: 'jobs',
  });

  const handleDecision = async reason => {
    if (!decisionTarget || !workspaceId) return;
    const { job, decision } = decisionTarget;
    const decide = decision === 'approve' ? approveJob : rejectJob;
    try {
      await decide(workspaceId, job.id, { reason });
      showSuccess(decision === 'approve' ? 'Job approved' : 'Job rejected');
      setDecisionTarget(null);
      refresh();
    } catch (err) {
      showError(
        decision === 'approve' ? 'Approve failed' : 'Reject failed',
        approvalDecisionErrorMessage(err, decision)
      );
      if (
        err?.response?.data?.code ===
        'CERTOPS_APPROVAL_JOB_NOT_PENDING_APPROVAL'
      ) {
        setDecisionTarget(null);
        refresh();
      }
    }
  };

  return (
    <DashboardPanel>
      <DashboardPanelHeader
        title='Machine executor jobs'
        description='Certificate jobs reported by machine tokens and the API'
        action={
          <HStack spacing={2}>
            {canManage ? (
              <DashboardActionButton
                colorScheme='blue'
                onClick={() => setCreateOpen(true)}
              >
                Create manual job
              </DashboardActionButton>
            ) : null}
            <DashboardActionButton
              variant='outline'
              onClick={refresh}
              isLoading={loading}
            >
              Refresh
            </DashboardActionButton>
          </HStack>
        }
      />
      {loading && jobs.length === 0 ? (
        <DashboardState type='loading' title='Loading executor jobs...' />
      ) : error ? (
        <Text fontSize='sm' color='red.400'>
          {error}
        </Text>
      ) : jobs.length === 0 ? (
        <DashboardState
          title='No executor-reported certificate jobs yet'
          description='Jobs appear here once an external executor reports lifecycle events through the CertOps executor API.'
          py={6}
        />
      ) : (
        <VStack align='stretch' spacing={1}>
          {jobs.map(job => {
            const isOpen = expandedId === job.id;
            const awaitingApproval = job.status === 'pending_approval';
            return (
              <Box key={job.id} borderColor={border}>
                <HStack
                  w='full'
                  spacing={2}
                  px={2}
                  py={2}
                  borderRadius='md'
                  cursor='pointer'
                  _hover={{ bg: rowHoverBg }}
                  role='button'
                  tabIndex={0}
                  aria-expanded={isOpen}
                  onClick={() =>
                    setExpandedId(current =>
                      current === job.id ? null : job.id
                    )
                  }
                  onKeyDown={event => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      setExpandedId(current =>
                        current === job.id ? null : job.id
                      );
                    }
                  }}
                >
                  <Icon
                    as={isOpen ? ChevronDown : ChevronRight}
                    boxSize={3.5}
                    color={muted}
                    flexShrink={0}
                  />
                  <Text
                    fontSize='sm'
                    fontWeight='medium'
                    flexShrink={0}
                    noOfLines={1}
                  >
                    {jobOperationLabel(job.operation)}
                  </Text>
                  <Box
                    flexShrink={0}
                    onClick={event => event.stopPropagation()}
                  >
                    <CopyableId id={job.id} display={truncateId(job.id)} />
                  </Box>
                  <Text fontSize='xs' color={muted} flex='1' noOfLines={1}>
                    {job.subjectId
                      ? `${subjectTypeLabel(job.subjectType) || 'Subject'}: ${job.subjectId}`
                      : job.source
                        ? `Source: ${job.source}`
                        : ''}
                  </Text>
                  <JobStatusBadge status={job.status} />
                  <Text
                    fontSize='xs'
                    color={muted}
                    flexShrink={0}
                    title={formatDateTime(job.createdAt)}
                  >
                    {formatRelativeDateTime(job.createdAt)}
                  </Text>
                  {canManage && awaitingApproval ? (
                    <HStack
                      spacing={1}
                      flexShrink={0}
                      onClick={event => event.stopPropagation()}
                    >
                      <Button
                        size='xs'
                        colorScheme='green'
                        onClick={() =>
                          setDecisionTarget({ job, decision: 'approve' })
                        }
                      >
                        Approve
                      </Button>
                      <Button
                        size='xs'
                        colorScheme='red'
                        variant='outline'
                        onClick={() =>
                          setDecisionTarget({ job, decision: 'reject' })
                        }
                      >
                        Reject
                      </Button>
                    </HStack>
                  ) : null}
                </HStack>
                <Collapse in={isOpen} animateOpacity>
                  <Box
                    mt={1}
                    mb={2}
                    ml={5}
                    pl={3}
                    py={2}
                    borderLeftWidth='2px'
                    borderColor={border}
                    bg={expandedBg}
                    borderRadius='md'
                  >
                    {isOpen ? <EvidenceTimeline jobId={job.id} /> : null}
                  </Box>
                </Collapse>
              </Box>
            );
          })}
          {jobsTruncation ? (
            <Text fontSize='xs' color={muted} px={2} pt={1}>
              {jobsTruncation}
            </Text>
          ) : null}
        </VStack>
      )}
      <CreateManualJobModal
        isOpen={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={refresh}
      />
      <ApprovalDecisionModal
        isOpen={Boolean(decisionTarget)}
        onClose={() => setDecisionTarget(null)}
        job={decisionTarget?.job}
        decision={decisionTarget?.decision}
        onDecide={handleDecision}
      />
    </DashboardPanel>
  );
}

/**
 * CertOps orchestration page: machine executor jobs, evidence timelines,
 * and scoped machine API-token management. Mounted via the /certops/* splat
 * route so orchestration surfaces stay out of the read-only Control Center.
 */
export default function CertOpsOperations({
  session,
  onLogout,
  onAccountClick,
}) {
  const { pageBg, text } = useDashboardTheme();
  const {
    ready,
    enabled,
    error: availabilityError,
    retry: retryAvailability,
  } = useCertOpsAvailability();
  // Bumped when DeployAgentPanel detects a freshly registered agent, so the
  // fleet panel refetches immediately instead of waiting on its own poll.
  const [fleetRefreshSignal, setFleetRefreshSignal] = useState(0);

  const shellProps = useDashboardShellProps({
    session,
    onLogout,
    onAccountClick,
    pageTitle: 'Certificate operations',
  });

  return (
    <>
      <SEO
        title='Certificate operations'
        description='Machine executor jobs, evidence timelines, and scoped API tokens'
        noindex
      />
      <Box color={text} minH='100vh' bg={pageBg}>
        <DashboardShell {...shellProps}>
          <Box
            px={{ base: 4, lg: 4, '2xl': 5 }}
            py={{ base: 5, lg: 3 }}
            w='100%'
            minW={0}
            maxW='100%'
          >
            {!ready ? (
              <DashboardState
                type='loading'
                title='Checking certificate operations availability...'
              />
            ) : availabilityError ? (
              <DashboardState
                title='Could not load certificate operations status'
                description='The availability check failed. This does not mean the feature is disabled. Retry in a moment.'
                action={
                  <DashboardActionButton
                    variant='outline'
                    onClick={retryAvailability}
                  >
                    Retry
                  </DashboardActionButton>
                }
              />
            ) : enabled ? (
              <SimpleGrid columns={{ base: 1, xl: 2 }} spacing={3}>
                <DashboardPanel gridColumn={{ xl: '1 / -1' }}>
                  <WorkspaceKillSwitchPanel />
                </DashboardPanel>
                <ExecutorJobsPanel />
                <DashboardPanel>
                  <ApiTokenPanel />
                </DashboardPanel>
                <DashboardPanel>
                  <DeployAgentPanel
                    onAgentRegistered={() =>
                      setFleetRefreshSignal(tick => tick + 1)
                    }
                  />
                </DashboardPanel>
                <DashboardPanel>
                  <AgentFleetPanel refreshSignal={fleetRefreshSignal} />
                </DashboardPanel>
              </SimpleGrid>
            ) : (
              <DashboardState
                title='Certificate operations is not enabled'
                description='Certificate operations is not enabled for this workspace yet.'
              />
            )}
          </Box>
        </DashboardShell>
      </Box>
    </>
  );
}
