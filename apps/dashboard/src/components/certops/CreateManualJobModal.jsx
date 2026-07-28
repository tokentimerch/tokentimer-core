import { useEffect, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Button,
  ButtonGroup,
  Checkbox,
  FormControl,
  FormHelperText,
  FormLabel,
  HStack,
  Input,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Select,
  SimpleGrid,
  Text,
  Textarea,
  VStack,
} from '@chakra-ui/react';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import {
  CERTOPS_JOB_OPERATIONS,
  CERTOPS_SUBJECT_TYPES,
  createJob,
} from './certopsJobsApi.js';
import {
  createControllerProvisionIntent,
  listCertificates,
  listCertificateTargets,
  listWorkspaceCertificateInstances,
} from './certopsApi.js';
import {
  jobOperationLabel,
  subjectTypeLabel,
  truncateId,
} from './certopsJobsFormat';
import { useCertOpsAgents } from './useCertOpsAgents.js';
import { useCertOpsControllerClusters } from './useCertOpsControllerClusters.js';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { showError, showSuccess } from '../../utils/toast.js';

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

// "Issue" via a controller hands a strict public desired state to a
// cert-manager controller instead of an agent (see
// apps/api/services/certops/controllerProvisioning.js); this is a distinct
// executor from the ACME/DNS-01 agent path below, with its own fields and
// its own API route (createControllerProvisionIntent), not the job payload.
const JOB_EXECUTORS = [
  { value: 'agent', label: 'Agent' },
  { value: 'controller', label: 'Controller (cluster)' },
];

// Mirrors the CertOpsProvisionIntentRequest.issuerRef.kind enum in
// openapi.yaml.
const CONTROLLER_ISSUER_KINDS = ['ClusterIssuer', 'Issuer'];
const DEFAULT_CONTROLLER_ISSUER_GROUP = 'cert-manager.io';

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
  if (code === 'CERTOPS_CONTROLLER_PROVISIONING_TERMINAL_IDENTITY') {
    return 'This certificate/secret name was already retired in this namespace and cannot be reactivated by provisioning. Choose a different certificate or secret name.';
  }
  if (code === 'CERTOPS_CONTROLLER_PROVISIONING_INVALID') {
    return 'This provisioning request is invalid. Check the cluster, namespace, certificate/secret names, issuer reference, and DNS names.';
  }
  if (code === 'CERTOPS_WORKSPACE_PAUSED') {
    return 'CertOps is paused for this workspace, so no new job can be created.';
  }
  return err?.response?.data?.error || err?.message || 'Could not create job.';
}

/**
 * Manual job creation modal: the exception path for creating
 * a CertOps job before the certops-scheduler exists. Always posts with
 * source "api"; the server never accepts a client-supplied source.
 */
export default function CreateManualJobModal({ isOpen, onClose, onCreated }) {
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    outlineButtonProps,
    primaryButtonProps,
  } = useDashboardModalProps();
  const { workspaceId } = useWorkspace();
  const { agents } = useCertOpsAgents();
  const { clusters: controllerClusters } = useCertOpsControllerClusters();
  const [operation, setOperation] = useState('');
  const [executor, setExecutor] = useState('agent');
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
  const [controllerClusterId, setControllerClusterId] = useState('');
  const [controllerNamespace, setControllerNamespace] = useState('');
  const [controllerCertificateName, setControllerCertificateName] =
    useState('');
  const [controllerSecretName, setControllerSecretName] = useState('');
  const [controllerIssuerKind, setControllerIssuerKind] = useState(
    CONTROLLER_ISSUER_KINDS[0]
  );
  const [controllerIssuerName, setControllerIssuerName] = useState('');
  const [controllerDnsNames, setControllerDnsNames] = useState('');

  // "issue" has no existing subject to act on (ADR-0008): the control
  // plane creates the managed_certificate row itself, so passing
  // subjectType/subjectId is a validation error. idempotencyKey is
  // mandatory on issue because the request has a side effect beyond the
  // job (the new inventory row) and must not be duplicated by a retry.
  const isIssue = operation === 'issue';

  // The controller executor is only offered for "issue": renew/deploy/
  // reload/revoke against a controller-provisioned certificate are not
  // exposed by the provisioning API today (CertOpsProvisionIntentRequest is
  // issue-only), so switching away from issue always falls back to agent.
  const isControllerIssue = isIssue && executor === 'controller';

  useEffect(() => {
    if (!isIssue && executor === 'controller') setExecutor('agent');
  }, [isIssue, executor]);

  // renew/deploy/reload/revoke always act on something that already
  // exists, so the API requires subjectType+subjectId for these (see
  // SUBJECT_REQUIRED_OPERATIONS in services/certops/jobs.js). noop is the
  // only other operation that stays optional, since it exists purely to
  // exercise the pipeline without a real target.
  const subjectRequiredForOperation =
    SUBJECT_REQUIRED_OPERATIONS.has(operation);

  // Only agents that can still be handed a job: a retired agent can never
  // claim anything, so pinning to one would silently strand the job.
  const assignableAgents = agents.filter(agent => agent.status !== 'retired');

  // domain/endpoint/external subjects are free-text references an agent
  // can never match against (see MANUAL_ONLY_SUBJECT_TYPES above), so the
  // pin-to-agent control would imply a capability that doesn't exist here.
  // A controller-executed issue has no agent at all: cluster-side
  // provisioning is picked up by whichever controller watches that
  // clusterId, not by pinning a fleet agent.
  const hidesAgentField =
    isControllerIssue ||
    (!isIssue && MANUAL_ONLY_SUBJECT_TYPES.includes(subjectType));

  // Clears a stale pin left over from a previous subjectType selection so a
  // hidden field can never silently submit a leftover assignedAgentId.
  useEffect(() => {
    if (hidesAgentField) setAssignedAgentId('');
  }, [hidesAgentField]);

  const resetForm = () => {
    setOperation('');
    setExecutor('agent');
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
    setControllerClusterId('');
    setControllerNamespace('');
    setControllerCertificateName('');
    setControllerSecretName('');
    setControllerIssuerKind(CONTROLLER_ISSUER_KINDS[0]);
    setControllerIssuerName('');
    setControllerDnsNames('');
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

  // Agent-executed issue reads its shape from the payload fields (ACME
  // command, CA, DNS-01 zone/provider, deploy path); controller-executed
  // issue never touches the payload at all (see handleSubmit) and is
  // validated by controllerFieldsMet instead.
  const fieldsRequiredForIssueMet =
    isControllerIssue ||
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

  // Mirrors the required fields of CertOpsProvisionIntentRequest in
  // openapi.yaml: clusterId, namespace, certificateName, secretName,
  // issuerRef{group,kind,name}, and at least one DNS name.
  const controllerDnsNamesList = controllerDnsNames
    .split(/[\n,]+/)
    .map(value => value.trim())
    .filter(Boolean);
  const controllerFieldsMet =
    !isControllerIssue ||
    Boolean(
      controllerClusterId.trim() &&
        controllerNamespace.trim() &&
        controllerCertificateName.trim() &&
        controllerSecretName.trim() &&
        controllerIssuerKind &&
        controllerIssuerName.trim() &&
        controllerDnsNamesList.length > 0
    );

  const canSubmit =
    Boolean(operation) &&
    Boolean(workspaceId) &&
    !submitting &&
    fieldsRequiredForIssueMet &&
    controllerFieldsMet &&
    (isIssue
      ? Boolean(idempotencyKey.trim()) &&
        (isControllerIssue || payloadMode === 'fields' || !payloadError)
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
    } else {
      setExecutor('agent');
    }
  };

  const handleSubmit = async () => {
    if (!canSubmit) return;
    setSubmitting(true);
    try {
      if (isControllerIssue) {
        const result = await createControllerProvisionIntent(workspaceId, {
          idempotencyKey: idempotencyKey.trim(),
          clusterId: controllerClusterId.trim(),
          namespace: controllerNamespace.trim(),
          certificateName: controllerCertificateName.trim(),
          secretName: controllerSecretName.trim(),
          issuerRef: {
            group: DEFAULT_CONTROLLER_ISSUER_GROUP,
            kind: controllerIssuerKind,
            name: controllerIssuerName.trim(),
          },
          dnsNames: controllerDnsNamesList,
        });
        showSuccess(
          result?.duplicate ? 'Provisioning intent already existed' : 'Provisioning intent created',
          result?.job?.id ? `Job ID: ${truncateId(result.job.id)}` : undefined
        );
        resetForm();
        onClose();
        onCreated?.();
        return;
      }
      const body = { operation };
      if (!isIssue && subjectType) body.subjectType = subjectType;
      if (!isIssue && subjectId.trim()) body.subjectId = subjectId.trim();
      if (idempotencyKey.trim()) body.idempotencyKey = idempotencyKey.trim();
      if (assignedAgentId) body.assignedAgentId = assignedAgentId;
      const payload =
        payloadMode === 'fields'
          ? buildFieldsPayload()
          : JSON.parse(payloadText || '{}');
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
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      isCentered
      scrollBehavior='inside'
    >
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame maxW={{ base: 'calc(100vw - 24px)', md: '640px' }}>
        <ModalHeader {...headerProps}>
          <DashboardModalTitle>Create manual job</DashboardModalTitle>
          <DashboardModalDescription>
            Manual job creation is an exception path for driving certificate
            operations before automated scheduling ships.
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} isDisabled={submitting} />
        <ModalBody {...bodyProps}>
          <VStack align='stretch' spacing={4}>
            <Alert status='info' variant='subtle' borderRadius='md'>
              <AlertIcon boxSize={4} />
              <AlertDescription fontSize='sm'>
                The job is recorded with source &quot;api&quot; and appears at
                the start of the job&apos;s history.
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
                  its ID once the request is accepted, so subject fields below
                  are hidden.
                </FormHelperText>
              ) : null}
            </FormControl>
            {isIssue ? (
              <FormControl>
                <FormLabel fontSize='sm'>Executor</FormLabel>
                <ButtonGroup size='sm' isAttached variant='outline'>
                  {JOB_EXECUTORS.map(option => (
                    <Button
                      key={option.value}
                      colorScheme={executor === option.value ? 'blue' : undefined}
                      variant={executor === option.value ? 'solid' : 'outline'}
                      onClick={() => setExecutor(option.value)}
                    >
                      {option.label}
                    </Button>
                  ))}
                </ButtonGroup>
                <FormHelperText>
                  {isControllerIssue
                    ? 'Hands a strict public desired state (namespace, certificate/secret name, issuer, DNS names) to a controller bound to the chosen cluster. No manifest, Secret data, CSR, or private key material is ever sent.'
                    : 'The default path: an agent runs the ACME/DNS-01 issuance below.'}
                </FormHelperText>
              </FormControl>
            ) : null}
            {isControllerIssue ? (
              <>
                <FormControl isRequired>
                  <FormLabel fontSize='sm'>Cluster</FormLabel>
                  <Select
                    size='sm'
                    placeholder={
                      controllerClusters.length
                        ? 'Select a cluster'
                        : 'No controller-bound clusters found'
                    }
                    value={controllerClusterId}
                    onChange={event => setControllerClusterId(event.target.value)}
                    isDisabled={controllerClusters.length === 0}
                  >
                    {controllerClusters.map(clusterId => (
                      <option key={clusterId} value={clusterId}>
                        {clusterId}
                      </option>
                    ))}
                  </Select>
                  <FormHelperText>
                    {controllerClusters.length
                      ? 'Only clusters with an active API token scoped to certops:observations:write or certops:provision:execute appear here.'
                      : 'Create an API token scoped to a cluster on the API Tokens tab first, then come back here.'}
                  </FormHelperText>
                </FormControl>
                <SimpleGrid columns={2} spacing={2}>
                  <FormControl isRequired>
                    <FormLabel fontSize='sm'>Namespace</FormLabel>
                    <Input
                      size='sm'
                      value={controllerNamespace}
                      onChange={event => setControllerNamespace(event.target.value)}
                      placeholder='e.g. default'
                      autoComplete='off'
                    />
                  </FormControl>
                  <FormControl isRequired>
                    <FormLabel fontSize='sm'>Certificate name</FormLabel>
                    <Input
                      size='sm'
                      value={controllerCertificateName}
                      onChange={event =>
                        setControllerCertificateName(event.target.value)
                      }
                      placeholder='e.g. example-web-tls'
                      autoComplete='off'
                    />
                  </FormControl>
                </SimpleGrid>
                <FormControl isRequired>
                  <FormLabel fontSize='sm'>Secret name</FormLabel>
                  <Input
                    size='sm'
                    value={controllerSecretName}
                    onChange={event => setControllerSecretName(event.target.value)}
                    placeholder='e.g. example-web-tls'
                    autoComplete='off'
                  />
                  <FormHelperText>
                    The Kubernetes Secret the cert-manager Certificate will
                    write to. Only its metadata is ever read back by
                    TokenTimer.
                  </FormHelperText>
                </FormControl>
                <SimpleGrid columns={2} spacing={2}>
                  <FormControl isRequired>
                    <FormLabel fontSize='sm'>Issuer kind</FormLabel>
                    <Select
                      size='sm'
                      value={controllerIssuerKind}
                      onChange={event => setControllerIssuerKind(event.target.value)}
                    >
                      {CONTROLLER_ISSUER_KINDS.map(kind => (
                        <option key={kind} value={kind}>
                          {kind}
                        </option>
                      ))}
                    </Select>
                  </FormControl>
                  <FormControl isRequired>
                    <FormLabel fontSize='sm'>Issuer name</FormLabel>
                    <Input
                      size='sm'
                      value={controllerIssuerName}
                      onChange={event => setControllerIssuerName(event.target.value)}
                      placeholder='e.g. letsencrypt-prod'
                      autoComplete='off'
                    />
                  </FormControl>
                </SimpleGrid>
                <FormControl isRequired>
                  <FormLabel fontSize='sm'>DNS names</FormLabel>
                  <Textarea
                    size='sm'
                    rows={2}
                    value={controllerDnsNames}
                    onChange={event => setControllerDnsNames(event.target.value)}
                    placeholder='Comma or newline separated, e.g. example.com, www.example.com'
                  />
                  <FormHelperText>
                    At least one DNS name is required; wildcards (e.g.
                    *.example.com) are accepted.
                  </FormHelperText>
                </FormControl>
              </>
            ) : null}
            {isIssue ? null : (
              <>
                <FormControl
                  isRequired={
                    subjectRequiredForOperation || Boolean(subjectId.trim())
                  }
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
                  isRequired={
                    subjectRequiredForOperation || Boolean(subjectType)
                  }
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
            {isControllerIssue ? null : (
              <FormControl
                isInvalid={payloadMode === 'json' && Boolean(payloadError)}
              >
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
                        onChange={event =>
                          setFieldCommandRef(event.target.value)
                        }
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
                        onChange={event =>
                          setFieldDnsProvider(event.target.value)
                        }
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
            )}
            {isControllerIssue ? null : (
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
            )}
          </VStack>
        </ModalBody>
        <ModalFooter {...footerProps}>
          <Button
            {...outlineButtonProps}
            onClick={handleClose}
            isDisabled={submitting}
          >
            Cancel
          </Button>
          <Button
            {...primaryButtonProps}
            ml={3}
            onClick={handleSubmit}
            isDisabled={!canSubmit}
            isLoading={submitting}
            loadingText='Creating'
          >
            {isControllerIssue ? 'Create provisioning intent' : 'Create job'}
          </Button>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}
