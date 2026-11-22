import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { Link as RouterLink, useInRouterContext } from 'react-router';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Button,
  FormControl,
  FormHelperText,
  FormLabel,
  Input,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Select,
  Stack,
  Text,
} from '@chakra-ui/react';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import { listAgents } from './certopsAgentsApi';
import { createJob } from './certopsJobsApi';
import { useAdcsStoreIssueAttempts } from './AdcsStoreIssueAttempts.jsx';

const REQUIRED_CAPABILITIES = [
  'windows-store-only-adcs-v1',
  'adcs-enroll-v1',
  'evidence-claim-binding-v1',
];

export default function AdcsStoreIssueDialog(props) {
  const state = useAdcsStoreIssueAttempts(props.workspaceId);
  return (
    <WorkspaceStoreIssueDialog
      key={JSON.stringify([state.attempts?.accountId, props.workspaceId])}
      {...props}
      {...state}
    />
  );
}

function WorkspaceStoreIssueDialog({
  isOpen,
  onClose,
  workspaceId,
  issuers,
  onCreated,
  attempts,
  attempt,
}) {
  const modal = useDashboardModalProps();
  const inRouter = useInRouterContext();
  const [agents, setAgents] = useState([]);
  const [issuerId, setIssuerId] = useState('');
  const [agentId, setAgentId] = useState('');
  const [name, setName] = useState('');
  const [extraNames, setExtraNames] = useState('');
  const [ticket, setTicket] = useState('');
  const [algorithm, setAlgorithm] = useState('rsa');
  const [keySize, setKeySize] = useState('2048');
  const [error, setError] = useState('');
  const view = useRef(null);
  const hasAttempt = Boolean(attempt);
  const busy = attempt?.status === 'pending';
  const job = attempt?.job;
  const readyIssuers = (issuers || []).filter(
    i =>
      i.kind === 'adcs' &&
      Number(i.currentVersion) > 0 &&
      i.revalidationRequired !== true
  );

  useLayoutEffect(() => {
    view.current = isOpen ? {} : null;
    return () => {
      view.current = null;
    };
  }, [isOpen, attempts]);

  useEffect(() => {
    if (!attempts || !isOpen || !workspaceId || hasAttempt) return undefined;
    let cancelled = false;
    listAgents(workspaceId)
      .then(page => {
        if (!cancelled) setAgents(page.items || []);
      })
      .catch(() => {
        if (!cancelled) setError('Could not load Windows agents. Try again.');
      });
    return () => {
      cancelled = true;
    };
  }, [attempts, isOpen, workspaceId, hasAttempt]);

  const eligible = agents.filter(
    agent =>
      agent.status === 'active' &&
      agent.livenessState === 'live' &&
      agent.platform === 'win32' &&
      Array.isArray(agent.declaredCapabilities) &&
      REQUIRED_CAPABILITIES.every(capability =>
        agent.declaredCapabilities.includes(capability)
      )
  );
  const canSubmit = Boolean(
    attempts &&
    workspaceId &&
    readyIssuers.some(i => i.id === issuerId) &&
    eligible.some(a => a.id === agentId) &&
    name.trim()
  );
  const edit = setter => event => setter(event.target.value);
  const resetAndClose = () => {
    const current = attempts?.get(workspaceId);
    if (current?.status === 'pending') return;
    if (current?.status === 'accepted') attempts.set(workspaceId, null);
    onClose();
  };
  const submit = async () => {
    if (!view.current || !attempts || !workspaceId) return;
    const previous = attempts.get(workspaceId);
    if (previous ? previous.status !== 'unknown' : !canSubmit) return;
    const submittedView = view.current;
    setError('');
    const reference = name.trim();
    const sans = [
      ...new Set([reference, ...extraNames.split(/[\s,]+/).filter(Boolean)]),
    ];
    let body = previous?.body;
    if (!body) {
      try {
        body = Object.freeze({
          operation: 'issue',
          idempotencyKey: crypto.randomUUID(),
          assignedAgentId: agentId,
          ...(ticket.trim() ? { changeTicketReference: ticket.trim() } : {}),
          payload: Object.freeze({
            issuerId,
            target: Object.freeze({
              type: 'windows-cert-store',
              reference,
              store: 'My',
            }),
            sans: Object.freeze(sans),
            keyAlgorithm: algorithm,
            keySize: Number(keySize),
            automationEnabled: false,
          }),
        });
      } catch {
        setError(
          'Could not prepare a request. Reopen this dialog and try again.'
        );
        return;
      }
    }
    const controller = new AbortController();
    attempts.set(workspaceId, { body, status: 'pending', controller });
    let result;
    try {
      result = await createJob(workspaceId, body, {
        signal: controller.signal,
      });
      if (!result?.job?.id) throw new Error('The server returned no job.');
    } catch (err) {
      const { status, data } = err?.response ?? {};
      if (!previous && status === 400 && data?.code === 'CERTOPS_JOB_INVALID') {
        attempts.set(workspaceId, null);
        if (view.current === submittedView) {
          setError(data.error || 'Check the request and try again.');
        }
      } else {
        attempts.set(workspaceId, {
          body,
          status: 'unknown',
          error: data?.error,
        });
      }
      return;
    }
    attempts.set(workspaceId, { body, status: 'accepted', job: result.job });
    if (view.current === submittedView && onCreated) {
      try {
        await onCreated({
          job: result.job,
          agentId: body.assignedAgentId,
          issuerId: body.payload.issuerId,
        });
      } catch {
        // A refresh failure does not change the accepted job.
      }
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={resetAndClose}
      size='lg'
      closeOnOverlayClick={!busy}
      closeOnEsc={!busy}
    >
      <ModalOverlay {...modal.overlayProps} />
      <DashboardModalFrame>
        <ModalHeader {...modal.headerProps}>
          <DashboardModalTitle>Issue from Microsoft CA</DashboardModalTitle>
          <DashboardModalDescription>
            Install a certificate in the selected Windows machine store.
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton {...modal.closeButtonProps} isDisabled={busy} />
        <ModalBody {...modal.bodyProps}>
          <Stack spacing={3}>
            {error ? (
              <Alert status='error'>
                <AlertIcon />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            ) : null}
            {!attempts ? (
              <Alert status='error'>
                <AlertIcon />
                <AlertDescription>
                  Windows-store issuance is unavailable because this page could
                  not load the AD CS request session.
                </AlertDescription>
              </Alert>
            ) : job ? (
              <Alert status='info'>
                <AlertIcon />
                <AlertDescription>
                  Issuance requested. Follow the job to confirm installation.
                  Automatic renewal is off.
                  {inRouter ? (
                    <Button
                      as={RouterLink}
                      to={`/certops/jobs?workspace=${encodeURIComponent(workspaceId)}&job=${encodeURIComponent(job.id)}`}
                      size='sm'
                      variant='link'
                      ml={2}
                    >
                      Open job
                    </Button>
                  ) : null}
                </AlertDescription>
              </Alert>
            ) : attempt ? (
              <Alert status={busy ? 'info' : 'warning'}>
                <AlertIcon />
                <AlertDescription>
                  <Text>
                    {busy
                      ? 'Request in progress for '
                      : 'Outcome is unknown for '}
                    {attempt.body.payload.target.reference}.
                  </Text>
                  {busy ? (
                    <Text>
                      Keep this tab open and stay signed in until the request
                      finishes.
                    </Text>
                  ) : (
                    <>
                      {attempt.error ? <Text>{attempt.error}</Text> : null}
                      <Text>
                        Retry the original request or check job history. If you
                        reload, sign out or use another tab or device, check job
                        history before starting a new request.
                      </Text>
                    </>
                  )}
                </AlertDescription>
              </Alert>
            ) : (
              <>
                <FormControl isRequired>
                  <FormLabel>Confirmed AD CS issuer</FormLabel>
                  <Select
                    aria-label='Confirmed AD CS issuer'
                    value={issuerId}
                    onChange={edit(setIssuerId)}
                  >
                    <option value=''>Select an issuer</option>
                    {readyIssuers.map(i => (
                      <option key={i.id} value={i.id}>
                        {i.name}
                      </option>
                    ))}
                  </Select>
                </FormControl>
                <FormControl isRequired>
                  <FormLabel>Windows agent</FormLabel>
                  <Select
                    aria-label='Windows agent'
                    value={agentId}
                    onChange={edit(setAgentId)}
                  >
                    <option value=''>Select an agent</option>
                    {eligible.map(a => (
                      <option key={a.id} value={a.id}>
                        {a.name || a.hostname || a.agentId}
                      </option>
                    ))}
                  </Select>
                  <FormHelperText>
                    The selected agent needs a current safe CA check and an
                    enrollment rule for these names.
                  </FormHelperText>
                  {eligible.length === 0 ? (
                    <FormHelperText>
                      No live qualified Windows agent is available. Check its
                      package, connection and capability before trying again.
                    </FormHelperText>
                  ) : null}
                </FormControl>
                <FormControl isRequired>
                  <FormLabel>Certificate DNS name</FormLabel>
                  <Input
                    aria-label='Certificate DNS name'
                    value={name}
                    onChange={edit(setName)}
                    placeholder='server.example.com'
                  />
                </FormControl>
                <FormControl>
                  <FormLabel>Extra DNS names</FormLabel>
                  <Input
                    aria-label='Extra DNS names'
                    value={extraNames}
                    onChange={edit(setExtraNames)}
                  />
                </FormControl>
                <FormControl>
                  <FormLabel>Key algorithm</FormLabel>
                  <Select
                    aria-label='Key algorithm'
                    value={algorithm}
                    onChange={event => {
                      setAlgorithm(event.target.value);
                      setKeySize(event.target.value === 'rsa' ? '2048' : '256');
                    }}
                  >
                    <option value='rsa'>RSA</option>
                    <option value='ecdsa'>ECDSA</option>
                  </Select>
                </FormControl>
                <FormControl>
                  <FormLabel>Key size</FormLabel>
                  <Select
                    aria-label='Key size'
                    value={keySize}
                    onChange={edit(setKeySize)}
                  >
                    {(algorithm === 'rsa'
                      ? ['2048', '3072', '4096']
                      : ['256', '384']
                    ).map(size => (
                      <option key={size} value={size}>
                        {size}
                      </option>
                    ))}
                  </Select>
                </FormControl>
                <FormControl>
                  <FormLabel>Change ticket reference</FormLabel>
                  <Input
                    aria-label='Change ticket reference'
                    value={ticket}
                    onChange={edit(setTicket)}
                  />
                  <FormHelperText>
                    Provide this when your workspace policy requires a ticket.
                  </FormHelperText>
                </FormControl>
                <Text fontSize='sm'>
                  Destination: LocalMachine\My. The private key stays on this
                  agent. Installing the certificate does not activate a service;
                  automatic renewal is off.
                </Text>
              </>
            )}
          </Stack>
        </ModalBody>
        <ModalFooter {...modal.footerProps}>
          <Button
            {...modal.outlineButtonProps}
            onClick={resetAndClose}
            isDisabled={busy}
          >
            {job ? 'Done' : attempt ? 'Close for now' : 'Cancel'}
          </Button>
          {attempts && !job ? (
            <Button
              {...modal.primaryButtonProps}
              isLoading={busy}
              isDisabled={busy || (!attempt && !canSubmit)}
              onClick={submit}
            >
              {attempt ? 'Retry original request' : 'Issue certificate'}
            </Button>
          ) : null}
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}
