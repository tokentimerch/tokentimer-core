import { useEffect, useRef, useState } from 'react';
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

const STORE_CAPABILITY = 'windows-store-only-adcs-v1';

export default function AdcsStoreIssueDialog({
  isOpen,
  onClose,
  workspaceId,
  issuers,
  onCreated,
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
  const [busy, setBusy] = useState(false);
  const [requestLocked, setRequestLocked] = useState(false);
  const [error, setError] = useState('');
  const [job, setJob] = useState(null);
  const requestKey = useRef(null);
  const workspaceRef = useRef(workspaceId);
  workspaceRef.current = workspaceId;
  const readyIssuers = (issuers || []).filter(
    i =>
      i.kind === 'adcs' &&
      Number(i.currentVersion) > 0 &&
      i.revalidationRequired !== true
  );

  useEffect(() => {
    setAgents([]);
    setIssuerId('');
    setAgentId('');
    setName('');
    setExtraNames('');
    setTicket('');
    setJob(null);
    setError('');
    setRequestLocked(false);
    setBusy(false);
    requestKey.current = null;
  }, [workspaceId]);

  useEffect(() => {
    if (!isOpen || !workspaceId) return undefined;
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
  }, [isOpen, workspaceId]);

  const eligible = agents.filter(
    agent =>
      agent.status === 'active' &&
      agent.livenessState === 'live' &&
      agent.platform === 'win32' &&
      Array.isArray(agent.declaredCapabilities) &&
      agent.declaredCapabilities.includes(STORE_CAPABILITY) &&
      agent.declaredCapabilities.includes('adcs-enroll-v1')
  );
  const edit = setter => event => {
    requestKey.current = null;
    setter(event.target.value);
  };
  const resetAndClose = () => {
    if (busy) return;
    setIssuerId('');
    setAgentId('');
    setName('');
    setExtraNames('');
    setTicket('');
    setAlgorithm('rsa');
    setKeySize('2048');
    setError('');
    setJob(null);
    setRequestLocked(false);
    requestKey.current = null;
    onClose();
  };
  const submit = async () => {
    setBusy(true);
    setError('');
    setRequestLocked(true);
    const requestWorkspace = workspaceId;
    const reference = name.trim();
    const sans = [
      ...new Set([reference, ...extraNames.split(/[\s,]+/).filter(Boolean)]),
    ];
    try {
      if (!requestKey.current) requestKey.current = crypto.randomUUID();
      const result = await createJob(workspaceId, {
        operation: 'issue',
        idempotencyKey: requestKey.current,
        assignedAgentId: agentId,
        ...(ticket.trim() ? { changeTicketReference: ticket.trim() } : {}),
        payload: {
          issuerId,
          target: { type: 'windows-cert-store', reference, store: 'My' },
          sans,
          keyAlgorithm: algorithm,
          keySize: Number(keySize),
          automationEnabled: false,
        },
      });
      if (workspaceRef.current !== requestWorkspace) return;
      if (!result?.job?.id) throw new Error('The server returned no job.');
      setJob(result.job);
      if (onCreated) {
        try {
          await onCreated({ job: result.job, agentId, issuerId });
        } catch {
          // A refresh failure does not change the accepted job.
        }
      }
    } catch (err) {
      if (workspaceRef.current !== requestWorkspace) return;
      if (
        err?.response?.status >= 400 &&
        err.response.status < 500 &&
        err.response.status !== 409
      ) {
        requestKey.current = null;
        setRequestLocked(false);
      }
      setError(
        err?.response?.data?.error ||
          'The outcome is unknown. Retry the same request or check job history before starting another.'
      );
    } finally {
      if (workspaceRef.current === requestWorkspace) setBusy(false);
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
            {job ? (
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
            ) : (
              <>
                <FormControl isRequired isDisabled={requestLocked}>
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
                <FormControl isRequired isDisabled={requestLocked}>
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
                <FormControl isRequired isDisabled={requestLocked}>
                  <FormLabel>Certificate DNS name</FormLabel>
                  <Input
                    aria-label='Certificate DNS name'
                    value={name}
                    onChange={edit(setName)}
                    placeholder='server.example.com'
                  />
                </FormControl>
                <FormControl isDisabled={requestLocked}>
                  <FormLabel>Extra DNS names</FormLabel>
                  <Input
                    aria-label='Extra DNS names'
                    value={extraNames}
                    onChange={edit(setExtraNames)}
                  />
                </FormControl>
                <FormControl isDisabled={requestLocked}>
                  <FormLabel>Key algorithm</FormLabel>
                  <Select
                    aria-label='Key algorithm'
                    value={algorithm}
                    onChange={event => {
                      requestKey.current = null;
                      setAlgorithm(event.target.value);
                      setKeySize(event.target.value === 'rsa' ? '2048' : '256');
                    }}
                  >
                    <option value='rsa'>RSA</option>
                    <option value='ecdsa'>ECDSA</option>
                  </Select>
                </FormControl>
                <FormControl isDisabled={requestLocked}>
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
                <FormControl isDisabled={requestLocked}>
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
            {job ? 'Done' : 'Cancel'}
          </Button>
          {!job ? (
            <Button
              {...modal.primaryButtonProps}
              isLoading={busy}
              isDisabled={
                !readyIssuers.some(i => i.id === issuerId) ||
                !eligible.some(a => a.id === agentId) ||
                !name.trim()
              }
              onClick={submit}
            >
              Issue certificate
            </Button>
          ) : null}
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}
