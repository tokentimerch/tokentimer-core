import { useRef, useState } from 'react';
import {
  Alert,
  AlertIcon,
  Button,
  FormControl,
  FormLabel,
  Input,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Select,
  Stack,
  Text,
} from '@chakra-ui/react';
import { createJob } from './certopsJobsApi';

export default function AcmeStoreIssueDialog({
  isOpen,
  onClose,
  workspaceId,
  agents,
  onCreated,
}) {
  const [fields, setFields] = useState({
    agentId: '',
    name: '',
    endpoint: '',
    command: '',
    provider: '',
    zone: '',
  });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const key = useRef(null);
  const eligible = agents.filter(
    agent =>
      agent.status === 'active' &&
      agent.platform === 'win32' &&
      agent.declaredCapabilities?.includes('windows-store-only-acme-v1') &&
      agent.declaredCapabilities?.includes('evidence-claim-binding-v1')
  );
  const change = (name, value) => {
    key.current = null;
    setFields(current => ({ ...current, [name]: value }));
  };
  const submit = async () => {
    key.current ||= crypto.randomUUID();
    setBusy(true);
    setMessage('');
    try {
      const result = await createJob(workspaceId, {
        operation: 'issue',
        mode: 'real',
        assignedAgentId: fields.agentId,
        idempotencyKey: key.current,
        payload: {
          target: {
            type: 'windows-cert-store',
            reference: fields.name.trim(),
            store: 'My',
          },
          caEndpoint: fields.endpoint.trim(),
          commandRef: fields.command.trim(),
          dnsProvider: fields.provider.trim(),
          dnsZone: fields.zone.trim(),
          keyAlgorithm: 'rsa',
          keySize: 2048,
        },
      });
      setMessage(
        `Issuance job ${result.job.id} created. The certificate must still be configured on the service.`
      );
      onCreated?.();
    } catch (error) {
      setMessage(
        error?.response?.data?.error || 'Could not create the issuance job.'
      );
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal isOpen={isOpen} onClose={onClose}>
      <ModalOverlay />
      <ModalContent>
        <ModalHeader>Issue to Windows certificate store</ModalHeader>
        <ModalBody>
          <Stack spacing={3}>
            <Text fontSize='sm'>
              Choose an agent configured for the ACME server, DNS provider and
              allowed command.
            </Text>
            <FormControl>
              <FormLabel htmlFor='acme-store-agent'>Windows agent</FormLabel>
              <Select
                id='acme-store-agent'
                value={fields.agentId}
                onChange={e => change('agentId', e.target.value)}
                placeholder='Choose agent'
              >
                {eligible.map(agent => (
                  <option key={agent.id} value={agent.id}>
                    {agent.name || agent.id}
                  </option>
                ))}
              </Select>
            </FormControl>
            {['name', 'endpoint', 'command', 'provider', 'zone'].map(
              (field, index) => (
                <FormControl key={field}>
                  <FormLabel htmlFor={`acme-store-${field}`}>
                    {
                      [
                        'DNS name',
                        'ACME directory URL',
                        'Allowed command name',
                        'DNS provider',
                        'DNS zone',
                      ][index]
                    }
                  </FormLabel>
                  <Input
                    id={`acme-store-${field}`}
                    value={fields[field]}
                    onChange={e => change(field, e.target.value)}
                  />
                </FormControl>
              )
            )}
            {message && (
              <Alert status='info'>
                <AlertIcon />
                {message}
              </Alert>
            )}
          </Stack>
        </ModalBody>
        <ModalFooter>
          <Button variant='ghost' onClick={onClose}>
            Close
          </Button>
          <Button
            colorScheme='blue'
            onClick={submit}
            isLoading={busy}
            isDisabled={Object.values(fields).some(value => !value.trim())}
          >
            Issue certificate
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
}
