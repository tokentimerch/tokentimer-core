import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Box,
  Button,
  FormControl,
  FormLabel,
  HStack,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalContent,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Text,
  Textarea,
  VStack,
} from '@chakra-ui/react';
import apiClient from '../utils/apiClient.js';
import { useWorkspace } from '../utils/WorkspaceContext.jsx';

export default function PagerDutyIncidentActions({ tokenId, enabled }) {
  const { workspaceId } = useWorkspace();
  const [data, setData] = useState({ incidents: [], canManage: false });
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [dialog, setDialog] = useState(null);
  const [reason, setReason] = useState('');
  const root = `/api/v1/workspaces/${workspaceId}`;
  const scope = `${workspaceId}:${tokenId}:${enabled}`;
  const currentScope = useRef(scope);
  currentScope.current = scope;
  const load = useCallback(async () => {
    const response = await apiClient.get(
      `/api/v1/workspaces/${workspaceId}/tokens/${tokenId}/pagerduty-incidents`
    );
    if (currentScope.current === scope) setData(response.data);
  }, [workspaceId, tokenId, scope]);
  useEffect(() => {
    setData({ incidents: [], canManage: false });
    setError('');
    setDialog(null);
    setReason('');
    setBusy(false);
    if (!enabled || !workspaceId || !tokenId) return undefined;
    let active = true;
    apiClient
      .get(
        `/api/v1/workspaces/${workspaceId}/tokens/${tokenId}/pagerduty-incidents`
      )
      .then(response => {
        if (active) setData(response.data);
      })
      .catch(() => {
        if (active) setError('Could not load PagerDuty incidents.');
      });
    return () => {
      active = false;
    };
  }, [enabled, workspaceId, tokenId]);
  const run = async operation => {
    setBusy(true);
    setError('');
    try {
      await operation();
      if (currentScope.current !== scope) return;
      await load();
      if (currentScope.current !== scope) return;
      setDialog(null);
      setReason('');
    } catch (e) {
      if (currentScope.current !== scope) return;
      setError(
        e.response?.data?.error ||
          'The action could not be requested. Try again.'
      );
    } finally {
      if (currentScope.current === scope) setBusy(false);
    }
  };
  if (!enabled || (!data.incidents.length && !error)) return null;
  const incidentRoot = id => `${root}/pagerduty-incidents/${id}`;
  const close = () => {
    if (!busy) {
      setDialog(null);
      setReason('');
    }
  };
  return (
    <Box mt={4} aria-label='PagerDuty incidents' role='region'>
      <HStack justify='space-between'>
        <Text fontSize='sm' fontWeight='semibold'>
          PagerDuty incidents
        </Text>
        <Button size='xs' isLoading={busy} onClick={() => run(load)}>
          Refresh
        </Button>
      </HStack>
      {error && (
        <Text role='alert' color='red.500' fontSize='sm'>
          {error}
        </Text>
      )}
      <VStack align='stretch' spacing={3} mt={2}>
        {data.incidents.map(incident => (
          <Box key={incident.id} borderWidth='1px' borderRadius='md' p={3}>
            <Text fontSize='sm'>
              Expiration {String(incident.original_expiration).slice(0, 10)} ·{' '}
              {incident.state.replaceAll('_', ' ')}
            </Text>
            {incident.acknowledge_requested_at && (
              <Text fontSize='xs'>
                {incident.acknowledge_accepted_at
                  ? 'Acknowledgement accepted by PagerDuty'
                  : incident.acknowledge_exhausted
                    ? 'Acknowledgement failed; review the integration configuration'
                    : 'Acknowledgement queued'}
              </Text>
            )}
            {incident.operator_reason && (
              <Text fontSize='xs'>
                Resolution reason: {incident.operator_reason}
              </Text>
            )}
            {(incident.last_error || incident.acknowledge_error) && (
              <Text fontSize='xs' color='orange.500'>
                Delivery needs attention:{' '}
                {incident.last_error || incident.acknowledge_error}
              </Text>
            )}
            {data.canManage && (
              <HStack flexWrap='wrap' mt={2}>
                <Button
                  size='xs'
                  isDisabled={
                    busy ||
                    incident.state !== 'open' ||
                    (!!incident.acknowledge_requested_at &&
                      !incident.acknowledge_exhausted)
                  }
                  onClick={() =>
                    run(() =>
                      apiClient.post(`${incidentRoot(incident.id)}/actions`, {
                        action: 'acknowledge',
                      })
                    )
                  }
                >
                  Acknowledge
                </Button>
                <Button
                  size='xs'
                  isDisabled={busy || incident.state !== 'open'}
                  onClick={() => {
                    setError('');
                    setDialog(incident);
                  }}
                >
                  Resolve
                </Button>
              </HStack>
            )}
          </Box>
        ))}
      </VStack>
      <Modal isOpen={!!dialog} onClose={close} closeOnOverlayClick={!busy}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>Resolve PagerDuty incident?</ModalHeader>
          <ModalCloseButton isDisabled={busy} />
          <ModalBody>
            <Text fontSize='sm' mb={3}>
              This resolves this TokenTimer alert in PagerDuty without changing
              the asset expiration. Grouped incidents can remain open for other
              alerts. Later thresholds for this expiration cycle will not reopen
              it.
            </Text>
            <FormControl isRequired>
              <FormLabel>Reason</FormLabel>
              <Textarea
                value={reason}
                onChange={e => setReason(e.target.value)}
                maxLength={1000}
              />
            </FormControl>
            {error && (
              <Text role='alert' color='red.500' mt={3}>
                {error}
              </Text>
            )}
          </ModalBody>
          <ModalFooter gap={2}>
            <Button onClick={close} isDisabled={busy}>
              Cancel
            </Button>
            <Button
              colorScheme='red'
              isLoading={busy}
              isDisabled={reason.trim().length < 5}
              onClick={() =>
                run(() =>
                  apiClient.post(`${incidentRoot(dialog.id)}/actions`, {
                    action: 'resolve',
                    confirmed: true,
                    reason: reason.trim(),
                  })
                )
              }
            >
              Confirm resolve
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Box>
  );
}
