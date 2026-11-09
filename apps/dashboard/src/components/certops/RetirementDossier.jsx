import { useRef, useState } from 'react';
import {
  Alert,
  AlertIcon,
  Box,
  Button,
  Checkbox,
  FormControl,
  FormLabel,
  Input,
  Stack,
  Text,
} from '@chakra-ui/react';
import { distributionApi } from './distributionApi.js';

const evidenceKinds = [
  ['writerInventory', 'Writer and clone inventory'],
  ['writerIsolation', 'Writer isolation'],
  ['destinationIsolation', 'Destination isolation'],
  ['replacementReadback', 'Replacement readback'],
];

export default function RetirementDossier({ workspaceId, canManage }) {
  const [jobId, setJobId] = useState('');
  const [evidence, setEvidence] = useState({});
  const [items, setItems] = useState([]);
  const [selected, setSelected] = useState(null);
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const selectionEpoch = useRef(0);
  async function run(action) {
    const epoch = selectionEpoch.current;
    setBusy(true);
    setError('');
    try {
      await action();
    } catch (err) {
      if (epoch === selectionEpoch.current)
        setError(
          err.response?.data?.code || 'Unable to load the retirement dossier.'
        );
    } finally {
      setBusy(false);
    }
  }
  async function list() {
    const epoch = selectionEpoch.current;
    const result = await distributionApi.retirementDossiers(
      workspaceId,
      jobId.trim()
    );
    if (epoch !== selectionEpoch.current) return;
    setItems(result.items);
    setSelected(null);
    if (result.hasMore) setError('Only the newest 100 dossiers are shown.');
  }
  return (
    <Box as='details' mt={4}>
      <Text as='summary' cursor='pointer' fontSize='sm' fontWeight='semibold'>
        Review a retired destination
      </Text>
      <Stack spacing={3} mt={3}>
        <Alert status='warning'>
          <AlertIcon />
          Retirement review is advisory. History remains unknown, evidence is
          not verified by TokenTimer, and reconciliation stays required.
        </Alert>
        <Text fontSize='sm'>
          Keep the source evidence in your own evidence system. Enter SHA-256
          digests for each record; the reviewer must inspect the underlying
          records independently.
        </Text>
        <FormControl>
          <FormLabel>Original job ID</FormLabel>
          <Input
            value={jobId}
            onChange={e => {
              selectionEpoch.current++;
              setJobId(e.target.value);
              setItems([]);
              setSelected(null);
              setConfirmed(false);
            }}
          />
        </FormControl>
        <Button
          size='sm'
          alignSelf='start'
          isLoading={busy}
          onClick={() => {
            selectionEpoch.current++;
            setSelected(null);
            setConfirmed(false);
            run(list);
          }}
        >
          Find dossiers
        </Button>
        {items.map(item => (
          <Button
            key={item.id}
            size='sm'
            variant='outline'
            onClick={() => {
              selectionEpoch.current++;
              run(async () => {
                const epoch = selectionEpoch.current;
                setSelected(null);
                setConfirmed(false);
                const detail = await distributionApi.retirementDossier(
                  workspaceId,
                  item.id
                );
                if (epoch !== selectionEpoch.current) return;
                setSelected(detail);
                setConfirmed(false);
              });
            }}
          >
            {item.status.replaceAll('_', ' ')} · {item.id}
          </Button>
        ))}
        {selected && (
          <Box borderWidth='1px' borderRadius='md' p={3}>
            <Text fontWeight='semibold'>
              Scope: {selected.scopeStatus} · History: unknown
            </Text>
            <Text fontSize='sm' overflowWrap='anywhere'>
              Job: {selected.original_job_id} · Binding:{' '}
              {selected.scope.bindingId} · Original generation:{' '}
              {selected.scope.originalGeneration} · Current generation at
              request: {selected.scope.currentGeneration}
            </Text>
            <Text fontSize='sm' overflowWrap='anywhere'>
              Workspace: {workspaceId} · Group: {selected.scope.groupId} ·
              Original agent: {selected.scope.assignedAgentId} · Current agent:{' '}
              {selected.scope.currentAgentId} · Binding state:{' '}
              {selected.scope.bindingState} · Binding revision:{' '}
              {selected.scope.bindingAuthorizationRevision}
            </Text>
            <Text fontSize='sm' overflowWrap='anywhere'>
              Desired generation: {selected.scope.desiredGeneration} · Desired
              material version:{' '}
              {selected.scope.desiredMaterialVersionId || 'none'} · Requester:{' '}
              {selected.requested_by} · Reviewer:{' '}
              {selected.reviewed_by || 'not yet reviewed'}
            </Text>
            {evidenceKinds.map(([key, title]) => (
              <Text key={key} fontSize='sm' overflowWrap='anywhere'>
                {title}: {selected.evidence[key]}
              </Text>
            ))}
            {selected.status === 'pending_review' && canManage && (
              <Stack mt={3}>
                <Checkbox
                  isChecked={confirmed}
                  onChange={e => setConfirmed(e.target.checked)}
                >
                  I independently inspected the underlying records and
                  understand this does not verify fencing or clear
                  reconciliation.
                </Checkbox>
                <Button
                  size='sm'
                  alignSelf='start'
                  isDisabled={!confirmed || selected.scopeStatus !== 'current'}
                  isLoading={busy}
                  onClick={() =>
                    run(async () => {
                      const epoch = selectionEpoch.current;
                      await distributionApi.reviewRetirementDossier(
                        workspaceId,
                        selected.id,
                        selected.dossier_hash
                      );
                      if (epoch !== selectionEpoch.current) return;
                      const detail = await distributionApi.retirementDossier(
                        workspaceId,
                        selected.id
                      );
                      if (epoch !== selectionEpoch.current) return;
                      setSelected(detail);
                      setConfirmed(false);
                    })
                  }
                >
                  Record advisory review
                </Button>
              </Stack>
            )}
          </Box>
        )}
        {canManage && (
          <Box as='details'>
            <Text
              as='summary'
              cursor='pointer'
              fontSize='sm'
              fontWeight='semibold'
            >
              Prepare a new dossier
            </Text>
            <Stack mt={3} spacing={3}>
              {evidenceKinds.map(([key, title]) => (
                <FormControl key={key}>
                  <FormLabel>{title} digest</FormLabel>
                  <Input
                    placeholder='sha256:…'
                    value={evidence[key] || ''}
                    onChange={e =>
                      setEvidence({ ...evidence, [key]: e.target.value.trim() })
                    }
                  />
                </FormControl>
              ))}
              <Button
                size='sm'
                alignSelf='start'
                isLoading={busy}
                onClick={() =>
                  run(async () => {
                    const epoch = selectionEpoch.current;
                    await distributionApi.requestRetirementDossier(
                      workspaceId,
                      jobId.trim(),
                      evidence
                    );
                    if (epoch !== selectionEpoch.current) return;
                    await list();
                  })
                }
              >
                Request independent review
              </Button>
            </Stack>
          </Box>
        )}
        {error && (
          <Alert status='error'>
            <AlertIcon />
            {error}
          </Alert>
        )}
      </Stack>
    </Box>
  );
}
