import { useState } from 'react';
import { Box, Button, Select, Text } from '@chakra-ui/react';
import {
  listIisReassociationCandidates,
  reassociateWindowsSource,
} from './certopsApi';

export default function IisReassociation({ workspaceId, sourceId, onChanged }) {
  const [candidates, setCandidates] = useState(null);
  const [selected, setSelected] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const current = candidates?.find(item => item.currentId === selected);
  async function findTargets() {
    setBusy(true);
    setError('');
    setSelected('');
    try {
      const result = await listIisReassociationCandidates(
        workspaceId,
        sourceId
      );
      setCandidates(result.items || []);
    } catch {
      setError('Could not verify IIS targets. Try again.');
    } finally {
      setBusy(false);
    }
  }
  async function confirm() {
    if (!current) return;
    setBusy(true);
    setError('');
    try {
      await reassociateWindowsSource(workspaceId, sourceId, current);
      onChanged?.();
    } catch (err) {
      setError(
        err?.response?.data?.error ||
          'Reassociation failed. Refresh and check the target.'
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <Box mt={3}>
      <Text fontSize='sm'>
        This older registration may refer to a different certificate. Verify the
        IIS binding before moving its renewal profile.
      </Text>
      <Button size='sm' onClick={findTargets} isLoading={busy}>
        Find matching IIS binding
      </Button>
      {candidates?.length === 0 ? (
        <Text fontSize='sm'>
          No recently observed matching IIS binding. Check the agent and run
          discovery again.
        </Text>
      ) : null}
      {candidates?.length > 0 ? (
        <Select
          aria-label='IIS binding for reassociation'
          value={selected}
          onChange={e => setSelected(e.target.value)}
        >
          <option value=''>Select a binding</option>
          {candidates.map(item => (
            <option key={item.currentId} value={item.currentId}>
              {item.host} · {item.site}:{item.port} ·{' '}
              {item.expectedFingerprintSha256}
            </option>
          ))}
        </Select>
      ) : null}
      {current ? (
        <>
          <Text fontSize='sm'>
            Confirm {current.site}:{current.port}, DNS {current.expectedDnsName}
            , SHA-256 {current.expectedFingerprintSha256}. The profile retains
            its current enabled or disabled state.
          </Text>
          <Button size='sm' onClick={confirm} isLoading={busy}>
            Move renewal profile to this binding
          </Button>
        </>
      ) : null}
      {error ? (
        <Text color='red.400' role='alert'>
          {error}
        </Text>
      ) : null}
    </Box>
  );
}
