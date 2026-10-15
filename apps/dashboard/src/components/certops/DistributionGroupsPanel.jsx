import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Box,
  Button,
  HStack,
  Link,
  Select,
  Table,
  TableContainer,
  Tbody,
  Td,
  Text,
  Th,
  Thead,
  Tr,
} from '@chakra-ui/react';
import { Link as RouterLink } from 'react-router';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import apiClient from '../../utils/apiClient';
import { formatDateTime } from './certopsFormat';

export default function DistributionGroupsPanel() {
  const { workspaceId } = useWorkspace();
  const scope = useRef(workspaceId);
  scope.current = workspaceId;
  const sequence = useRef(0);
  const [groups, setGroups] = useState([]);
  const [groupId, setGroupId] = useState('');
  const [consumers, setConsumers] = useState([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const refresh = useCallback(async () => {
    if (!workspaceId) return;
    const request = ++sequence.current;
    const current = () =>
      scope.current === workspaceId && sequence.current === request;
    setLoading(true);
    setError('');
    try {
      const base = `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/certops/distribution-groups`;
      const response = await apiClient.get(base);
      const available = response.data.groups || [];
      if (!current()) return;
      setGroups(available);
      const selected = available.some(g => g.id === groupId)
        ? groupId
        : available[0]?.id || '';
      setGroupId(selected);
      const rows = selected
        ? (await apiClient.get(`${base}/${selected}/consumers`)).data
            .consumers || []
        : [];
      if (current()) setConsumers(rows);
    } catch {
      if (!current()) return;
      setConsumers([]);
      setError('Consumer status could not be loaded.');
    } finally {
      if (current()) setLoading(false);
    }
  }, [workspaceId, groupId]);
  useEffect(() => {
    setGroups([]);
    setConsumers([]);
    setGroupId('');
  }, [workspaceId]);
  useEffect(() => {
    void refresh();
  }, [refresh]);
  return (
    <Box>
      <HStack justify='space-between' mb={3}>
        <Text fontWeight='semibold'>Certificate distribution</Text>
        <Button size='sm' onClick={refresh} isLoading={loading}>
          Refresh
        </Button>
      </HStack>
      <Text fontSize='sm' mb={3}>
        Publication and consumer deployment are tracked separately. Each
        consumer shows its own certificate expiry and last verification.
      </Text>
      {error ? <Text role='alert'>{error}</Text> : null}
      {groups.length ? (
        <Select
          aria-label='Distribution group'
          value={groupId}
          onChange={e => setGroupId(e.target.value)}
          mb={3}
        >
          {groups.map(g => (
            <option key={g.id} value={g.id}>
              {g.managed_certificate_id} · {g.material_store_ref}
            </option>
          ))}
        </Select>
      ) : !loading && !error ? (
        <Text fontSize='sm'>No distribution groups configured.</Text>
      ) : null}
      {groupId && !error ? (
        <TableContainer>
          <Table size='sm'>
            <Thead>
              <Tr>
                {[
                  'Consumer',
                  'Desired version',
                  'Observed version',
                  'Served fingerprint',
                  'Deployed expiry',
                  'Verification',
                  'Status',
                ].map(label => (
                  <Th key={label}>{label}</Th>
                ))}
              </Tr>
            </Thead>
            <Tbody>
              {consumers.map(c => (
                <Tr key={c.binding_id}>
                  <Td title={c.assigned_agent_id}>{c.binding_id}</Td>
                  <Td>
                    {c.desired_material_version_id || 'Not assigned'}
                    <Text fontSize='xs'>
                      Generation {c.desired_generation || '—'}
                    </Text>
                  </Td>
                  <Td>
                    {c.observed_material_version_id || 'Not observed'}
                    <Text fontSize='xs'>
                      Generation {c.accepted_generation || '—'}
                    </Text>
                  </Td>
                  <Td title={c.observed_fingerprint_sha256 || ''}>
                    {c.observed_fingerprint_sha256?.slice(0, 16) || '—'}
                  </Td>
                  <Td>
                    {c.observed_valid_to
                      ? formatDateTime(c.observed_valid_to)
                      : 'Not observed'}
                  </Td>
                  <Td>
                    {c.verification_method || c.verification_policy}
                    <Text fontSize='xs'>
                      {c.observed_at
                        ? formatDateTime(c.observed_at)
                        : 'Never verified'}
                    </Text>
                  </Td>
                  <Td>
                    {c.converged
                      ? 'Verified and current'
                      : 'Needs verification'}
                    <Text fontSize='xs'>
                      {c.latest_deployment?.failureCode ||
                        c.latest_deployment?.stage ||
                        ''}
                    </Text>
                    {c.latest_deployment?.jobId ? (
                      <Link
                        as={RouterLink}
                        to={`/certops/jobs?job=${encodeURIComponent(c.latest_deployment.jobId)}`}
                      >
                        View job
                      </Link>
                    ) : null}
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        </TableContainer>
      ) : null}
    </Box>
  );
}
