import { useEffect, useState } from 'react';
import { Box, Button, HStack, Spinner, Text, VStack } from '@chakra-ui/react';
import apiClient from '../../utils/apiClient';
import { formatDateTime } from './certopsJobsFormat';

const PAGE_SIZE = 10;
const VERDICTS = {
  good: 'Not revoked',
  revoked: 'Revoked',
  issuer_revoked: 'CA revoked',
  unknown: 'Revocation unknown',
  not_configured: 'Revocation not configured',
  disabled: 'Revocation disabled',
  invalid_observation: 'Invalid revocation observation',
};

export default function CertificateObservationHistory({
  workspaceId,
  certificateId,
  fingerprintSha256,
}) {
  const [offset, setOffset] = useState(0);
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    setOffset(0);
  }, [workspaceId, certificateId, fingerprintSha256]);
  useEffect(() => {
    if (!workspaceId || !certificateId) return undefined;
    const controller = new AbortController();
    setLoading(true);
    setError('');
    setItems([]);
    apiClient
      .get(
        `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/certops/certificates/${encodeURIComponent(certificateId)}/observations`,
        {
          params: {
            limit: PAGE_SIZE,
            offset,
            ...(fingerprintSha256 ? { fingerprint: fingerprintSha256 } : {}),
          },
          signal: controller.signal,
        }
      )
      .then(({ data }) =>
        setItems(Array.isArray(data?.items) ? data.items : [])
      )
      .catch(err => {
        if (!controller.signal.aborted)
          setError(
            err?.response?.status === 409
              ? 'Certificate changed. Reload its details.'
              : 'Could not load observation history.'
          );
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [workspaceId, certificateId, fingerprintSha256, offset]);

  if (loading) return <Spinner size='sm' />;
  if (error) return <Text>{error}</Text>;
  if (!items.length && offset === 0)
    return (
      <Text>
        No observations for this registration and current fingerprint.
      </Text>
    );
  return (
    <VStack align='stretch' spacing={3}>
      {items.map(item => {
        const m = item.metadata || {};
        const verdict =
          m.observedRevocationVerdict || m.observedRevocationState;
        return (
          <Box key={item.id}>
            <Text fontWeight='medium'>
              {VERDICTS[verdict] || 'Revocation not reported'}
            </Text>
            <Text fontSize='sm'>
              {formatDateTime(item.observedAt || item.createdAt)} ·{' '}
              {m.agentId || m.source || 'Observer'}
            </Text>
            {m.targetHost ? <Text fontSize='sm'>{m.targetHost}</Text> : null}
            {m.fingerprintSha256 ? (
              <Text fontSize='sm' overflowWrap='anywhere'>
                SHA-256: {m.fingerprintSha256}
              </Text>
            ) : null}
            {m.locationSlot || m.filePath ? (
              <Text fontSize='sm'>{m.locationSlot || m.filePath}</Text>
            ) : null}
            {m.observedRevocationCheckedAt ? (
              <Text fontSize='sm'>
                Checked {formatDateTime(m.observedRevocationCheckedAt)}
              </Text>
            ) : null}
            {m.observedRevocationValidUntil ? (
              <Text fontSize='sm'>
                Evidence valid until{' '}
                {formatDateTime(m.observedRevocationValidUntil)}
              </Text>
            ) : null}
            {m.observedRevocationDetail ? (
              <Text fontSize='sm'>{m.observedRevocationDetail}</Text>
            ) : null}
          </Box>
        );
      })}
      <HStack>
        <Button
          size='sm'
          isDisabled={offset === 0}
          onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
        >
          Previous
        </Button>
        <Button
          size='sm'
          isDisabled={items.length < PAGE_SIZE}
          onClick={() => setOffset(offset + PAGE_SIZE)}
        >
          Next
        </Button>
      </HStack>
    </VStack>
  );
}
