import { useEffect, useState } from 'react';
import { Button, Checkbox, Input, Text, VStack } from '@chakra-ui/react';
import apiClient from '../../utils/apiClient';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { useCertOpsCanManage } from './useCertOps.js';

export default function AcmeStoreRecovery({ job }) {
  const { workspaceId } = useWorkspace();
  const canManage = useCertOpsCanManage();
  const [enrollment, setEnrollment] = useState(null);
  const [reason, setReason] = useState('');
  const [ack, setAck] = useState(false);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const base = `/api/v1/workspaces/${encodeURIComponent(workspaceId || '')}/certops/acme-store-enrollments`;
  useEffect(() => {
    setEnrollment(null);
    setAck(false);
    setReason('');
    setMessage('');
    if (
      !workspaceId ||
      !canManage ||
      job?.status !== 'orphaned_unknown_effect' ||
      !job?.id
    )
      return undefined;
    let cancelled = false;
    apiClient
      .get(`${base}/by-job/${encodeURIComponent(job.id)}`)
      .then(res => {
        if (!cancelled) setEnrollment(res.data);
      })
      .catch(() => {
        if (!cancelled) setEnrollment(null);
      });
    return () => {
      cancelled = true;
    };
  }, [workspaceId, canManage, job?.id, job?.status, base]);
  if (!enrollment?.outcomeUncertain) return null;
  const recover = async () => {
    setBusy(true);
    setMessage('');
    try {
      const res = await apiClient.post(
        `${base}/${encodeURIComponent(enrollment.enrollmentId)}/recover`,
        {
          orphanedJobId: job.id,
          reason,
          acknowledgeUnknownEffect: true,
        }
      );
      setEnrollment(value => ({ ...value, recoveryAvailable: false }));
      setMessage(
        `Recovery job ${res.data.jobId} queued for the original agent.`
      );
    } catch (error) {
      setMessage(
        error?.response?.data?.error || 'Recovery could not be queued.'
      );
    } finally {
      setBusy(false);
    }
  };
  return (
    <VStack align='stretch' spacing={2}>
      <Text fontSize='xs'>
        The ACME outcome is uncertain. Recovery uses the original agent and will
        not place a replacement order.
      </Text>
      {enrollment.recoveryAvailable && (
        <>
          <Input
            size='sm'
            aria-label='Recovery reason'
            placeholder='Reason for recovery'
            value={reason}
            onChange={e => setReason(e.target.value)}
            maxLength={500}
          />
          <Checkbox
            size='sm'
            isChecked={ack}
            onChange={e => setAck(e.target.checked)}
          >
            I understand the original outcome may be unknown
          </Checkbox>
          <Button
            size='sm'
            onClick={recover}
            isLoading={busy}
            isDisabled={!ack || !reason.trim()}
          >
            Recover on original agent
          </Button>
        </>
      )}
      {message && <Text fontSize='xs'>{message}</Text>}
    </VStack>
  );
}
