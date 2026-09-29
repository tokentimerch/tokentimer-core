import { useCallback, useEffect, useState } from 'react';
import {
  Alert, AlertDescription, AlertIcon, Badge, Box, Button, FormControl,
  FormHelperText, FormLabel, HStack, Input, Select, Text, Textarea, VStack,
} from '@chakra-ui/react';
import {
  acknowledgeCsrNames, cancelCsrWorkflow, confirmCsrInstallation,
  createCsrWorkflow, getCsrWorkflow, importCsrSignedCertificate,
  listCertificateTargets, listCsrWorkflows,
} from './certopsApi.js';
import { containsPrivateKeyMaterial, PRIVATE_KEY_REFUSAL_MESSAGE } from './privateKeyScan.js';

const KEY_PACKAGE_EXTENSION = /\.(?:key|p8|p12|pfx|jks|keystore)$/i;
const TARGET_CHOICES = [
  ['host', 'Host'], ['load-balancer', 'Load balancer'],
  ['appliance', 'Appliance'], ['other', 'Other location'],
];

async function publicFileText(file) {
  if (!file) return '';
  if (KEY_PACKAGE_EXTENSION.test(file.name)) throw new Error('Choose a public CSR or certificate PEM, not a key package.');
  if (file.size > 64 * 1024) throw new Error('Public PEM must be 64 KB or smaller.');
  const text = await new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ''));
    reader.onerror = () => reject(new Error('Could not read the public PEM file.'));
    reader.readAsText(file);
  });
  if (containsPrivateKeyMaterial(text)) throw new Error(PRIVATE_KEY_REFUSAL_MESSAGE);
  return text;
}

function downloadCsr(csr) {
  const blob = new Blob([`${csr.csrPem}\n`], { type: 'application/pkcs10' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `tokentimer-${csr.id}.csr.pem`;
  link.click();
  URL.revokeObjectURL(url);
}

export default function CsrWorkflowPanel({ workspaceId, existingCertificateId = null, onChanged }) {
  const [items, setItems] = useState([]);
  const [targets, setTargets] = useState([]);
  const [selected, setSelected] = useState(null);
  const [csrPem, setCsrPem] = useState('');
  const [signedPem, setSignedPem] = useState('');
  const [targetId, setTargetId] = useState('');
  const [targetName, setTargetName] = useState('');
  const [targetType, setTargetType] = useState('host');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const refresh = useCallback(async () => {
    if (!workspaceId) return;
    const [workflows, knownTargets] = await Promise.all([
      listCsrWorkflows(workspaceId), listCertificateTargets(workspaceId, { limit: 100 }),
    ]);
    setItems(workflows.items || []);
    setTargets(knownTargets.items || []);
  }, [workspaceId]);

  useEffect(() => {
    refresh().catch(err => setError(err?.response?.data?.error || 'Could not load CSR workflows.'));
  }, [refresh]);

  useEffect(() => {
    if (!selected?.id || selected.status !== 'signed_pending_install') return undefined;
    const timer = window.setInterval(() => {
      getCsrWorkflow(workspaceId, selected.id).then(setSelected).catch(() => {});
    }, 15000);
    return () => window.clearInterval(timer);
  }, [selected?.id, selected?.status, workspaceId]);

  const act = async work => {
    setBusy(true);
    setError('');
    try {
      const result = await work();
      if (result?.id) setSelected(result);
      await refresh();
      onChanged?.();
    } catch (err) {
      setError(err?.response?.data?.error || err?.message || 'CSR action failed.');
    } finally {
      setBusy(false);
    }
  };

  const select = item => act(() => getCsrWorkflow(workspaceId, item.id));
  const create = () => act(() => {
    if (containsPrivateKeyMaterial(csrPem)) throw new Error(PRIVATE_KEY_REFUSAL_MESSAGE);
    const payload = {
      csrPem,
      ...(existingCertificateId ? { existingCertificateId } : {}),
      ...(targetId ? { targetId } : { target: { name: targetName, type: targetType } }),
    };
    return createCsrWorkflow(workspaceId, payload);
  });

  const namesChanged = selected?.namesChanged;
  const acknowledgementPending = namesChanged && !selected?.namesAcknowledgedAt;
  const awaitingInstall = selected?.status === 'signed_pending_install';
  const selectedTarget = targets.find(target => target.id === selected?.targetId);
  const manualEligible = selectedTarget && ['api', 'manual', 'import'].includes(selectedTarget.source)
    && !selectedTarget.domainMonitorId && !selected?.identityConflict;

  return (
    <VStack align='stretch' spacing={4} mt={6}>
      <Box borderWidth='1px' borderRadius='md' p={4}>
        <Text fontWeight='semibold' mb={1}>Public CSR workflow</Text>
        <Text fontSize='sm' mb={4}>Upload a CSR made where its private key lives. Only public CSR and certificate PEM reach TokenTimer.</Text>
        {existingCertificateId ? <Text fontSize='sm' mb={3}>Replacing certificate {existingCertificateId}</Text> : null}
        {error ? <Alert status='error' mb={3}><AlertIcon /><AlertDescription>{error}</AlertDescription></Alert> : null}
        <FormControl mb={3}>
          <FormLabel>CSR PEM</FormLabel>
          <Textarea value={csrPem} onChange={event => setCsrPem(event.target.value)} rows={5} fontFamily='mono' placeholder='-----BEGIN CERTIFICATE REQUEST-----' />
          <Input type='file' accept='.csr,.pem,.txt' mt={2} aria-label='Choose public CSR file'
            onChange={event => publicFileText(event.target.files?.[0]).then(setCsrPem).catch(err => setError(err.message))} />
        </FormControl>
        <FormControl mb={3}>
          <FormLabel>Existing target</FormLabel>
          <Select value={targetId} onChange={event => setTargetId(event.target.value)}>
            <option value=''>Create a target below</option>
            {targets.map(target => <option key={target.id} value={target.id}>{target.name || target.id}</option>)}
          </Select>
        </FormControl>
        {!targetId ? <HStack align='start' mb={3}>
          <FormControl><FormLabel>New target name</FormLabel><Input value={targetName} onChange={event => setTargetName(event.target.value)} /></FormControl>
          <FormControl><FormLabel>Type</FormLabel><Select value={targetType} onChange={event => setTargetType(event.target.value)}>
            {TARGET_CHOICES.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </Select></FormControl>
        </HStack> : null}
        <Button onClick={create} isLoading={busy} isDisabled={!csrPem.trim() || (!targetId && !targetName.trim())}>Save CSR</Button>
      </Box>

      <Box borderWidth='1px' borderRadius='md' p={4}>
        <Text fontWeight='semibold' mb={2}>CSR requests</Text>
        {items.length === 0 ? <Text fontSize='sm'>No CSR requests yet.</Text> : items.map(item => (
          <HStack key={item.id} justify='space-between' py={1}>
            <Text fontSize='sm'>{item.requestedNames?.join(', ') || item.subject || item.id}</Text>
            <HStack><Badge colorScheme={item.identityConflict ? 'red' : undefined}>
              {item.identityConflict ? 'Identity conflict' : item.status.replaceAll('_', ' ')}
            </Badge><Button size='sm' onClick={() => select(item)}>Open</Button></HStack>
          </HStack>
        ))}
      </Box>

      {selected ? <Box borderWidth='1px' borderRadius='md' p={4}>
        <HStack justify='space-between' mb={3}>
          <Text fontWeight='semibold'>CSR {selected.id}</Text>
          <Badge>{selected.status.replaceAll('_', ' ')}</Badge>
        </HStack>
        <Text fontSize='sm'>Requested: {selected.requestedNames?.join(', ') || 'No names'}</Text>
        <Text fontSize='sm'>CSR SHA-256: {selected.csrDerSha256}</Text>
        <HStack mt={3}>
          <Button size='sm' onClick={() => downloadCsr(selected)} isDisabled={!selected.csrPem}>Export public CSR</Button>
          {selected.status !== 'completed' && selected.status !== 'cancelled' ?
            <Button size='sm' variant='outline' onClick={() => act(() => cancelCsrWorkflow(workspaceId, selected.id))} isLoading={busy}>Cancel</Button> : null}
        </HStack>
        {selected.status === 'pending_signature' ? <FormControl mt={4}>
          <FormLabel>CA-signed public certificate PEM</FormLabel>
          <Textarea value={signedPem} onChange={event => setSignedPem(event.target.value)} rows={5} fontFamily='mono' placeholder='-----BEGIN CERTIFICATE-----' />
          <Input type='file' accept='.crt,.cer,.pem,.txt' mt={2} aria-label='Choose signed public certificate file'
            onChange={event => publicFileText(event.target.files?.[0]).then(setSignedPem).catch(err => setError(err.message))} />
          <FormHelperText>Leaf first, followed by an optional public CA chain.</FormHelperText>
          <Button mt={2} onClick={() => act(() => importCsrSignedCertificate(workspaceId, selected.id, signedPem))}
            isLoading={busy} isDisabled={!signedPem.trim()}>Import signed certificate</Button>
        </FormControl> : null}
        {selected.issuedNames?.length ? <Text fontSize='sm' mt={3}>Issued: {selected.issuedNames.join(', ')}</Text> : null}
        {namesChanged ? <Alert status='warning' mt={3}><AlertIcon /><AlertDescription>
          Names added: {selected.nameAdditions?.join(', ') || 'none'}; omitted: {selected.nameOmissions?.join(', ') || 'none'}.
        </AlertDescription></Alert> : null}
        {selected.identityConflict ? <Alert status='error' mt={3}><AlertIcon /><AlertDescription>
          A matching certificate was observed at this target, but its instance belongs to managed certificate
          {' '}{selected.identityConflict.observedCertificateId}, not the selected certificate
          {' '}{selected.existingCertificateId}. The observation remains in deployment history; this CSR cannot
          promote or be manually confirmed until the identities are reconciled. Review the two certificate
          records and cancel this workflow if B is the intended identity.
        </AlertDescription></Alert> : null}
        {awaitingInstall ? <HStack mt={3}>
          {acknowledgementPending ? <Button size='sm' onClick={() => act(() => acknowledgeCsrNames(workspaceId, selected.id))}
            isLoading={busy}>Acknowledge name changes</Button> : null}
          {manualEligible ? <Button size='sm' onClick={() => act(() => confirmCsrInstallation(workspaceId, selected.id))}
            isLoading={busy} isDisabled={acknowledgementPending}>Confirm installation</Button> :
            <Text fontSize='sm'>{selected.identityConflict ? 'Identity reconciliation required.' : 'Waiting for target observation.'}</Text>}
          {selected.observedInstanceId ? <Text fontSize='sm'>Observed at target; ready to complete after review.</Text> : null}
        </HStack> : null}
        {selected.status === 'completed' ? <Text fontSize='sm' mt={3}>
          Completed by {selected.confirmationMethod === 'manual' ? 'manager attestation' : 'target observation'}.
        </Text> : null}
      </Box> : null}
    </VStack>
  );
}
