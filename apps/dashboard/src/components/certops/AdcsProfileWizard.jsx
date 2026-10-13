import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Button,
  FormControl,
  FormHelperText,
  FormLabel,
  HStack,
  Input,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Select,
  SimpleGrid,
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
import { listCertificates, replaceManagingSource } from './certopsApi';
import { createAdcsRenewalProfile } from './certopsRenewalApi';
import { sourceLabel } from './certopsFormat.js';
import AdcsDocsLink from './AdcsDocsLink.jsx';
import { ADCS_DOCS } from '../../utils/docsUrls.js';
import { showSuccess } from '../../utils/toast.js';

const STEPS = ['Issuer', 'Deployment', 'Review', 'Attach'];

function errorText(err, fallback) {
  return err?.response?.data?.error || fallback;
}

function sameDns(left, right) {
  return (
    String(left || '')
      .trim()
      .toLowerCase() ===
    String(right || '')
      .trim()
      .toLowerCase()
  );
}

function confirmedIssuers(issuers) {
  return (issuers || []).filter(
    issuer =>
      issuer.kind === 'adcs' &&
      Number(issuer.currentVersion) > 0 &&
      issuer.revalidationRequired !== true
  );
}

function namesOf(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value;
  return [];
}

function certificateUsesName(certificate, dnsName) {
  if (
    sameDns(certificate?.commonName, dnsName) ||
    sameDns(certificate?.name, dnsName)
  ) {
    return true;
  }
  if (
    namesOf(certificate?.subjectAltNames).some(name => sameDns(name, dnsName))
  )
    return true;
  const sources = Array.isArray(certificate?.sources)
    ? certificate.sources
    : [];
  return sources.some(
    source =>
      sameDns(source?.commonName, dnsName) ||
      namesOf(source?.subjectAltNames).some(name => sameDns(name, dnsName))
  );
}

function sourceIsThisCertificate(certificate, source) {
  if (source?.endedAt) return false;
  if (!certificate?.identityId || !source?.currentIdentityId) return true;
  return source.currentIdentityId === certificate.identityId;
}

function wholeInRange(value, min, max) {
  if (!/^\d+$/.test(String(value || '').trim())) return false;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= min && parsed <= max;
}

function extraDnsNames(value, reference) {
  const names = [];
  for (const part of String(value || '').split(/[\s,]+/)) {
    const host = part.trim();
    if (
      !host ||
      sameDns(host, reference) ||
      names.some(name => sameDns(name, host))
    )
      continue;
    names.push(host);
  }
  return names;
}

function sweepSentence(dnsName, leadDays) {
  return `The sweep enrolls when the certificate is inside the ${leadDays} day lead time and an agent that declares ${dnsName} has passed the CA check and is online.`;
}

/**
 * One registration per managed certificate. An open period has to end before
 * the same registration can take a profile, which is the inventory re-add path.
 */
function targetsForCertificate(certificate) {
  const label = certificate.commonName || certificate.name || 'Certificate';
  const sources = Array.isArray(certificate.sources) ? certificate.sources : [];
  if (sources.length) {
    const latest = new Map();
    const openIds = new Set();
    for (const source of sources) {
      if (
        !source?.managedCertificateId ||
        !sourceIsThisCertificate(certificate, source)
      )
        continue;
      if (!source.periodEndedAt) openIds.add(source.managedCertificateId);
      const previous = latest.get(source.managedCertificateId);
      if (
        !previous ||
        new Date(source.startedAt) > new Date(previous.startedAt)
      ) {
        latest.set(source.managedCertificateId, source);
      }
    }
    const targets = [];
    for (const [managedCertificateId, source] of latest) {
      if (source.endedReason === 'endpoint_monitor_deleted') continue;
      const open = openIds.has(managedCertificateId);
      const hint = source.source ? sourceLabel(source.source) : '';
      const targetLabel = hint ? `${label} (${hint})` : label;
      if (!open && source.periodEndedAt) {
        targets.push({
          managedCertificateId,
          periodId: null,
          open: false,
          label: targetLabel,
          canAttach: true,
        });
      } else if (open) {
        targets.push({
          managedCertificateId,
          periodId: source.periodId || null,
          open: true,
          label: targetLabel,
          canAttach: Boolean(source.periodId),
        });
      }
    }
    return targets;
  }
  if (certificate.managed && certificate.managedCertificateId) {
    return [
      {
        managedCertificateId: certificate.managedCertificateId,
        periodId: null,
        open: true,
        label,
        canAttach: false,
      },
    ];
  }
  return [];
}

function targetsForName(certificates, dnsName) {
  const seen = new Set();
  const targets = [];
  for (const certificate of certificates || []) {
    if (!certificateUsesName(certificate, dnsName)) continue;
    for (const target of targetsForCertificate(certificate)) {
      if (seen.has(target.managedCertificateId)) continue;
      seen.add(target.managedCertificateId);
      targets.push(target);
    }
  }
  return targets;
}

export default function AdcsProfileWizard({
  isOpen,
  onClose,
  workspaceId,
  issuers,
  onCreated,
}) {
  const modal = useDashboardModalProps();
  const readyIssuers = useMemo(() => confirmedIssuers(issuers), [issuers]);
  const [step, setStep] = useState(0);
  const [name, setName] = useState('');
  const [issuerId, setIssuerId] = useState('');
  const [reference, setReference] = useState('');
  const [extraNames, setExtraNames] = useState('');
  const [site, setSite] = useState('Default Web Site');
  const [port, setPort] = useState('443');
  const [sniHost, setSniHost] = useState('');
  const [store, setStore] = useState('My');
  const [keyAlgorithm, setKeyAlgorithm] = useState('rsa');
  const [keySize, setKeySize] = useState('2048');
  const [leadTime, setLeadTime] = useState('30');
  const [agents, setAgents] = useState([]);
  const [busy, setBusy] = useState(false);
  const [localError, setLocalError] = useState('');
  const [created, setCreated] = useState(null);
  const [targets, setTargets] = useState([]);
  const [selectedId, setSelectedId] = useState('');
  const [matchesLoading, setMatchesLoading] = useState(false);
  const [lookupFailed, setLookupFailed] = useState(false);
  const [attached, setAttached] = useState(null);

  useEffect(() => {
    if (!isOpen) {
      setStep(0);
      setName('');
      setIssuerId('');
      setReference('');
      setExtraNames('');
      setSite('Default Web Site');
      setPort('443');
      setSniHost('');
      setStore('My');
      setKeyAlgorithm('rsa');
      setKeySize('2048');
      setLeadTime('30');
      setBusy(false);
      setLocalError('');
      setCreated(null);
      setTargets([]);
      setSelectedId('');
      setMatchesLoading(false);
      setLookupFailed(false);
      setAttached(null);
    }
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen || !workspaceId) return undefined;
    let cancelled = false;
    listAgents(workspaceId)
      .then(page => {
        if (!cancelled) setAgents(page.items || []);
      })
      .catch(() => {
        if (!cancelled) setAgents([]);
      });
    return () => {
      cancelled = true;
    };
  }, [isOpen, workspaceId]);

  useEffect(() => {
    if (!isOpen || step !== 3 || !created?.id || !workspaceId) return undefined;
    let cancelled = false;
    setMatchesLoading(true);
    setLookupFailed(false);
    listCertificates(workspaceId, {
      q: reference.trim(),
      grouped: true,
      limit: 100,
      excludeRetired: true,
    })
      .then(page => {
        if (cancelled) return;
        const next = targetsForName(page.items || [], reference.trim());
        setTargets(next);
        setSelectedId(
          next.find(target => target.canAttach)?.managedCertificateId || ''
        );
      })
      .catch(() => {
        if (cancelled) return;
        setTargets([]);
        setLookupFailed(true);
      })
      .finally(() => {
        if (!cancelled) setMatchesLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [isOpen, step, created?.id, workspaceId, reference]);

  const declaringAgents = agents.filter(
    agent =>
      agent.status === 'active' &&
      Array.isArray(agent.targetSelectors) &&
      agent.targetSelectors.includes(reference.trim())
  );
  const attachable = targets.filter(target => target.canAttach);
  const blocked = targets.filter(target => !target.canAttach);
  const selected =
    attachable.find(target => target.managedCertificateId === selectedId) ||
    null;
  const dnsName = reference.trim();

  async function handleCreate() {
    setBusy(true);
    setLocalError('');
    const dnsNames = extraDnsNames(extraNames, reference.trim());
    try {
      const profile = await createAdcsRenewalProfile(workspaceId, {
        name: name.trim(),
        issuerId,
        target: {
          type: 'windows-iis',
          reference: reference.trim(),
          store: store.trim(),
          binding: {
            site: site.trim(),
            port: Number(port),
            ...(sniHost.trim() ? { sniHost: sniHost.trim() } : {}),
          },
        },
        dnsNames,
        keyAlgorithm,
        keySize: Number(keySize),
        renewBeforeDays: Number(leadTime),
      });
      setCreated(profile);
      showSuccess('Renewal profile created.');
      if (onCreated) await onCreated();
      setMatchesLoading(true);
      setStep(3);
    } catch (err) {
      setLocalError(errorText(err, 'Could not create the renewal profile.'));
    } finally {
      setBusy(false);
    }
  }

  async function handleAttach() {
    if (!selected || !created?.id) return;
    setBusy(true);
    setLocalError('');
    try {
      await replaceManagingSource(workspaceId, selected.managedCertificateId, {
        periodId: selected.open && selected.periodId ? selected.periodId : null,
        renewalProfileId: created.id,
        automationEnabled: true,
      });
      setAttached(selected);
      showSuccess('Automatic renewal is on for this certificate.');
    } catch (err) {
      const code = err?.response?.data?.code;
      if (code === 'CERTOPS_MANAGEMENT_ALREADY_OPEN') {
        setLocalError(
          'This certificate is already being managed. Open it in Certificates, stop managing, then start managing again and choose this profile. Automation turns on with the profile.'
        );
      } else {
        // The server runs stop and start in one transaction, so a refusal
        // leaves the certificate exactly as it was.
        setLocalError(
          errorText(err, 'Could not attach the profile.') +
            ' Nothing changed; the certificate is still managed as before.'
        );
      }
    } finally {
      setBusy(false);
    }
  }

  const extraNameCount = extraDnsNames(extraNames, reference.trim()).length;
  const deploymentReady =
    reference.trim() &&
    site.trim() &&
    store.trim() &&
    wholeInRange(port, 1, 65535) &&
    wholeInRange(leadTime, 1, 365) &&
    extraNameCount <= 15;

  return (
    <Modal isOpen={isOpen} onClose={onClose} size='xl'>
      <ModalOverlay {...modal.overlayProps} />
      <DashboardModalFrame>
        <ModalHeader {...modal.headerProps}>
          <DashboardModalTitle>New AD CS renewal profile</DashboardModalTitle>
          <DashboardModalDescription>
            Choose a confirmed issuer, describe the IIS binding, then attach the
            profile to a certificate already in inventory.
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton {...modal.closeButtonProps} />
        <ModalBody {...modal.bodyProps}>
          <Stack spacing={4}>
            <HStack spacing={3} fontSize='xs' wrap='wrap'>
              {STEPS.map((label, index) => (
                <Text
                  key={label}
                  fontWeight={
                    index === Math.min(step, STEPS.length - 1)
                      ? 'semibold'
                      : 'normal'
                  }
                >
                  {index + 1}. {label}
                </Text>
              ))}
            </HStack>
            {localError ? (
              <Alert status='error' borderRadius='md'>
                <AlertIcon />
                <AlertDescription fontSize='sm'>{localError}</AlertDescription>
              </Alert>
            ) : null}
            {step === 0 && readyIssuers.length === 0 ? (
              <Alert status='warning' borderRadius='md'>
                <AlertIcon />
                <AlertDescription fontSize='sm'>
                  No AD CS issuer has a chosen CA certificate yet. Open AD CS
                  issuers, use New issuer, and finish the check before creating
                  a profile.
                </AlertDescription>
              </Alert>
            ) : null}
            {step === 0 ? (
              <Stack spacing={3}>
                <FormControl isRequired>
                  <FormLabel {...modal.labelProps}>Profile name</FormLabel>
                  <Input
                    {...modal.fieldProps}
                    aria-label='Profile name'
                    value={name}
                    maxLength={128}
                    onChange={event => setName(event.target.value)}
                  />
                </FormControl>
                <FormControl isRequired>
                  <FormLabel {...modal.labelProps}>AD CS issuer</FormLabel>
                  <Select
                    {...modal.fieldProps}
                    aria-label='AD CS issuer'
                    value={issuerId}
                    onChange={event => setIssuerId(event.target.value)}
                  >
                    <option value=''>Select a confirmed issuer</option>
                    {readyIssuers.map(issuer => (
                      <option key={issuer.id} value={issuer.id}>
                        {issuer.name}
                      </option>
                    ))}
                  </Select>
                  <FormHelperText>
                    Only issuers with a pinned CA certificate are listed. The
                    template stays on that issuer. This profile does not choose
                    a new one.
                  </FormHelperText>
                  <AdcsDocsLink href={ADCS_DOCS.renewalProfile}>
                    What a renewal profile records
                  </AdcsDocsLink>
                </FormControl>
              </Stack>
            ) : null}
            {step === 1 ? (
              <Stack spacing={3}>
                <FormControl isRequired>
                  <FormLabel {...modal.labelProps}>Certificate name</FormLabel>
                  <Input
                    {...modal.fieldProps}
                    aria-label='Certificate name'
                    placeholder='www.example.com'
                    value={reference}
                    onChange={event => setReference(event.target.value)}
                  />
                  <FormHelperText>
                    This becomes the certificate common name. An active agent
                    must already declare this DNS name as a target selector, or
                    the renewal sweep skips it and does not create an
                    enrollment.
                  </FormHelperText>
                  <AdcsDocsLink href={ADCS_DOCS.renewalProfile}>
                    Renewal profile
                  </AdcsDocsLink>
                </FormControl>
                <FormControl>
                  <FormLabel {...modal.labelProps}>Extra DNS names</FormLabel>
                  <Input
                    {...modal.fieldProps}
                    aria-label='Extra DNS names'
                    placeholder='www.example.com, example.com'
                    value={extraNames}
                    onChange={event => setExtraNames(event.target.value)}
                  />
                </FormControl>
                <SimpleGrid columns={{ base: 1, md: 2 }} spacing={3}>
                  <FormControl isRequired>
                    <FormLabel {...modal.labelProps}>IIS site</FormLabel>
                    <Input
                      {...modal.fieldProps}
                      aria-label='IIS site'
                      value={site}
                      onChange={event => setSite(event.target.value)}
                    />
                  </FormControl>
                  <FormControl isRequired>
                    <FormLabel {...modal.labelProps}>Port</FormLabel>
                    <Input
                      {...modal.fieldProps}
                      aria-label='IIS port'
                      value={port}
                      onChange={event => setPort(event.target.value)}
                    />
                  </FormControl>
                  <FormControl>
                    <FormLabel {...modal.labelProps}>SNI hostname</FormLabel>
                    <Input
                      {...modal.fieldProps}
                      aria-label='SNI hostname'
                      value={sniHost}
                      onChange={event => setSniHost(event.target.value)}
                    />
                  </FormControl>
                  <FormControl isRequired>
                    <FormLabel {...modal.labelProps}>
                      Certificate store
                    </FormLabel>
                    <Input
                      {...modal.fieldProps}
                      aria-label='Certificate store'
                      value={store}
                      onChange={event => setStore(event.target.value)}
                    />
                  </FormControl>
                </SimpleGrid>
                <SimpleGrid columns={{ base: 1, md: 3 }} spacing={3}>
                  <FormControl>
                    <FormLabel {...modal.labelProps}>Key</FormLabel>
                    <Select
                      {...modal.fieldProps}
                      aria-label='Key algorithm'
                      value={keyAlgorithm}
                      onChange={event => {
                        const next = event.target.value;
                        setKeyAlgorithm(next);
                        setKeySize(next === 'rsa' ? '2048' : '256');
                      }}
                    >
                      <option value='rsa'>RSA</option>
                      <option value='ecdsa'>ECDSA</option>
                    </Select>
                  </FormControl>
                  <FormControl>
                    <FormLabel {...modal.labelProps}>Key size</FormLabel>
                    <Select
                      {...modal.fieldProps}
                      aria-label='Key size'
                      value={keySize}
                      onChange={event => setKeySize(event.target.value)}
                    >
                      {(keyAlgorithm === 'rsa'
                        ? ['2048', '3072', '4096']
                        : ['256', '384']
                      ).map(size => (
                        <option key={size} value={size}>
                          {size}
                        </option>
                      ))}
                    </Select>
                  </FormControl>
                  <FormControl isRequired>
                    <FormLabel {...modal.labelProps}>
                      Lead time (days)
                    </FormLabel>
                    <Input
                      {...modal.fieldProps}
                      aria-label='Lead time'
                      value={leadTime}
                      onChange={event => setLeadTime(event.target.value)}
                    />
                  </FormControl>
                </SimpleGrid>
              </Stack>
            ) : null}
            {step === 2 ? (
              <Stack spacing={3}>
                <Text fontSize='sm'>
                  {name.trim()} enrolls {dnsName} from the selected issuer into{' '}
                  {site.trim()} on port {port}, store {store.trim()}. The next
                  step attaches this profile to a certificate already in
                  inventory and turns automation on.
                </Text>
                {declaringAgents.length === 0 ? (
                  <Alert status='warning' borderRadius='md'>
                    <AlertIcon />
                    <AlertDescription fontSize='sm'>
                      No active agent declares {dnsName || 'this name'} as a
                      target. Add it to that agent's declared target selectors
                      and restart the agent. The next heartbeat publishes the
                      name. Until then the renewal sweep skips this certificate.
                    </AlertDescription>
                  </Alert>
                ) : (
                  <Alert status='success' borderRadius='md'>
                    <AlertIcon />
                    <AlertDescription fontSize='sm'>
                      {declaringAgents.length === 1
                        ? 'One active agent declares this name. Renewal waits until it passes the CA check.'
                        : `${declaringAgents.length} active agents declare this name. Renewal goes to the most recently seen agent that has passed the CA check.`}
                    </AlertDescription>
                  </Alert>
                )}
              </Stack>
            ) : null}
            {step === 3 ? (
              <Stack spacing={3}>
                <Alert
                  status={created?.agentDeclaresName ? 'success' : 'warning'}
                  borderRadius='md'
                >
                  <AlertIcon />
                  <AlertDescription fontSize='sm'>
                    {created?.agentDeclaresName
                      ? 'An active agent already declares this certificate name. Run the CA check on that agent if you have not already. The check stores the CA certificate and template OID there.'
                      : 'The profile is saved. No active agent declares this certificate name yet. Add the name to the agent target selectors and restart the agent. The next heartbeat publishes it. Until then the renewal sweep skips this certificate.'}
                  </AlertDescription>
                </Alert>
                {matchesLoading ? (
                  <Text fontSize='sm'>
                    Looking for {dnsName} in Certificates.
                  </Text>
                ) : null}
                {!matchesLoading && lookupFailed ? (
                  <Alert status='warning' borderRadius='md'>
                    <AlertIcon />
                    <AlertDescription fontSize='sm'>
                      Could not check Certificates for {dnsName}. Open
                      Certificates later, open that certificate, and start
                      managing it again with this profile.
                      {` ${sweepSentence(dnsName, leadTime)}`}
                    </AlertDescription>
                  </Alert>
                ) : null}
                {!matchesLoading && !lookupFailed && targets.length === 0 ? (
                  <Alert status='warning' borderRadius='md'>
                    <AlertIcon />
                    <AlertDescription fontSize='sm'>
                      No certificate in inventory uses {dnsName}. This wizard
                      does not create one. Open Certificates later, open that
                      certificate, and start managing it again with this
                      profile. Do not attach a different certificate. That
                      leaves the other name in inventory.{' '}
                      {sweepSentence(dnsName, leadTime)}
                    </AlertDescription>
                  </Alert>
                ) : null}
                {!matchesLoading && blocked.length > 0 && !attached ? (
                  <Alert status='warning' borderRadius='md'>
                    <AlertIcon />
                    <AlertDescription fontSize='sm'>
                      {blocked[0].label} is already managed, and this screen
                      cannot change that registration. Open it in Certificates,
                      stop managing, then start managing again and choose this
                      profile. {sweepSentence(dnsName, leadTime)}
                    </AlertDescription>
                  </Alert>
                ) : null}
                {!matchesLoading && attachable.length > 0 && !attached ? (
                  <Stack spacing={3}>
                    {attachable.length > 1 ? (
                      <FormControl>
                        <FormLabel {...modal.labelProps}>Certificate</FormLabel>
                        <Select
                          {...modal.fieldProps}
                          aria-label='Certificate to attach'
                          value={selectedId}
                          onChange={event => setSelectedId(event.target.value)}
                        >
                          {attachable.map(target => (
                            <option
                              key={target.managedCertificateId}
                              value={target.managedCertificateId}
                            >
                              {target.label}
                            </option>
                          ))}
                        </Select>
                      </FormControl>
                    ) : (
                      <Text fontSize='sm'>
                        {selected?.open
                          ? `${selected.label} is already managed. Attaching stops that period and starts a new one with this profile and automation on. Earlier periods stay in history.`
                          : `Attach this profile to ${attachable[0].label} and turn automation on.`}
                      </Text>
                    )}
                    {attachable.length > 1 && selected?.open ? (
                      <Text fontSize='sm'>
                        This certificate is already managed. Attaching stops
                        that period and starts a new one with this profile and
                        automation on. Earlier periods stay in history.
                      </Text>
                    ) : null}
                    <Text fontSize='sm'>
                      {sweepSentence(dnsName, leadTime)}
                    </Text>
                  </Stack>
                ) : null}
                {attached ? (
                  <Alert status='success' borderRadius='md'>
                    <AlertIcon />
                    <AlertDescription fontSize='sm'>
                      Automatic renewal is on for {attached.label}.{' '}
                      {sweepSentence(dnsName, leadTime)}
                    </AlertDescription>
                  </Alert>
                ) : null}
              </Stack>
            ) : null}
          </Stack>
        </ModalBody>
        <ModalFooter {...modal.footerProps}>
          <Button {...modal.outlineButtonProps} onClick={onClose}>
            {step === 3 ? 'Done' : 'Close'}
          </Button>
          {step === 0 ? (
            <Button
              {...modal.primaryButtonProps}
              isDisabled={!name.trim() || !issuerId}
              onClick={() => setStep(1)}
            >
              Continue
            </Button>
          ) : null}
          {step === 1 ? (
            <Button
              {...modal.primaryButtonProps}
              isDisabled={!deploymentReady}
              onClick={() => {
                setLocalError('');
                setStep(2);
              }}
            >
              Review
            </Button>
          ) : null}
          {step === 2 ? (
            <Button
              {...modal.primaryButtonProps}
              isLoading={busy}
              onClick={handleCreate}
            >
              Create profile
            </Button>
          ) : null}
          {step === 3 && attachable.length > 0 && !attached ? (
            <Button
              {...modal.primaryButtonProps}
              isLoading={busy}
              isDisabled={matchesLoading || !selected}
              onClick={handleAttach}
            >
              Attach and enable automation
            </Button>
          ) : null}
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}
