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
import { createAdcsRenewalProfile } from './certopsRenewalApi';
import AdcsDocsLink from './AdcsDocsLink.jsx';
import { ADCS_DOCS } from '../../utils/docsUrls.js';
import { showSuccess } from '../../utils/toast.js';

const STEPS = ['Issuer', 'Deployment', 'Review'];

function errorText(err, fallback) {
  return err?.response?.data?.error || fallback;
}

function confirmedIssuers(issuers) {
  return (issuers || []).filter(
    issuer =>
      issuer.kind === 'adcs' &&
      Number(issuer.currentVersion) > 0 &&
      issuer.revalidationRequired !== true
  );
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

  const declaringAgents = agents.filter(
    agent =>
      agent.status === 'active' &&
      Array.isArray(agent.targetSelectors) &&
      agent.targetSelectors.includes(reference.trim())
  );

  async function handleCreate() {
    setBusy(true);
    setLocalError('');
    const dnsNames = extraNames
      .split(/[\s,]+/)
      .map(item => item.trim())
      .filter(Boolean);
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
      setStep(3);
    } catch (err) {
      setLocalError(errorText(err, 'Could not create the renewal profile.'));
    } finally {
      setBusy(false);
    }
  }

  const deploymentReady =
    reference.trim() && site.trim() && store.trim() && Number(port) >= 1 && Number(leadTime) >= 1;

  return (
    <Modal isOpen={isOpen} onClose={onClose} size='xl'>
      <ModalOverlay {...modal.overlayProps} />
      <DashboardModalFrame>
        <ModalHeader {...modal.headerProps}>
          <DashboardModalTitle>New AD CS renewal profile</DashboardModalTitle>
          <DashboardModalDescription>
            The renewal sweep uses this profile to enroll through the issuer you pin here.
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton {...modal.closeButtonProps} />
        <ModalBody {...modal.bodyProps}>
          <Stack spacing={4}>
            <HStack spacing={3} fontSize='xs'>
              {STEPS.map((label, index) => (
                <Text key={label} fontWeight={index === Math.min(step, 2) ? 'semibold' : 'normal'}>
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
                  No AD CS issuer has a chosen CA certificate yet. Open AD CS issuers,
                  use New issuer, and finish the check before creating a profile.
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
                    template stays on that issuer. This profile does not choose a
                    new one.
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
                    This becomes the certificate common name. An active agent must
                    already declare this DNS name as a target selector, or a renewal
                    job stays unclaimed.
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
                    <FormLabel {...modal.labelProps}>Certificate store</FormLabel>
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
                      {(keyAlgorithm === 'rsa' ? ['2048', '3072', '4096'] : ['256', '384']).map(
                        size => (
                          <option key={size} value={size}>
                            {size}
                          </option>
                        )
                      )}
                    </Select>
                  </FormControl>
                  <FormControl isRequired>
                    <FormLabel {...modal.labelProps}>Lead time (days)</FormLabel>
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
                  {name.trim()} enrolls {reference.trim()} from the selected issuer into{' '}
                  {site.trim()} on port {port}, store {store.trim()}. Automatic renewal starts
                  when that certificate expires within {leadTime} days.
                </Text>
                {declaringAgents.length === 0 ? (
                  <Alert status='warning' borderRadius='md'>
                    <AlertIcon />
                    <AlertDescription fontSize='sm'>
                      No active agent declares {reference.trim() || 'this name'} as a target.
                      Add it to the agent target selectors, or the renewal job will be created
                      and then stay unclaimed.
                    </AlertDescription>
                  </Alert>
                ) : (
                  <Alert status='success' borderRadius='md'>
                    <AlertIcon />
                    <AlertDescription fontSize='sm'>
                      {declaringAgents.length === 1
                        ? 'One active agent declares this name.'
                        : `${declaringAgents.length} active agents declare this name. The most recently seen agent receives the renewal.`}
                    </AlertDescription>
                  </Alert>
                )}
              </Stack>
            ) : null}
            {step === 3 ? (
              <Stack spacing={3}>
                <Alert status={created?.agentDeclaresName ? 'success' : 'warning'} borderRadius='md'>
                  <AlertIcon />
                  <AlertDescription fontSize='sm'>
                    {created?.agentDeclaresName
                      ? 'An active agent already declares this certificate name.'
                      : 'The profile is saved. No active agent declares this certificate name yet, so a renewal job would stay unclaimed.'}
                  </AlertDescription>
                </Alert>
                <Text fontSize='sm'>
                  Open the certificate in inventory and attach this profile with automation
                  enabled. The sweep enrolls it only after the certificate is inside the lead
                  time and an agent that declares the name is online.
                </Text>
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
            <Button {...modal.primaryButtonProps} isLoading={busy} onClick={handleCreate}>
              Create profile
            </Button>
          ) : null}
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}
