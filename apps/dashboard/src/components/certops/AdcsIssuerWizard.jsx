import { useEffect, useRef, useState } from 'react';
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
  Stack,
  Text,
} from '@chakra-ui/react';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import { formatDate } from './certopsFormat.js';
import {
  confirmIssuerKey,
  createIssuer,
  discardIssuer,
  dispatchIssuerPreflight,
  listIssuers,
} from './certopsEnrollmentsApi';
import AdcsDocsLink from './AdcsDocsLink.jsx';
import { ADCS_DOCS } from '../../utils/docsUrls.js';
import { showError, showSuccess } from '../../utils/toast.js';

const STEPS = ['Name', 'Check the CA', 'Choose a certificate'];

function errorText(err, fallback) {
  return err?.response?.data?.error || fallback;
}

function reasonsOf(check) {
  return Array.isArray(check?.reasons) ? check.reasons.filter(Boolean) : [];
}

function certTime(value) {
  const time = Date.parse(value || '');
  return Number.isFinite(time) ? time : 0;
}

function groupCaCertificates(certs) {
  const groups = [];
  const indexByKey = new Map();
  (certs || []).forEach((cert, index) => {
    const keySha256 = cert?.keySha256;
    if (!keySha256) return;
    let group = indexByKey.get(keySha256);
    if (!group) {
      group = { keySha256, certificates: [], firstIndex: index };
      indexByKey.set(keySha256, group);
      groups.push(group);
    }
    group.certificates.push(cert);
  });
  for (const group of groups) {
    group.certificates.sort(
      (a, b) => certTime(b.notBefore) - certTime(a.notBefore)
    );
    group.thumbprintSha1 = group.certificates.find(
      cert => cert.thumbprintSha1
    )?.thumbprintSha1;
  }
  groups.sort(
    (a, b) =>
      certTime(b.certificates[0]?.notBefore) -
        certTime(a.certificates[0]?.notBefore) || a.firstIndex - b.firstIndex
  );
  return groups;
}

function adviceFor(issuer, agents) {
  if (!agents.length) {
    return {
      status: 'warning',
      text: 'No Windows agent is registered. Install the agent on a domain machine that can reach the CA, then open this wizard again.',
    };
  }
  const preflight = issuer?.lastPreflight;
  if (!preflight) {
    return {
      status: 'info',
      text: 'The check runs on the agent you select. It stores the CA certificate and the template OID on that agent, and it does not issue a certificate. Run it on the agent that will enroll. If this stays waiting, confirm that agent is online, that its enrollment rule names this CA and template, and that its build advertises AD CS preflight.',
    };
  }
  const notes = [];
  if (preflight.templateCheck?.verdict !== 'safe') {
    const reasons = reasonsOf(preflight.templateCheck);
    notes.push(
      `Template check is ${preflight.templateCheck?.verdict || 'missing'}${reasons.length ? `: ${reasons.join(', ')}` : ''}. Use the template common name the CA publishes, and make sure an agent enrollment rule names that same template.`
    );
  }
  if (preflight.caCheck?.verdict !== 'safe') {
    const reasons = reasonsOf(preflight.caCheck);
    notes.push(
      `CA check is ${preflight.caCheck?.verdict || 'missing'}${reasons.length ? `: ${reasons.join(', ')}` : ''}. CA config is the CA computer's DNS name, a backslash, and the CA name from the Certification Authority console.`
    );
  }
  if (notes.length) return { status: 'error', text: notes.join(' ') };
  if (!issuer.currentVersion || issuer.revalidationRequired) {
    return {
      status: 'info',
      text: 'Both checks are safe. Choose the newest CA certificate. Enrollment accepts only the certificate you pin here.',
    };
  }
  return {
    status: 'success',
    text: 'This issuer is ready. Create a renewal profile that selects it, then attach that profile to the certificate you want renewed.',
  };
}

function preflightCameBackUnsafe(issuer) {
  const preflight = issuer?.lastPreflight;
  if (!preflight) return false;
  return (
    preflight.templateCheck?.verdict === 'unsafe' ||
    preflight.caCheck?.verdict === 'unsafe'
  );
}

export default function AdcsIssuerWizard({
  isOpen,
  onClose,
  workspaceId,
  agents,
  paused,
  onChanged,
}) {
  const modal = useDashboardModalProps();
  const [step, setStep] = useState(0);
  const [name, setName] = useState('');
  const [issuer, setIssuer] = useState(null);
  const [agentId, setAgentId] = useState('');
  const [caConfig, setCaConfig] = useState('');
  const [template, setTemplate] = useState('');
  const [busy, setBusy] = useState(false);
  const [waiting, setWaiting] = useState(false);
  const [localError, setLocalError] = useState('');
  const draftIdRef = useRef(null);
  const finishedRef = useRef(false);

  useEffect(() => {
    if (!isOpen) {
      setStep(0);
      setName('');
      setIssuer(null);
      setAgentId('');
      setCaConfig('');
      setTemplate('');
      setBusy(false);
      setWaiting(false);
      setLocalError('');
      return;
    }
    finishedRef.current = false;
    draftIdRef.current = null;
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen || !waiting || !issuer?.id) return undefined;
    let cancelled = false;
    let attempts = 0;
    const timer = setInterval(async () => {
      attempts += 1;
      try {
        const page = await listIssuers(workspaceId, {
          limit: 100,
          includeUnconfigured: true,
        });
        if (cancelled) return;
        const current = (page.items || []).find(item => item.id === issuer.id);
        if (current) setIssuer(current);
        const safe =
          current?.lastPreflight?.templateCheck?.verdict === 'safe' &&
          current?.lastPreflight?.caCheck?.verdict === 'safe';
        if (safe || attempts >= 20) {
          setWaiting(false);
          if (safe) setStep(2);
        }
      } catch (err) {
        if (!cancelled) {
          setWaiting(false);
          setLocalError(
            errorText(err, 'Could not refresh the preflight verdict.')
          );
        }
      }
    }, 3000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [isOpen, waiting, issuer?.id, workspaceId]);

  const advice = step === 0 || step >= 3 ? null : adviceFor(issuer, agents);
  const groups = groupCaCertificates(issuer?.lastPreflight?.caCertificates);

  async function handleDismiss() {
    const draftId = draftIdRef.current;
    const finished = finishedRef.current;
    const keepUnsafe = preflightCameBackUnsafe(issuer);
    draftIdRef.current = null;
    if (draftId && !finished && !keepUnsafe) {
      try {
        await discardIssuer(workspaceId, draftId);
      } catch {
        // A draft that could not be discarded stays out of the list until a certificate is chosen.
      }
    }
    onClose();
    if (keepUnsafe && onChanged) await onChanged();
  }

  async function handlePreflight() {
    setBusy(true);
    setLocalError('');
    try {
      let issuerId = issuer?.id;
      if (!issuerId) {
        const created = await createIssuer(workspaceId, {
          kind: 'adcs',
          name: name.trim(),
        });
        issuerId = created?.issuer?.id;
        if (!issuerId) throw new Error('Could not start the CA check.');
        draftIdRef.current = issuerId;
        setIssuer({ id: issuerId, name: name.trim(), currentVersion: 0 });
      }
      await dispatchIssuerPreflight(workspaceId, issuerId, {
        agentId,
        caConfig: caConfig.trim(),
        template: template.trim(),
      });
      setWaiting(true);
      showSuccess(
        'Preflight dispatched. This wizard updates when the agent reports.'
      );
    } catch (err) {
      setLocalError(errorText(err, 'Could not dispatch preflight.'));
    } finally {
      setBusy(false);
    }
  }

  async function handleConfirm(keySha256) {
    setBusy(true);
    setLocalError('');
    try {
      await confirmIssuerKey(workspaceId, issuer.id, {
        caKeySha256: keySha256,
        caConfig: issuer.lastPreflight?.caConfig,
        template: issuer.lastPreflight?.template,
      });
      finishedRef.current = true;
      draftIdRef.current = null;
      showSuccess(
        'Issuer created. Enrollment runs only for a CA and template named by an agent enrollment rule.'
      );
      if (onChanged) await onChanged();
      setStep(3);
    } catch (err) {
      const message = errorText(err, 'Could not confirm the CA certificate.');
      setLocalError(message);
      showError(message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={handleDismiss} size='xl'>
      <ModalOverlay {...modal.overlayProps} />
      <DashboardModalFrame>
        <ModalHeader {...modal.headerProps}>
          <DashboardModalTitle>New AD CS issuer</DashboardModalTitle>
          <DashboardModalDescription>
            {STEPS[Math.min(step, 2)]}
            {step < 3 ? ` · step ${step + 1} of 3` : ''}
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton {...modal.closeButtonProps} />
        <ModalBody {...modal.bodyProps}>
          <Stack spacing={4}>
            <HStack spacing={3} fontSize='xs'>
              {STEPS.map((label, index) => (
                <Text
                  key={label}
                  fontWeight={
                    index === Math.min(step, 2) ? 'semibold' : 'normal'
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
            {advice ? (
              <Alert status={advice.status} borderRadius='md'>
                <AlertIcon />
                <AlertDescription fontSize='sm'>{advice.text}</AlertDescription>
              </Alert>
            ) : null}
            {waiting ? (
              <Text fontSize='sm'>
                Waiting for the agent to report the preflight verdict.
              </Text>
            ) : null}
            {step === 0 ? (
              <FormControl isRequired>
                <FormLabel {...modal.labelProps}>Issuer name</FormLabel>
                <Input
                  {...modal.fieldProps}
                  value={name}
                  aria-label='Issuer name'
                  maxLength={128}
                  onChange={event => setName(event.target.value)}
                />
                <FormHelperText>
                  A name you will recognize later, such as TTLab Issuing CA.
                </FormHelperText>
              </FormControl>
            ) : null}
            {step === 1 ? (
              <Stack spacing={3}>
                <FormControl isRequired>
                  <FormLabel {...modal.labelProps}>
                    Agent that reads the CA
                  </FormLabel>
                  <Select
                    {...modal.fieldProps}
                    aria-label='Preflight agent'
                    value={agentId}
                    onChange={event => setAgentId(event.target.value)}
                  >
                    <option value=''>Select an agent</option>
                    {agents.map(agent => (
                      <option key={agent.id} value={agent.id}>
                        {agent.name || agent.hostname || agent.agentId}
                      </option>
                    ))}
                  </Select>
                  <FormHelperText>
                    TokenTimer does not contact the CA. This Windows agent reads
                    the template and stores the CA certificate and template OID
                    for later enrollment. Run the check on the agent that will
                    enroll the certificate. A different agent cannot enroll
                    until it has run the same check.
                  </FormHelperText>
                </FormControl>
                <FormControl isRequired>
                  <FormLabel {...modal.labelProps}>CA config</FormLabel>
                  <Input
                    {...modal.fieldProps}
                    aria-label='CA config'
                    placeholder='ca01.corp.example.com\\Corp Issuing CA'
                    value={caConfig}
                    onChange={event => setCaConfig(event.target.value)}
                  />
                  <FormHelperText>
                    DNS host, a backslash, then the CA name from the
                    Certification Authority console. Use the same string as this
                    agent's enrollment rule.
                  </FormHelperText>
                  <AdcsDocsLink href={ADCS_DOCS.caConfig}>
                    Where the CA name comes from
                  </AdcsDocsLink>
                </FormControl>
                <FormControl isRequired>
                  <FormLabel {...modal.labelProps}>Template</FormLabel>
                  <Input
                    {...modal.fieldProps}
                    aria-label='Template'
                    placeholder='WebServer'
                    value={template}
                    onChange={event => setTemplate(event.target.value)}
                  />
                  <FormHelperText>
                    The template common name already published on that CA. In
                    Certificate Templates this is the Template name, not the
                    display name. TokenTimer does not create it, and the same
                    name must be in the agent's enrollment rule or the check
                    never contacts the CA.
                  </FormHelperText>
                  <AdcsDocsLink href={ADCS_DOCS.template}>
                    Where the template name comes from
                  </AdcsDocsLink>
                  <AdcsDocsLink href={ADCS_DOCS.enrollmentRules}>
                    How the agent allows this CA
                  </AdcsDocsLink>
                </FormControl>
              </Stack>
            ) : null}
            {step === 2 ? (
              <Stack spacing={3}>
                {groups.map((group, index) => (
                  <HStack
                    key={group.keySha256}
                    justify='space-between'
                    align='flex-start'
                  >
                    <Stack spacing={0}>
                      <Text fontSize='sm' fontWeight='semibold'>
                        {groups.length === 1
                          ? 'CA certificate'
                          : index === 0
                            ? 'Newest CA certificate'
                            : 'Earlier CA certificate'}
                      </Text>
                      <Text fontSize='xs'>
                        {group.thumbprintSha1 || group.keySha256.slice(0, 16)}
                        {group.certificates[0]
                          ? ` · ${formatDate(group.certificates[0].notBefore)} to ${formatDate(group.certificates[0].notAfter)}`
                          : ''}
                      </Text>
                    </Stack>
                    <Button
                      {...modal.primaryButtonProps}
                      size='sm'
                      isLoading={busy}
                      isDisabled={paused}
                      onClick={() => handleConfirm(group.keySha256)}
                    >
                      Use this certificate
                    </Button>
                  </HStack>
                ))}
              </Stack>
            ) : null}
            {step === 3 ? (
              <Text fontSize='sm'>
                Issuer saved. Renewal profiles is the shared list, above. Choose
                New AD CS profile there. The last step attaches the profile to a
                certificate already in inventory and turns automation on. The
                sweep enrolls when that certificate is inside the profile lead
                time and an agent that declares the DNS name has passed the CA
                check and is online.
              </Text>
            ) : null}
          </Stack>
        </ModalBody>
        <ModalFooter {...modal.footerProps}>
          <Button {...modal.outlineButtonProps} onClick={handleDismiss}>
            {step === 3 ? 'Done' : 'Close'}
          </Button>
          {step === 0 ? (
            <Button
              {...modal.primaryButtonProps}
              isDisabled={paused || !name.trim()}
              onClick={() => setStep(1)}
            >
              Continue
            </Button>
          ) : null}
          {step === 1 ? (
            <Button
              {...modal.primaryButtonProps}
              isLoading={busy || waiting}
              isDisabled={
                paused || !agentId || !caConfig.trim() || !template.trim()
              }
              onClick={handlePreflight}
            >
              Run check
            </Button>
          ) : null}
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}
