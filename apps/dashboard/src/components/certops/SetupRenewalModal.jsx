import { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
  Box,
  Button,
  Flex,
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
  Radio,
  RadioGroup,
  SimpleGrid,
  Spinner,
  Stack,
  Switch,
  Text,
  VStack,
  useColorModeValue,
} from '@chakra-ui/react';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import { setUpCertificateRenewal } from './certopsApi.js';
import { listRenewalProfiles } from './certopsRenewalApi.js';

/** A profile is only offerable as a preset when it carries all four fields
 * this modal needs; an incomplete or pre-derivation row would just hand the
 * user blanks with extra steps. */
function isUsablePreset(profile) {
  const renewal = profile?.renewalProfile;
  return Boolean(
    renewal?.acme?.commandRef &&
      renewal?.ca?.endpoint &&
      renewal?.dns?.provider &&
      renewal?.dns?.zone
  );
}

/**
 * The filesystem path a profile's own renewal deploys the certificate to.
 *
 * A profile is bound to the deployment it was derived from (see the
 * `certPath`/`deploymentTargets` immutability rule in
 * renewalProfileAdmin.js), so surfacing it here lets the operator notice a
 * profile meant for a different certificate before picking it, even though
 * this certificate's own discovered path is what the resulting job actually
 * deploys to. `deploymentTargets` is the current shape; `target` is kept as
 * a fallback for older single-target profiles.
 */
function presetCertPath(profile) {
  const renewal = profile?.renewalProfile;
  const targets = Array.isArray(renewal?.deploymentTargets)
    ? renewal.deploymentTargets
    : renewal?.target
      ? [renewal.target]
      : [];
  return targets[0]?.certPath || null;
}

/**
 * "Set up automatic renewal" (adopt-via-issuance, U7).
 *
 * This is not a settings save: confirming renews the certificate right now,
 * onto the deployment path TokenTimer already discovered, and only a
 * successful run derives a renewal profile. The certificate is not eligible
 * without an agent-deployable key and exactly one deployment location; the
 * server enforces both and this modal surfaces whichever precondition it
 * refuses on rather than guessing them client-side.
 *
 * The ACME command, CA endpoint, and DNS provider/zone are asked for because
 * this certificate has no prior issuance job to derive them from; a
 * certificate TokenTimer originally issued already has a profile and never
 * reaches this modal. Typing these from memory is error-prone (they must
 * match strings the agent already knows), so when the workspace already has
 * usable renewal profiles this defaults to picking one of them as a preset;
 * manual entry stays available as a fallback via the switch below.
 */
export default function SetupRenewalModal({
  isOpen,
  onClose,
  workspaceId,
  certificate,
  onSetUp,
}) {
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    outlineButtonProps,
    primaryButtonProps,
  } = useDashboardModalProps();
  const muted = useColorModeValue('gray.600', 'gray.400');
  const cardBorder = useColorModeValue('gray.200', 'gray.600');
  const cardSelectedBorder = useColorModeValue('blue.400', 'blue.300');
  const cardSelectedBg = useColorModeValue('blue.50', 'whiteAlpha.100');

  const [presets, setPresets] = useState([]);
  const [loadingPresets, setLoadingPresets] = useState(false);
  const [manualEntry, setManualEntry] = useState(false);
  const [selectedPresetId, setSelectedPresetId] = useState('');

  const [commandRef, setCommandRef] = useState('');
  const [caEndpoint, setCaEndpoint] = useState('');
  const [dnsZone, setDnsZone] = useState('');
  const [dnsProvider, setDnsProvider] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!isOpen) return;
    setCommandRef('');
    setCaEndpoint('');
    setDnsZone('');
    setDnsProvider('');
    setSubmitting(false);
    setError('');
    setManualEntry(false);
    setSelectedPresetId('');
    setPresets([]);

    if (!workspaceId) return;
    let cancelled = false;
    setLoadingPresets(true);
    listRenewalProfiles(workspaceId, { limit: 50 })
      .then(data => {
        if (cancelled) return;
        const usable = (Array.isArray(data?.items) ? data.items : []).filter(
          isUsablePreset
        );
        setPresets(usable);
        if (usable.length > 0) setSelectedPresetId(usable[0].id);
        else setManualEntry(true);
      })
      .catch(() => {
        // Presets are a convenience, not a requirement: if the list can't be
        // fetched, fall straight back to the manual form rather than
        // blocking the whole modal on it.
        if (!cancelled) setManualEntry(true);
      })
      .finally(() => {
        if (!cancelled) setLoadingPresets(false);
      });

    return () => {
      cancelled = true;
    };
  }, [isOpen, workspaceId]);

  const handleClose = () => {
    if (submitting) return;
    onClose();
  };

  const certName =
    certificate?.commonName ||
    (Array.isArray(certificate?.subjectAltNames)
      ? certificate.subjectAltNames[0]
      : null) ||
    certificate?.id;
  const certificatePath = certificate?.deployedCertPath || null;

  const selectedPreset = presets.find(p => p.id === selectedPresetId) || null;
  const usingPreset = !manualEntry && presets.length > 0;
  const selectedPresetPath = selectedPreset ? presetCertPath(selectedPreset) : null;
  const pathMismatch = Boolean(
    usingPreset &&
      certificatePath &&
      selectedPresetPath &&
      selectedPresetPath !== certificatePath
  );

  const resolvedFields = usingPreset
    ? {
        commandRef: selectedPreset?.renewalProfile?.acme?.commandRef || '',
        caEndpoint: selectedPreset?.renewalProfile?.ca?.endpoint || '',
        dnsZone: selectedPreset?.renewalProfile?.dns?.zone || '',
        dnsProvider: selectedPreset?.renewalProfile?.dns?.provider || '',
      }
    : {
        commandRef: commandRef.trim(),
        caEndpoint: caEndpoint.trim(),
        dnsZone: dnsZone.trim(),
        dnsProvider: dnsProvider.trim(),
      };

  const canSubmit =
    Boolean(workspaceId) &&
    Boolean(certificate?.id) &&
    !submitting &&
    !loadingPresets &&
    (usingPreset ? Boolean(selectedPreset) : true) &&
    Boolean(resolvedFields.commandRef) &&
    Boolean(resolvedFields.caEndpoint) &&
    Boolean(resolvedFields.dnsZone) &&
    Boolean(resolvedFields.dnsProvider);

  const handleConfirm = async () => {
    if (!canSubmit) return;
    setSubmitting(true);
    setError('');
    try {
      const { job } = await setUpCertificateRenewal(
        workspaceId,
        certificate.id,
        { payload: resolvedFields }
      );
      onSetUp?.(job);
      onClose();
    } catch (err) {
      setError(setupErrorMessage(err));
      setSubmitting(false);
    }
  };

  const toggleManualEntry = useCallback(() => {
    setManualEntry(prev => !prev);
  }, []);

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      isCentered
      scrollBehavior='inside'
    >
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame maxW={{ base: 'calc(100vw - 24px)', md: '560px' }}>
        <ModalHeader {...headerProps}>
          <DashboardModalTitle>Set up automatic renewal</DashboardModalTitle>
          <DashboardModalDescription>
            This renews{' '}
            <Text as='span' fontWeight='semibold'>
              {certName}
            </Text>{' '}
            right now, onto the deployment path TokenTimer already
            discovered{certificatePath ? (
              <>
                {' '}
                (
                <Text as='span' fontFamily='mono'>
                  {certificatePath}
                </Text>
                )
              </>
            ) : null}
            . Only once that succeeds does a renewal profile get created, so
            future renewals happen automatically.
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} isDisabled={submitting} />
        <ModalBody {...bodyProps}>
          <VStack align='stretch' spacing={4}>
            {loadingPresets ? (
              <HStack spacing={2} color={muted} py={4} justify='center'>
                <Spinner size='sm' />
                <Text fontSize='sm'>Checking existing renewal profiles...</Text>
              </HStack>
            ) : (
              <>
                {presets.length > 0 ? (
                  <Flex justify='space-between' align='center'>
                    <Text fontSize='sm' fontWeight='medium'>
                      {usingPreset
                        ? 'Use an existing profile'
                        : 'Enter details manually'}
                    </Text>
                    <HStack spacing={2}>
                      <Text fontSize='xs' color={muted}>
                        Enter manually
                      </Text>
                      <Switch
                        size='sm'
                        isChecked={manualEntry}
                        onChange={toggleManualEntry}
                        aria-label='Enter renewal details manually'
                      />
                    </HStack>
                  </Flex>
                ) : null}

                {usingPreset ? (
                  <>
                    <Text fontSize='sm' color={muted}>
                      These settings become part of the renewal profile this
                      certificate will use, same as{' '}
                      <Text as='span' fontWeight='medium'>
                        {selectedPreset?.name}
                      </Text>
                      . A profile is bound to the path it was issued for, so
                      check each one's path below against this certificate's
                      own path above before picking it.
                    </Text>
                    <RadioGroup
                      value={selectedPresetId}
                      onChange={setSelectedPresetId}
                    >
                      <Stack spacing={2}>
                        {presets.map(preset => {
                          const renewal = preset.renewalProfile || {};
                          const certPath = presetCertPath(preset);
                          const selected = preset.id === selectedPresetId;
                          const mismatched = Boolean(
                            certificatePath && certPath && certPath !== certificatePath
                          );
                          return (
                            <Box
                              key={preset.id}
                              as='label'
                              p={3}
                              borderWidth='1px'
                              borderRadius='md'
                              cursor='pointer'
                              borderColor={
                                selected
                                  ? mismatched
                                    ? 'orange.400'
                                    : cardSelectedBorder
                                  : cardBorder
                              }
                              bg={selected ? cardSelectedBg : 'transparent'}
                            >
                              <Radio value={preset.id} size='sm'>
                                <Text fontSize='sm' fontWeight='medium'>
                                  {preset.name}
                                </Text>
                              </Radio>
                              <Stack
                                pl={6}
                                mt={1}
                                spacing={0}
                                fontSize='xs'
                                color={muted}
                              >
                                <Text>
                                  Command:{' '}
                                  <Text as='span' fontFamily='mono'>
                                    {renewal.acme?.commandRef}
                                  </Text>
                                </Text>
                                <Text noOfLines={1}>
                                  CA: {renewal.ca?.endpoint}
                                </Text>
                                <Text>
                                  DNS: {renewal.dns?.provider} &middot;{' '}
                                  {renewal.dns?.zone}
                                </Text>
                                <Text noOfLines={1}>
                                  Path:{' '}
                                  <Text
                                    as='span'
                                    fontFamily='mono'
                                    color={
                                      !certPath
                                        ? 'orange.500'
                                        : mismatched
                                          ? 'orange.500'
                                          : undefined
                                    }
                                    fontWeight={mismatched ? 'semibold' : undefined}
                                  >
                                    {certPath || 'Not recorded on this profile'}
                                  </Text>
                                </Text>
                              </Stack>
                            </Box>
                          );
                        })}
                      </Stack>
                    </RadioGroup>
                    {pathMismatch ? (
                      <Alert status='warning' variant='subtle' borderRadius='md'>
                        <AlertIcon boxSize={4} />
                        <AlertDescription fontSize='sm'>
                          <Text as='span' fontWeight='semibold'>
                            {selectedPreset?.name}
                          </Text>{' '}
                          deploys to{' '}
                          <Text as='span' fontFamily='mono'>
                            {selectedPresetPath}
                          </Text>
                          , not this certificate's own path (
                          <Text as='span' fontFamily='mono'>
                            {certificatePath}
                          </Text>
                          ). It looks like it belongs to a different
                          certificate; double-check before continuing.
                        </AlertDescription>
                      </Alert>
                    ) : null}
                  </>
                ) : (
                  <>
                    <Alert status='info' variant='subtle' borderRadius='md'>
                      <AlertIcon boxSize={4} />
                      <AlertDescription fontSize='sm'>
                        This is the one time these settings need to be
                        entered by hand: they become part of the renewal
                        profile this creates, so every later renewal reuses
                        them without asking again.
                      </AlertDescription>
                    </Alert>
                    <SimpleGrid columns={{ base: 1, sm: 2 }} spacing={3}>
                      <FormControl isRequired>
                        <FormLabel fontSize='sm'>
                          ACME command profile
                        </FormLabel>
                        <Input
                          size='sm'
                          value={commandRef}
                          onChange={event =>
                            setCommandRef(event.target.value)
                          }
                          placeholder='e.g. certbot-csr'
                          autoComplete='off'
                        />
                      </FormControl>
                      <FormControl isRequired>
                        <FormLabel fontSize='sm'>DNS provider</FormLabel>
                        <Input
                          size='sm'
                          value={dnsProvider}
                          onChange={event =>
                            setDnsProvider(event.target.value)
                          }
                          placeholder='e.g. cloudflare'
                          autoComplete='off'
                        />
                      </FormControl>
                    </SimpleGrid>
                    <FormControl isRequired>
                      <FormLabel fontSize='sm'>CA endpoint</FormLabel>
                      <Input
                        size='sm'
                        value={caEndpoint}
                        onChange={event => setCaEndpoint(event.target.value)}
                        placeholder='e.g. https://acme-v02.api.letsencrypt.org/directory'
                        autoComplete='off'
                      />
                    </FormControl>
                    <FormControl isRequired>
                      <FormLabel fontSize='sm'>DNS zone</FormLabel>
                      <Input
                        size='sm'
                        value={dnsZone}
                        onChange={event => setDnsZone(event.target.value)}
                        placeholder='e.g. example.com'
                        autoComplete='off'
                      />
                      <FormHelperText>
                        The zone the DNS-01 challenge record is created in.
                      </FormHelperText>
                    </FormControl>
                  </>
                )}
              </>
            )}

            {error ? (
              <Alert status='error' borderRadius='12px'>
                <AlertIcon />
                <AlertDescription fontSize='sm'>{error}</AlertDescription>
              </Alert>
            ) : null}
          </VStack>
        </ModalBody>
        <ModalFooter {...footerProps}>
          <Flex
            w='100%'
            gap={3}
            justify={{ base: 'stretch', sm: 'flex-end' }}
            direction={{ base: 'column-reverse', sm: 'row' }}
          >
            <Button
              onClick={handleClose}
              isDisabled={submitting}
              minW={{ base: '100%', sm: '104px' }}
              {...outlineButtonProps}
            >
              Cancel
            </Button>
            <Button
              onClick={handleConfirm}
              isDisabled={!canSubmit}
              isLoading={submitting}
              loadingText='Renewing'
              minW={{ base: '100%', sm: '196px' }}
              {...primaryButtonProps}
            >
              Renew and set up
            </Button>
          </Flex>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}

function setupErrorMessage(err) {
  const code = err?.response?.data?.code;
  const status = err?.response?.status;
  if (status === 403 || code === 'INSUFFICIENT_ROLE') {
    return 'You need workspace manager permission to set up automatic renewal.';
  }
  if (code === 'CERTOPS_RENEWAL_SETUP_ALREADY_CONFIGURED') {
    return 'This certificate already has a renewal profile. Detach it before setting renewal up again.';
  }
  if (code === 'CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE') {
    return "TokenTimer does not hold this certificate's key, so it is monitored only and cannot be renewed by an agent.";
  }
  if (code === 'CERTOPS_RENEWAL_SETUP_NO_DEPLOYED_PATH') {
    return 'No discovered deployment path is recorded for this certificate, so automatic renewal has nowhere to deploy to.';
  }
  if (code === 'CERTOPS_RENEWAL_SETUP_MULTI_LOCATION') {
    return (
      err?.response?.data?.error ||
      'This certificate is deployed to more than one location and only one can be automated today.'
    );
  }
  return (
    err?.response?.data?.error ||
    err?.message ||
    'Could not set up automatic renewal.'
  );
}
