import { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
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
} from '@chakra-ui/react';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import { useDashboardThemeColors } from '../../hooks/useDashboardTheme';
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
 * Whether a preset can be shown to be bound to this exact certificate's
 * deployment, i.e. the "matching profiles" filter's positive case.
 *
 * `certPath` is the one fact both sides carry today, so it is the only
 * signal checked; a preset (or the certificate itself) with no recorded
 * path cannot be proven to mismatch, so it counts as matching rather than
 * being hidden by the default filter - only a demonstrable path conflict
 * does that.
 */
function presetMatchesCertificate(profile, certificatePath) {
  if (!certificatePath) return true;
  const presetPath = presetCertPath(profile);
  if (!presetPath) return true;
  return presetPath === certificatePath;
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
  const { muted, dashboard } = useDashboardThemeColors();
  const cardBorder = dashboard.border.subtle;
  const cardSelectedBorder = dashboard.accent.interactiveBorder;
  const cardSelectedBg = dashboard.accent.interactiveSurface;
  const matchedBorder = dashboard.state.success;
  const matchedBg = dashboard.bg.nested;
  const matchedText = dashboard.state.success;
  const mismatchedBorder = dashboard.callout.warningBorder;
  const mismatchedBg = dashboard.callout.warningSurface;
  const mismatchedText = dashboard.callout.warningText;

  const [presets, setPresets] = useState([]);
  const [loadingPresets, setLoadingPresets] = useState(false);
  const [manualEntry, setManualEntry] = useState(false);
  const [selectedPresetId, setSelectedPresetId] = useState('');
  const [showAllProfiles, setShowAllProfiles] = useState(false);

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
    setShowAllProfiles(false);

    if (!workspaceId) return;
    let cancelled = false;
    setLoadingPresets(true);
    const certificatePath = certificate?.deployedCertPath || null;
    listRenewalProfiles(workspaceId, { limit: 50 })
      .then(data => {
        if (cancelled) return;
        const usable = (Array.isArray(data?.items) ? data.items : []).filter(
          isUsablePreset
        );
        setPresets(usable);
        // The switch always defaults to off (matching-only); it is never
        // auto-flipped to "show all", even when nothing matches. A certificate
        // with no matching profile shows the empty-state prompt instead, and
        // the operator opts into seeing the rest themselves.
        const matching = usable.filter(preset =>
          presetMatchesCertificate(preset, certificatePath)
        );
        if (matching.length > 0) {
          setSelectedPresetId(matching[0].id);
        } else if (usable.length === 0) {
          setManualEntry(true);
        }
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
  }, [isOpen, workspaceId, certificate?.deployedCertPath]);

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

  const matchingPresets = presets.filter(preset =>
    presetMatchesCertificate(preset, certificatePath)
  );
  const nonMatchingCount = presets.length - matchingPresets.length;
  const visiblePresets = showAllProfiles ? presets : matchingPresets;

  const usingPreset = !manualEntry && presets.length > 0;

  // If the filter toggle hides the currently selected preset (or reveals a
  // list the previous selection was never part of), fall back to the first
  // preset still visible rather than leaving a selection the radio group no
  // longer renders.
  useEffect(() => {
    if (!usingPreset) return;
    if (visiblePresets.some(preset => preset.id === selectedPresetId)) return;
    setSelectedPresetId(visiblePresets[0]?.id || '');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [usingPreset, showAllProfiles, presets, selectedPresetId]);

  const selectedPreset =
    visiblePresets.find(p => p.id === selectedPresetId) || null;
  const selectedPresetPath = selectedPreset
    ? presetCertPath(selectedPreset)
    : null;
  const pathMismatch = Boolean(
    usingPreset &&
    certificatePath &&
    selectedPresetPath &&
    selectedPresetPath !== certificatePath
  );

  // Keep the manual fields in sync with whichever preset is selected, so
  // switching to manual entry starts from its values instead of blank ones;
  // an operator tweaking one field off a known-good profile should not have
  // to retype the rest from memory.
  useEffect(() => {
    if (!selectedPreset) return;
    const renewal = selectedPreset.renewalProfile || {};
    setCommandRef(renewal.acme?.commandRef || '');
    setCaEndpoint(renewal.ca?.endpoint || '');
    setDnsZone(renewal.dns?.zone || '');
    setDnsProvider(renewal.dns?.provider || '');
  }, [selectedPreset]);

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

  const toggleShowAllProfiles = useCallback(() => {
    setShowAllProfiles(prev => !prev);
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
            Sets up automatic renewal for{' '}
            <Text as='span' fontWeight='semibold'>
              {certName}
            </Text>
            . TokenTimer renews it once now, onto
            {certificatePath ? (
              <>
                {' '}
                <Text as='span' fontFamily='mono'>
                  {certificatePath}
                </Text>
              </>
            ) : (
              ' the path TokenTimer already discovered'
            )}
            , to prove the settings below actually work. If that renewal
            succeeds, TokenTimer creates another renewal profile, scoped to just
            this certificate, so future renewals happen without asking again.
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
                      Picking a profile copies its command, CA endpoint, and DNS
                      settings into this setup; it does{' '}
                      <Text as='span' fontWeight='medium'>
                        not
                      </Text>{' '}
                      attach{' '}
                      <Text as='span' fontWeight='medium'>
                        {selectedPreset?.name}
                      </Text>{' '}
                      itself, since this certificate always gets its own
                      profile. Check each option's path below against this
                      certificate's own path above before picking it.
                    </Text>
                    {presets.length > 0 ? (
                      <Flex justify='space-between' align='center'>
                        <Text fontSize='xs' color={muted}>
                          {showAllProfiles
                            ? `Showing all ${presets.length} profile${presets.length === 1 ? '' : 's'}`
                            : `Showing ${matchingPresets.length} matching profile${matchingPresets.length === 1 ? '' : 's'}${nonMatchingCount > 0 ? ` (${nonMatchingCount} hidden)` : ''}`}
                        </Text>
                        <HStack spacing={2}>
                          <Text fontSize='xs' color={muted}>
                            Show all profiles
                          </Text>
                          <Switch
                            size='sm'
                            isChecked={showAllProfiles}
                            onChange={toggleShowAllProfiles}
                            aria-label='Show all profiles, including ones that do not match this certificate'
                          />
                        </HStack>
                      </Flex>
                    ) : null}
                    {visiblePresets.length === 0 ? (
                      <Alert status='info' variant='subtle' borderRadius='md'>
                        <AlertIcon boxSize={4} />
                        <AlertDescription fontSize='sm'>
                          No profile matches this certificate's own path. Turn
                          on "Show all profiles" above to pick from the
                          {` ${presets.length} `}
                          other profile{presets.length === 1 ? '' : 's'} in this
                          workspace, or enter details manually.
                        </AlertDescription>
                      </Alert>
                    ) : (
                      <RadioGroup
                        value={selectedPresetId}
                        onChange={setSelectedPresetId}
                      >
                        <Stack spacing={2}>
                          {visiblePresets.map(preset => {
                            const renewal = preset.renewalProfile || {};
                            const certPath = presetCertPath(preset);
                            const selected = preset.id === selectedPresetId;
                            const matched = Boolean(
                              certificatePath &&
                              certPath &&
                              certPath === certificatePath
                            );
                            const mismatched = Boolean(
                              certificatePath &&
                              certPath &&
                              certPath !== certificatePath
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
                                      ? mismatchedBorder
                                      : matched
                                        ? matchedBorder
                                        : cardSelectedBorder
                                    : cardBorder
                                }
                                bg={
                                  selected
                                    ? mismatched
                                      ? mismatchedBg
                                      : matched
                                        ? matchedBg
                                        : cardSelectedBg
                                    : 'transparent'
                                }
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
                                          ? dashboard.state.warning
                                          : mismatched
                                            ? mismatchedText
                                            : matched
                                              ? matchedText
                                              : undefined
                                      }
                                      fontWeight={
                                        mismatched || matched
                                          ? 'semibold'
                                          : undefined
                                      }
                                    >
                                      {certPath ||
                                        'Not recorded on this profile'}
                                    </Text>
                                  </Text>
                                </Stack>
                              </Box>
                            );
                          })}
                        </Stack>
                      </RadioGroup>
                    )}
                    {pathMismatch ? (
                      <Alert
                        status='warning'
                        variant='subtle'
                        borderRadius='md'
                      >
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
                        This is the one time these settings need to be entered
                        by hand: they become part of the renewal profile this
                        creates, so every later renewal reuses them without
                        asking again.
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
                          onChange={event => setCommandRef(event.target.value)}
                          placeholder='e.g. certbot-csr'
                          autoComplete='off'
                        />
                      </FormControl>
                      <FormControl isRequired>
                        <FormLabel fontSize='sm'>DNS provider</FormLabel>
                        <Input
                          size='sm'
                          value={dnsProvider}
                          onChange={event => setDnsProvider(event.target.value)}
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
