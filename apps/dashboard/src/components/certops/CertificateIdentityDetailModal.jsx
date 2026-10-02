import { useEffect, useState } from 'react';
import {
  Badge,
  Box,
  Button,
  HStack,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalContent,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Select,
  Text,
  VStack,
} from '@chakra-ui/react';
import {
  getCertificateIdentity,
  listCertOpsRenewalProfiles,
  readdManagingSource,
  stopManagingSource,
} from './certopsApi';

export default function CertificateIdentityDetailModal({
  workspaceId,
  certificate,
  isOpen,
  onClose,
  canManage,
  onChanged,
  onViewToken,
}) {
  const [detail, setDetail] = useState(null);
  const [profiles, setProfiles] = useState([]);
  const [profileId, setProfileId] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!isOpen || !workspaceId || !certificate) return undefined;
    let active = true;
    setDetail(certificate);
    setError('');
    if (certificate.identityId) {
      getCertificateIdentity(workspaceId, certificate.identityId)
        .then(value => {
          if (active) setDetail(value);
        })
        .catch(err => {
          if (active) setError(err?.response?.data?.error || err.message);
        });
    }
    if (canManage) {
      listCertOpsRenewalProfiles(workspaceId)
        .then(value => {
          if (active) setProfiles(value);
        })
        .catch(() => {
          if (active) setProfiles([]);
        });
    }
    return () => {
      active = false;
    };
  }, [workspaceId, certificate, isOpen, canManage]);

  const refresh = async () => {
    if (certificate.identityId) {
      setDetail(
        await getCertificateIdentity(workspaceId, certificate.identityId)
      );
    }
    onChanged?.();
  };

  const stop = async periodId => {
    setBusy(true);
    setError('');
    try {
      const result = await stopManagingSource(workspaceId, periodId);
      if (result.runningJobs) {
        setError(
          `${result.runningJobs} operation(s) are already running and may still complete.`
        );
      }
      await refresh();
    } catch (err) {
      setError(err?.response?.data?.error || err.message);
    } finally {
      setBusy(false);
    }
  };

  const readd = async managedCertificateId => {
    setBusy(true);
    setError('');
    try {
      await readdManagingSource(workspaceId, managedCertificateId, {
        renewalProfileId: profileId || null,
        automationEnabled: Boolean(profileId),
      });
      await refresh();
    } catch (err) {
      setError(err?.response?.data?.error || err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      isCentered
      scrollBehavior='inside'
      size='lg'
    >
      <ModalOverlay />
      <ModalContent>
        <ModalHeader>{detail?.commonName || 'Certificate'}</ModalHeader>
        <ModalCloseButton />
        <ModalBody>
          <VStack align='stretch' spacing={5}>
            <Text fontSize='xs' overflowWrap='anywhere'>
              SHA-256 {detail?.fingerprintSha256}
            </Text>
            <Badge
              alignSelf='flex-start'
              colorScheme={
                detail?.stillObserved && detail?.lifecycleStatus !== 'active'
                  ? 'red'
                  : 'blue'
              }
            >
              {detail?.lifecycleDisplay || detail?.status || 'Active'}
            </Badge>
            {detail?.visibilityUnknown ? (
              <Text fontSize='sm' color='orange.500'>
                Visibility is unknown at one or more locations.
              </Text>
            ) : null}
            <Box>
              <Text fontWeight='semibold' mb={2}>
                Observed at
              </Text>
              {(detail?.locations || []).length ? (
                detail.locations.map(location => (
                  <Text
                    key={location.id}
                    fontSize='sm'
                    mb={1}
                    overflowWrap='anywhere'
                  >
                    {location.presenceState === 'confirmed_present'
                      ? '✓'
                      : location.presenceState === 'confirmed_absent'
                        ? '—'
                        : '?'}{' '}
                    {location.deploymentReference ||
                      location.sourceRef ||
                      location.locationKind ||
                      'Location'}
                    {' · '}
                    {location.capturedAt
                      ? new Date(location.capturedAt).toLocaleString()
                      : 'Time unknown'}
                  </Text>
                ))
              ) : (
                <Text fontSize='sm'>No location observations recorded.</Text>
              )}
              {detail?.locationCount > (detail?.locations || []).length ? (
                <Text fontSize='xs'>
                  Showing {(detail.locations || []).length} of{' '}
                  {detail.locationCount} locations.
                </Text>
              ) : null}
            </Box>
            <Box>
              <Text fontWeight='semibold' mb={2}>
                Managed through
              </Text>
              {(detail?.sources || []).length ? (
                detail.sources.map(source => {
                  const current =
                    !source.endedAt &&
                    !source.periodEndedAt &&
                    source.currentIdentityId === detail.identityId;
                  const canReadd =
                    source.periodEndedAt &&
                    source.endedReason !== 'endpoint_monitor_deleted' &&
                    !(detail.sources || []).some(
                      other =>
                        other.managedCertificateId ===
                          source.managedCertificateId && !other.periodEndedAt
                    );
                  return (
                    <Box
                      key={`${source.periodId}-${source.startedAt}`}
                      py={2}
                      borderTopWidth='1px'
                    >
                      <HStack
                        justify='space-between'
                        align='start'
                        flexWrap='wrap'
                      >
                        <Box minW={0}>
                          <Text fontSize='sm' overflowWrap='anywhere'>
                            {source.source}:{' '}
                            {source.sourceRef || 'Manual source'}
                          </Text>
                          <Text fontSize='xs'>
                            {new Date(source.startedAt).toLocaleDateString()} –
                            {source.endedAt
                              ? new Date(source.endedAt).toLocaleDateString()
                              : 'present'}
                          </Text>
                        </Box>
                        <HStack flexWrap='wrap'>
                          {current && source.tokenId && onViewToken ? (
                            <Button
                              size='xs'
                              variant='outline'
                              onClick={() => onViewToken(source)}
                            >
                              View token details
                            </Button>
                          ) : null}
                          {canManage && current ? (
                            <Button
                              size='xs'
                              isDisabled={busy}
                              onClick={() => stop(source.periodId)}
                            >
                              Stop managing
                            </Button>
                          ) : null}
                        </HStack>
                      </HStack>
                      {canManage && canReadd ? (
                        <HStack mt={2}>
                          <Select
                            size='xs'
                            value={profileId}
                            onChange={event => setProfileId(event.target.value)}
                          >
                            <option value=''>No renewal automation</option>
                            {profiles.map(profile => (
                              <option key={profile.id} value={profile.id}>
                                {profile.name || profile.id}
                              </option>
                            ))}
                          </Select>
                          <Button
                            size='xs'
                            isDisabled={busy}
                            onClick={() => readd(source.managedCertificateId)}
                          >
                            Re-add
                          </Button>
                        </HStack>
                      ) : null}
                    </Box>
                  );
                })
              ) : (
                <Text fontSize='sm'>No management history recorded.</Text>
              )}
            </Box>
            {error ? (
              <Text fontSize='sm' color='orange.500'>
                {error}
              </Text>
            ) : null}
          </VStack>
        </ModalBody>
        <ModalFooter>
          <Button onClick={onClose}>Close</Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
}
