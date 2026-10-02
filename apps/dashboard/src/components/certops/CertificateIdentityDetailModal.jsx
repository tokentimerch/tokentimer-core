import { useEffect, useMemo, useState } from 'react';
import {
  Badge,
  Box,
  Button,
  HStack,
  Select,
  Text,
  VStack,
} from '@chakra-ui/react';
import apiClient, { tokenAPI, workspaceAPI } from '../../utils/apiClient';
import CopyableId from '../CopyableId.jsx';
import CertificateDetailsModal from './CertificateDetailsModal.jsx';
import {
  getCertificateIdentity,
  listCertOpsRenewalProfiles,
  readdManagingSource,
  stopManagingSource,
} from './certopsApi';
import { sourceLabel } from './certopsFormat.js';

function LocationStatus({ location }) {
  const present = location.presenceState === 'confirmed_present';
  const absent = location.presenceState === 'confirmed_absent';
  return (
    <Badge colorScheme={present ? 'green' : absent ? 'gray' : 'orange'}>
      {present ? 'Observed' : absent ? 'No longer observed' : 'Unknown'}
    </Badge>
  );
}

/** One certificate detail view: token fields, every source, and every location. */
export default function CertificateIdentityDetailModal({
  workspaceId,
  certificate,
  isOpen,
  onClose,
  canManage,
  onChanged,
}) {
  const [detail, setDetail] = useState(null);
  const [token, setToken] = useState(null);
  const [tokenError, setTokenError] = useState('');
  const [contactGroups, setContactGroups] = useState([]);
  const [workspaceContacts, setWorkspaceContacts] = useState([]);
  const [profiles, setProfiles] = useState([]);
  const [profileId, setProfileId] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!isOpen || !workspaceId || !certificate) return undefined;
    let active = true;
    setDetail(certificate);
    setToken(null);
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

  const tokenId = detail?.tokenId;
  useEffect(() => {
    if (!isOpen || !tokenId) {
      setToken(null);
      setTokenError('');
      return undefined;
    }
    let active = true;
    setToken(null);
    setTokenError('');
    Promise.all([
      tokenAPI.getToken(tokenId),
      workspaceAPI.getAlertSettings(workspaceId).catch(() => null),
      apiClient
        .get(`/api/v1/workspaces/${workspaceId}/contacts`)
        .catch(() => null),
    ])
      .then(([tokenData, settings, contacts]) => {
        if (!active) return;
        setToken(tokenData || null);
        setContactGroups(
          Array.isArray(settings?.contact_groups) ? settings.contact_groups : []
        );
        setWorkspaceContacts(
          Array.isArray(contacts?.data?.items) ? contacts.data.items : []
        );
      })
      .catch(err => {
        if (active)
          setTokenError(err?.message || 'Token details are unavailable.');
      });
    return () => {
      active = false;
    };
  }, [isOpen, tokenId, workspaceId]);

  const refresh = async () => {
    if (!certificate.identityId) {
      onChanged?.();
      onClose?.();
      return;
    }
    setDetail(
      await getCertificateIdentity(workspaceId, certificate.identityId)
    );
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

  const displayToken = useMemo(
    () =>
      token || {
        name: detail?.commonName || detail?.name || 'Certificate',
        category: 'cert',
        type: 'ssl_cert',
        issuer: detail?.issuer || '',
        expiresAt: detail?.notAfter || null,
      },
    [token, detail]
  );
  if (!isOpen || !detail) return null;

  const activeSources = (detail.sources || []).filter(
    source =>
      !source.endedAt &&
      !source.periodEndedAt &&
      (!detail.identityId || source.currentIdentityId === detail.identityId)
  );
  const certificateFacts = {
    status:
      detail.lifecycleStatus && detail.lifecycleStatus !== 'active'
        ? detail.lifecycleStatus
        : detail.status,
    notAfter: detail.notAfter,
    fingerprintSha256: detail.fingerprintSha256,
    issuer: detail.issuer,
  };

  const identityPanel = (
    <VStack align='stretch' spacing={4} mb={6}>
      <HStack spacing={2} flexWrap='wrap'>
        <Badge colorScheme='blue'>
          {detail.locationCount ?? (detail.locations || []).length} locations
        </Badge>
        <Badge colorScheme='purple'>
          {detail.activeSourceCount ?? activeSources.length} managing sources
        </Badge>
        {detail.lifecycleDisplay ? (
          <Badge colorScheme={detail.stillObserved ? 'red' : 'gray'}>
            {detail.lifecycleDisplay}
          </Badge>
        ) : null}
      </HStack>
      {detail.visibilityUnknown ? (
        <Text fontSize='sm' color='orange.400'>
          Visibility is unknown at one or more locations.
        </Text>
      ) : null}
      {tokenError ? (
        <Text fontSize='sm' color='orange.400'>
          Token fields could not be loaded: {tokenError}
        </Text>
      ) : null}
      {tokenId && !token && !tokenError ? (
        <Text fontSize='sm' color='dashboard.modal.muted'>
          Loading token fields…
        </Text>
      ) : null}
      <Box
        as='section'
        borderWidth='1px'
        borderColor='dashboard.modal.border'
        borderRadius='md'
        p={3}
      >
        <Text as='h3' fontSize='sm' fontWeight='bold' mb={2}>
          Observed locations
        </Text>
        {(detail.locations || []).length ? (
          detail.locations.map(location => (
            <HStack
              key={location.id}
              align='start'
              justify='space-between'
              flexWrap='wrap'
              py={2}
              borderTopWidth='1px'
              borderColor='dashboard.modal.border'
            >
              <Box minW={0} flex='1'>
                <Text fontSize='sm' overflowWrap='anywhere'>
                  {location.deploymentReference ||
                    location.sourceRef ||
                    location.locationKind ||
                    'Location'}
                </Text>
                <Text fontSize='xs' color='dashboard.modal.muted'>
                  {location.capturedAt
                    ? `Last seen ${new Date(location.capturedAt).toLocaleString()}`
                    : 'Observation time unknown'}
                </Text>
              </Box>
              <LocationStatus location={location} />
            </HStack>
          ))
        ) : (
          <Text fontSize='sm'>No location observations recorded.</Text>
        )}
        {detail.locationCount > (detail.locations || []).length ? (
          <Text fontSize='xs' mt={2}>
            Showing {(detail.locations || []).length} of {detail.locationCount}{' '}
            locations.
          </Text>
        ) : null}
      </Box>
      <Box
        as='section'
        borderWidth='1px'
        borderColor='dashboard.modal.border'
        borderRadius='md'
        p={3}
      >
        <Text as='h3' fontSize='sm' fontWeight='bold' mb={2}>
          Management sources
        </Text>
        {(detail.sources || []).length ? (
          detail.sources.map(source => {
            const current = activeSources.includes(source);
            const canReadd =
              source.periodEndedAt &&
              source.endedReason !== 'endpoint_monitor_deleted' &&
              !(detail.sources || []).some(
                other =>
                  other.managedCertificateId === source.managedCertificateId &&
                  !other.periodEndedAt
              );
            return (
              <Box
                key={`${source.periodId}-${source.startedAt}`}
                py={2}
                borderTopWidth='1px'
                borderColor='dashboard.modal.border'
              >
                <HStack
                  justify='space-between'
                  align='start'
                  flexWrap='wrap'
                  spacing={3}
                >
                  <Box minW={0} flex='1'>
                    <HStack spacing={2} flexWrap='wrap'>
                      <Text fontSize='sm' fontWeight='semibold'>
                        {sourceLabel(source.source)}
                      </Text>
                      <Badge colorScheme={current ? 'green' : 'gray'}>
                        {current ? 'Managing' : 'Ended'}
                      </Badge>
                    </HStack>
                    {source.sourceRef ? (
                      <Box maxW='100%' overflowWrap='anywhere'>
                        <CopyableId id={source.sourceRef} size='xs' />
                      </Box>
                    ) : null}
                    <Text fontSize='xs' color='dashboard.modal.muted'>
                      {new Date(source.startedAt).toLocaleDateString()} –{' '}
                      {source.endedAt
                        ? new Date(source.endedAt).toLocaleDateString()
                        : 'present'}
                    </Text>
                  </Box>
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
        {detail.sourceCount > (detail.sources || []).length ? (
          <Text fontSize='xs' mt={2}>
            Showing {(detail.sources || []).length} of {detail.sourceCount}{' '}
            source periods.
          </Text>
        ) : null}
      </Box>
      {error ? (
        <Text fontSize='sm' color='orange.400'>
          {error}
        </Text>
      ) : null}
    </VStack>
  );

  return (
    <CertificateDetailsModal
      token={displayToken}
      isOpen={isOpen}
      onClose={onClose}
      isViewer={!canManage || !token}
      contactGroups={contactGroups}
      workspaceContacts={workspaceContacts}
      onTokenUpdated={setToken}
      certOps={{ certificate: certificateFacts, instances: [] }}
      compactTableSections
      propertyValueRows
      titleOverride={detail.commonName || detail.name}
      identityPanel={identityPanel}
    />
  );
}
