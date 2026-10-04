import CertOpsBadge, { CertificateLifecycleBadge } from './CertOpsBadge.jsx';
import { useEffect, useMemo, useState } from 'react';
import {
  Box,
  Button,
  FormControl,
  FormLabel,
  HStack,
  Select,
  Switch,
  Table,
  TableContainer,
  Tbody,
  Td,
  Text,
  Th,
  Thead,
  Tr,
  VStack,
} from '@chakra-ui/react';
import apiClient, { tokenAPI, workspaceAPI } from '../../utils/apiClient';
import { MapPin, Settings } from 'lucide-react';
import DashboardDetailsSection from '../DashboardDetailsSection.jsx';
import CopyableId from '../CopyableId.jsx';
import CertificateDetailsModal from './CertificateDetailsModal.jsx';
import {
  getCertificateIdentity,
  getManagedCertificatesForToken,
  listCertOpsRenewalProfiles,
  readdManagingSource,
  stopManagingSource,
} from './certopsApi';
import {
  formatDate,
  formatDateTime,
  locationKindLabel,
  sourceLabel,
} from './certopsFormat.js';

function SectionContent({ children }) {
  return (
    <Box py={1} sx={{ '& > :last-child': { borderBottom: 0 } }}>
      {children}
    </Box>
  );
}

function LocationStatus({ location }) {
  const present = location.presenceState === 'confirmed_present';
  const absent = location.presenceState === 'confirmed_absent';
  const ended = location.observationReason === 'monitoring_ended';
  const unknownLabel = ended
    ? 'Monitoring ended'
    : location.observationReason === 'stale'
      ? 'Not checked recently'
      : 'Needs verification';
  return (
    <CertOpsBadge
      textTransform='none'
      whiteSpace='normal'
      colorScheme={
        location.historical || ended
          ? 'gray'
          : present
            ? 'green'
            : absent
              ? 'gray'
              : 'orange'
      }
    >
      {location.historical
        ? 'Previous observation'
        : present
          ? 'Observed'
          : absent
            ? 'No longer observed'
            : unknownLabel}
    </CertOpsBadge>
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
  const [certificateFields, setCertificateFields] = useState(null);
  const [tokenError, setTokenError] = useState('');
  const [contactGroups, setContactGroups] = useState([]);
  const [workspaceContacts, setWorkspaceContacts] = useState([]);
  const [profiles, setProfiles] = useState([]);
  const [profileIds, setProfileIds] = useState({});
  const [showHistory, setShowHistory] = useState(false);
  const [showLocationHistory, setShowLocationHistory] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!isOpen || !workspaceId || !certificate) return undefined;
    let active = true;
    setDetail(certificate);
    setToken(null);
    setCertificateFields(null);
    setError('');
    setShowHistory(false);
    setShowLocationHistory(false);
    setProfileIds({});
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
    if (isOpen && detail?.identityId) {
      // Identity-scoped public details are read on the server. Fetching a mutable
      // token separately can show B under A if it rotates between those reads.
      setToken(
        detail.tokenSnapshot
          ? { ...detail.tokenSnapshot, ...(tokenId ? { id: tokenId } : {}) }
          : null
      );
      // Current identity management facts are safe even when the historical
      // token has rotated away. They must not depend on an editable token link.
      const identityFields = {
        ...Object.fromEntries(
          [
            'source',
            'keyMode',
            'keyReference',
            'profileId',
            'renewal',
            'renewalPathState',
            'renewalPathReason',
            'renewalPathSummary',
            'dependencies',
            'renewalSetup',
            'renewalPreflight',
          ]
            .filter(key => detail[key] !== undefined)
            .map(key => [key, detail[key]])
        ),
        ...detail.certificateSnapshot,
      };
      setCertificateFields(identityFields);
      setTokenError('');
      if (!tokenId || !detail.tokenSnapshot || detail.managed === false)
        return undefined;
      let active = true;
      Promise.all([
        getManagedCertificatesForToken(workspaceId, tokenId),
        workspaceAPI.getAlertSettings(workspaceId).catch(() => null),
        apiClient
          .get(`/api/v1/workspaces/${workspaceId}/contacts`)
          .catch(() => null),
      ])
        .then(([certificates, settings, contacts]) => {
          if (!active) return;
          const normalize = value =>
            String(value || '')
              .replace(/:/g, '')
              .trim()
              .toLowerCase();
          const matching = (certificates || []).find(
            item =>
              normalize(item.fingerprintSha256) ===
              normalize(detail.fingerprintSha256)
          );
          setCertificateFields({ ...matching, ...identityFields });
          setContactGroups(
            Array.isArray(settings?.contact_groups)
              ? settings.contact_groups
              : []
          );
          setWorkspaceContacts(
            Array.isArray(contacts?.data?.items) ? contacts.data.items : []
          );
        })
        .catch(() => {
          // Retained public fields remain usable when live enrichment is unavailable.
        });
      return () => {
        active = false;
      };
    }
    if (!isOpen || !tokenId) {
      setToken(null);
      setCertificateFields(null);
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
      getManagedCertificatesForToken(workspaceId, tokenId),
    ])
      .then(([tokenData, settings, contacts, certificates]) => {
        if (!active) return;
        setToken(tokenData || null);
        // Reuse the token modal's enrichment, scoped to this immutable
        // fingerprint so a shared token's rotated certificate cannot leak in.
        const normalize = value =>
          String(value || '')
            .replace(/:/g, '')
            .trim()
            .toLowerCase();
        const matching = (certificates || []).filter(item =>
          detail?.fingerprintSha256
            ? normalize(item.fingerprintSha256) ===
              normalize(detail.fingerprintSha256)
            : String(item.id) === String(detail?.managedCertificateId)
        );
        setCertificateFields(
          matching.find(
            item => String(item.id) === String(detail?.managedCertificateId)
          ) ||
            matching[0] ||
            null
        );
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
  }, [isOpen, tokenId, workspaceId, detail]);

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
      const profileId = profileIds[managedCertificateId] || '';
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
  // Keep one current/latest period per registration in the default view.
  // A stopped registration remains available to restart without exposing all
  // its older periods. Rotation history cannot restart the old fingerprint.
  const latestSources = new Map();
  const openSourceIds = new Set();
  for (const source of detail.sources || []) {
    if (!source.periodEndedAt) openSourceIds.add(source.managedCertificateId);
    const previous = latestSources.get(source.managedCertificateId);
    if (
      !previous ||
      new Date(source.startedAt) > new Date(previous.startedAt)
    ) {
      latestSources.set(source.managedCertificateId, source);
    }
  }
  const canRestart = source =>
    Boolean(source.periodEndedAt) &&
    latestSources.get(source.managedCertificateId) === source &&
    source.endedReason !== 'endpoint_monitor_deleted' &&
    (!detail.identityId || source.currentIdentityId === detail.identityId) &&
    !openSourceIds.has(source.managedCertificateId);
  const visibleSources = showHistory
    ? detail.sources || []
    : (detail.sources || []).filter(
        source => activeSources.includes(source) || canRestart(source)
      );
  const hiddenPeriodCount =
    (detail.sources || []).length - visibleSources.length;
  const certificateFacts = {
    ...certificateFields,
    lifecycleStatus: detail.lifecycleStatus,
    lifecycleDisplay: detail.lifecycleDisplay,
    status:
      detail.lifecycleStatus && detail.lifecycleStatus !== 'active'
        ? detail.lifecycleStatus
        : detail.status,
    notAfter: detail.notAfter,
    fingerprintSha256: detail.fingerprintSha256,
    issuer: detail.issuer,
  };

  const locations = detail.locations || [];
  const previousObservationCount = locations.reduce(
    (total, location) => total + (location.previousObservationCount || 0),
    0
  );
  const visibleLocations = locations.flatMap(location => [
    location,
    ...(showLocationHistory
      ? (location.previousObservations || []).map(previous => ({
          ...location,
          ...previous,
          historical: true,
          previousObservationCount: 0,
          previousObservations: [],
        }))
      : []),
  ]);
  const identityPanel = (
    <VStack align='stretch' spacing={6} mb={6}>
      <HStack spacing={2} flexWrap='wrap'>
        <CertOpsBadge>
          {detail.locationCount ?? (detail.locations || []).length} locations
        </CertOpsBadge>
        <CertOpsBadge>
          {detail.activeSourceCount ?? activeSources.length} active
          registrations
        </CertOpsBadge>
        {detail.lifecycleDisplay ? (
          <CertificateLifecycleBadge certificate={detail} />
        ) : null}
      </HStack>
      {detail.visibilityUnknown ? (
        <Text fontSize='sm' color='orange.400'>
          Current presence cannot be confirmed at every location. Check the
          location status below.
        </Text>
      ) : null}
      {tokenError ? (
        <Text fontSize='sm' color='orange.400'>
          Token fields could not be loaded: {tokenError}
        </Text>
      ) : null}
      {detail.identityId &&
      detail.managed === false &&
      !detail.tokenSnapshot ? (
        <Text fontSize='sm' color='dashboard.modal.muted'>
          Full token details were not retained for this historical certificate.
        </Text>
      ) : null}
      {tokenId && !token && !tokenError ? (
        <Text fontSize='sm' color='dashboard.modal.muted'>
          Loading token fields…
        </Text>
      ) : null}
      <DashboardDetailsSection
        title='Observed locations'
        description='Where this certificate has been seen. Recreated endpoint monitors share one location; previous observations stay in history. Stored copies do not prove service use or configure automatic renewal.'
        icon={MapPin}
        enclosed
        mb={0}
      >
        <SectionContent>
          {previousObservationCount > 0 ? (
            <FormControl display='flex' alignItems='center' mb={3}>
              <Switch
                id='certificate-location-history'
                isChecked={showLocationHistory}
                onChange={event => setShowLocationHistory(event.target.checked)}
                mr={2}
              />
              <FormLabel
                htmlFor='certificate-location-history'
                mb={0}
                fontSize='sm'
              >
                Show previous observations
              </FormLabel>
            </FormControl>
          ) : null}
          {visibleLocations.length ? (
            <TableContainer overflowX='auto' whiteSpace='normal'>
              <Table
                aria-label='Observed locations'
                size='sm'
                tableLayout='fixed'
                minW='640px'
                sx={{
                  'th, td': {
                    borderColor: 'dashboard.modal.border',
                    verticalAlign: 'top',
                    whiteSpace: 'normal',
                    overflowWrap: 'anywhere',
                  },
                  th: { color: 'dashboard.modal.muted' },
                }}
              >
                <Thead>
                  <Tr>
                    <Th w='32%'>Location</Th>
                    <Th w='17%'>Type / evidence</Th>
                    <Th w='16%'>Source</Th>
                    <Th w='20%'>Last observed</Th>
                    <Th w='15%'>State</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {visibleLocations.map(location => (
                    <Tr
                      key={`${location.historical ? 'previous' : 'current'}-${location.id}`}
                    >
                      <Td>
                        {location.deploymentReference ||
                          location.sourceRef ||
                          'Location'}
                        {location.previousObservationCount > 0 ? (
                          <Text
                            fontSize='xs'
                            color='dashboard.modal.muted'
                            mt={1}
                          >
                            {location.previousObservationCount} previous
                            observations
                          </Text>
                        ) : null}
                      </Td>
                      <Td>
                        <Text fontSize='sm'>
                          {location.locationKind === 'tls_endpoint' ||
                          ['endpoint_monitor', 'domain_checker'].includes(
                            location.source
                          )
                            ? 'TLS endpoint'
                            : locationKindLabel(
                                location.locationKind,
                                location
                              )}
                        </Text>
                        <Text fontSize='xs' color='dashboard.modal.muted'>
                          {location.evidenceKind === 'service_binding'
                            ? 'Service use'
                            : location.evidenceKind === 'stored_copy'
                              ? 'Stored copy'
                              : 'Evidence unknown'}
                        </Text>
                      </Td>
                      <Td>{sourceLabel(location.source)}</Td>
                      <Td>
                        <Text fontSize='xs' color='dashboard.modal.muted'>
                          {formatDateTime(location.capturedAt)}
                        </Text>
                      </Td>
                      <Td>
                        <LocationStatus location={location} />
                        {location.historical && location.monitoringEnded ? (
                          <Text
                            fontSize='xs'
                            color='dashboard.modal.muted'
                            mt={1}
                          >
                            Monitoring ended
                          </Text>
                        ) : null}
                      </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            </TableContainer>
          ) : (
            <Text fontSize='sm'>No location observations recorded.</Text>
          )}
          {detail.locationCount > (detail.locations || []).length ? (
            <Text fontSize='xs' mt={2}>
              Showing {(detail.locations || []).length} of{' '}
              {detail.locationCount} locations.
            </Text>
          ) : null}
          {showLocationHistory &&
          locations.some(
            location =>
              (location.previousObservationCount || 0) >
              (location.previousObservations || []).length
          ) ? (
            <Text fontSize='xs' color='dashboard.modal.muted' mt={2}>
              Showing up to 20 previous observations per location. All records
              remain in the audit history.
            </Text>
          ) : null}
        </SectionContent>
      </DashboardDetailsSection>
      <DashboardDetailsSection
        title='Certificate management'
        description='Registrations through which CertOps tracks this certificate and can automate renewal. Stopping management ends that registration’s automation; it does not remove the certificate or stop location observations.'
        icon={Settings}
        enclosed
        mb={0}
      >
        <SectionContent>
          <FormControl display='flex' alignItems='center' mb={3}>
            <Switch
              id='certificate-management-history'
              isChecked={showHistory}
              onChange={event => setShowHistory(event.target.checked)}
              mr={2}
            />
            <FormLabel
              htmlFor='certificate-management-history'
              mb={0}
              fontSize='sm'
            >
              Show ended periods
            </FormLabel>
          </FormControl>
          {visibleSources.length ? (
            <TableContainer overflowX='auto' whiteSpace='normal'>
              <Table
                aria-label='Certificate management'
                size='sm'
                tableLayout='fixed'
                minW='640px'
                sx={{
                  'th, td': {
                    borderColor: 'dashboard.modal.border',
                    verticalAlign: 'top',
                    whiteSpace: 'normal',
                    overflowWrap: 'anywhere',
                  },
                  th: { color: 'dashboard.modal.muted' },
                }}
              >
                <Thead>
                  <Tr>
                    <Th w='32%'>Registration</Th>
                    <Th w='21%'>Management period</Th>
                    <Th w='13%'>State</Th>
                    <Th w='16%'>Renewal</Th>
                    <Th w='18%'>Actions</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {visibleSources.map(source => {
                    const current = activeSources.includes(source);
                    const canReadd = canRestart(source);
                    return (
                      <Tr key={`${source.periodId}-${source.startedAt}`}>
                        <Td>
                          <Text fontSize='sm' fontWeight='semibold'>
                            {sourceLabel(source.source)}
                          </Text>
                          {source.sourceRef ? (
                            <Box
                              maxW='100%'
                              overflowWrap='anywhere'
                              sx={{
                                '& .chakra-text': {
                                  whiteSpace: 'normal',
                                  overflowWrap: 'anywhere',
                                },
                              }}
                            >
                              <CopyableId id={source.sourceRef} size='xs' />
                            </Box>
                          ) : null}
                        </Td>
                        <Td>
                          <Text fontSize='xs' color='dashboard.modal.muted'>
                            {formatDate(source.startedAt)} –{' '}
                            {source.endedAt || source.periodEndedAt
                              ? formatDate(
                                  source.endedAt || source.periodEndedAt
                                )
                              : 'present'}
                          </Text>
                        </Td>
                        <Td>
                          <CertOpsBadge
                            textTransform='none'
                            whiteSpace='normal'
                            colorScheme={current ? 'green' : 'gray'}
                          >
                            {current
                              ? 'Managing'
                              : canReadd
                                ? 'Stopped'
                                : 'Ended'}
                          </CertOpsBadge>
                        </Td>
                        <Td>
                          <Text fontSize='xs'>
                            {source.renewalProfileId
                              ? profiles.find(
                                  profile =>
                                    profile.id === source.renewalProfileId
                                )?.name || 'Renewal profile assigned'
                              : 'No automatic renewal'}
                          </Text>
                        </Td>
                        <Td>
                          {canManage && current ? (
                            <Button
                              size='xs'
                              isDisabled={busy}
                              onClick={() => stop(source.periodId)}
                            >
                              Stop managing
                            </Button>
                          ) : null}
                          {canManage && canReadd ? (
                            <VStack align='stretch' spacing={2}>
                              <Select
                                aria-label={`Renewal settings for ${source.sourceRef || source.managedCertificateId}`}
                                size='xs'
                                value={
                                  profileIds[source.managedCertificateId] || ''
                                }
                                onChange={event =>
                                  setProfileIds(previous => ({
                                    ...previous,
                                    [source.managedCertificateId]:
                                      event.target.value,
                                  }))
                                }
                              >
                                <option value=''>
                                  Track without automatic renewal
                                </option>
                                {profiles.map(profile => (
                                  <option key={profile.id} value={profile.id}>
                                    {profile.name || profile.id}
                                  </option>
                                ))}
                              </Select>
                              <Button
                                size='xs'
                                whiteSpace='normal'
                                h='auto'
                                minH={6}
                                py={1}
                                isDisabled={busy}
                                onClick={() =>
                                  readd(source.managedCertificateId)
                                }
                              >
                                Start managing again
                              </Button>
                              <Text fontSize='xs' color='dashboard.modal.muted'>
                                Starts a new period for this registration.
                                Earlier periods stay in history.
                              </Text>
                            </VStack>
                          ) : null}
                        </Td>
                      </Tr>
                    );
                  })}
                </Tbody>
              </Table>
            </TableContainer>
          ) : (
            <Text fontSize='sm'>
              No active registrations. Show ended periods to view past
              management.
            </Text>
          )}
          {hiddenPeriodCount > 0 ? (
            <Text fontSize='xs' mt={2} color='dashboard.modal.muted'>
              {hiddenPeriodCount} earlier or ended period(s) hidden.
            </Text>
          ) : null}
          {detail.sourceCount > (detail.sources || []).length ? (
            <Text fontSize='xs' mt={2}>
              Showing {(detail.sources || []).length} of {detail.sourceCount}{' '}
              source periods.
            </Text>
          ) : null}
        </SectionContent>
      </DashboardDetailsSection>
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
      isViewer={!canManage || !tokenId || !token}
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
