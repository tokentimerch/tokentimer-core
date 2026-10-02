import { useEffect, useMemo, useState } from 'react';
import {
  Badge,
  Box,
  Button,
  HStack,
  Select,
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
  return (
    <Badge
      textTransform='none'
      whiteSpace='normal'
      colorScheme={present ? 'green' : absent ? 'gray' : 'orange'}
    >
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
  const [certificateFields, setCertificateFields] = useState(null);
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
    setCertificateFields(null);
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
  }, [
    isOpen,
    tokenId,
    workspaceId,
    detail?.fingerprintSha256,
    detail?.managedCertificateId,
  ]);

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
    ...certificateFields,
    status:
      detail.lifecycleStatus && detail.lifecycleStatus !== 'active'
        ? detail.lifecycleStatus
        : detail.status,
    notAfter: detail.notAfter,
    fingerprintSha256: detail.fingerprintSha256,
    issuer: detail.issuer,
  };

  const identityPanel = (
    <VStack align='stretch' spacing={6} mb={6}>
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
      <DashboardDetailsSection
        title='Observed locations'
        icon={MapPin}
        enclosed
        mb={0}
      >
        <SectionContent>
          {(detail.locations || []).length ? (
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
                  {detail.locations.map(location => (
                    <Tr key={location.id}>
                      <Td>
                        {location.deploymentReference ||
                          location.sourceRef ||
                          'Location'}
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
        </SectionContent>
      </DashboardDetailsSection>
      <DashboardDetailsSection
        title='Management sources'
        icon={Settings}
        enclosed
        mb={0}
      >
        <SectionContent>
          {(detail.sources || []).length ? (
            <TableContainer overflowX='auto' whiteSpace='normal'>
              <Table
                aria-label='Management sources'
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
                    <Th w='32%'>Source</Th>
                    <Th w='21%'>Management period</Th>
                    <Th w='13%'>State</Th>
                    <Th w='16%'>Renewal</Th>
                    <Th w='18%'>Actions</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {detail.sources.map(source => {
                    const current = activeSources.includes(source);
                    const canReadd =
                      source.periodEndedAt &&
                      source.endedReason !== 'endpoint_monitor_deleted' &&
                      !(detail.sources || []).some(
                        other =>
                          other.managedCertificateId ===
                            source.managedCertificateId && !other.periodEndedAt
                      );
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
                          <Badge
                            textTransform='none'
                            whiteSpace='normal'
                            colorScheme={current ? 'green' : 'gray'}
                          >
                            {current ? 'Managing' : 'Ended'}
                          </Badge>
                        </Td>
                        <Td>
                          <Text fontSize='xs'>
                            {source.renewalProfileId
                              ? profiles.find(
                                  profile =>
                                    profile.id === source.renewalProfileId
                                )?.name || 'Renewal profile assigned'
                              : 'Monitored only'}
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
                                value={profileId}
                                onChange={event =>
                                  setProfileId(event.target.value)
                                }
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
                                onClick={() =>
                                  readd(source.managedCertificateId)
                                }
                              >
                                Re-add
                              </Button>
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
            <Text fontSize='sm'>No management history recorded.</Text>
          )}
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
