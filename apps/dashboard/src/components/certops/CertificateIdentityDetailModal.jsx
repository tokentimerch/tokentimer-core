import CertOpsBadge, {
  CertificateLifecycleBadge,
  ObservedRevocationBadge,
  hasObservedRevocationContext,
} from './CertOpsBadge.jsx';
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Box,
  Button,
  FormControl,
  FormHelperText,
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
  Tooltip,
  VStack,
} from '@chakra-ui/react';
import apiClient, { tokenAPI, workspaceAPI } from '../../utils/apiClient';
import { HardDrive, Info, MapPin, Server, Settings } from 'lucide-react';
import DashboardDetailsSection from '../DashboardDetailsSection.jsx';
import CopyableId from '../CopyableId.jsx';
import CertificateDetailsModal from './CertificateDetailsModal.jsx';
import CertificateObservationHistory from './CertificateObservationHistory.jsx';
import IisReassociation from './IisReassociation.jsx';
import {
  getCertificate,
  getCertificateIdentity,
  getManagedCertificatesForToken,
  getWindowsRenewal,
  listCertOpsRenewalProfiles,
  readdManagingSource,
  replaceManagingSource,
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

// Windows discovery gives each store entry and binding its own stable source.
// Keep the full reference available, but make the target readable to operators.
function registrationLabel(source, includeHostname = true) {
  if (source.source !== 'agent_windows') return sourceLabel(source.source);
  const storeV2 = String(source.sourceRef || '').match(
    /^[^/]+\/host-sha256-[a-f0-9]{64}\/windows_store_v2\/([^/]+)\/([^/]+)\/sha256-[a-f0-9]{64}$/i
  );
  if (storeV2)
    return `Windows store copy · ${includeHostname && source.targetHostname ? `${source.targetHostname} · ` : ''}${storeV2[1]}/${storeV2[2]}`;
  const match = String(source.sourceRef || '').match(
    /^[^/]+\/([^/]+)\/(windows_store|iis_binding|http_sys)\/(.+)$/i
  );
  if (!match) return sourceLabel(source.source);
  const [, host, kind, slot] = match;
  const label = {
    windows_store: 'Windows store copy',
    iis_binding: 'IIS binding',
    http_sys: 'HTTP.sys binding',
  }[kind.toLowerCase()];
  return `${label} · ${includeHostname ? `${host} · ` : ''}${slot}`;
}

function sourceHostname(source) {
  if (source.targetHostname) return source.targetHostname;
  if (source.source !== 'agent_windows') return null;
  const match = String(source.sourceRef || '').match(
    /^[^/]+\/([^/]+)\/(?:windows_store|iis_binding|http_sys)\//i
  );
  return match?.[1] || null;
}

function SourceCell({ item }) {
  const hostname = sourceHostname(item);
  return (
    <>
      <Text fontSize='sm'>{sourceLabel(item.source)}</Text>
      {hostname ? (
        <Text fontSize='xs' color='dashboard.modal.muted'>
          {hostname}
        </Text>
      ) : null}
    </>
  );
}

function storeHasMatchingIis(source, sources, identityId) {
  if (source?.source !== 'agent_windows') return false;
  const store = /\/windows_store(?:_v2)?\//i.test(source.sourceRef || '')
    ? sourceHostname(source)
    : null;
  return Boolean(
    store &&
    sources.some(other => {
      if (
        other.source !== 'agent_windows' ||
        other.endedAt ||
        other.periodEndedAt ||
        (identityId && other.currentIdentityId !== identityId)
      )
        return false;
      const binding = String(other.sourceRef || '').match(
        /^[^/]+\/([^/]+)\/iis_binding\//i
      );
      return (
        binding && sourceHostname(other)?.toLowerCase() === store.toLowerCase()
      );
    })
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
  focusDeployments = false,
}) {
  const certificateKey = certificate?.identityId || certificate?.id || null;
  const session = useRef({ isOpen, version: 0 });
  useLayoutEffect(() => {
    session.current = { isOpen, version: session.current.version + 1 };
    return () => {
      session.current.version += 1;
    };
  }, [workspaceId, certificateKey, isOpen, canManage]);
  const isCurrent = version =>
    session.current.isOpen && session.current.version === version;
  const [detail, setDetail] = useState(null);
  const [token, setToken] = useState(null);
  const [certificateFields, setCertificateFields] = useState(null);
  const [tokenError, setTokenError] = useState('');
  const [contactGroups, setContactGroups] = useState([]);
  const [workspaceContacts, setWorkspaceContacts] = useState([]);
  const [profiles, setProfiles] = useState([]);
  const [windowsGroups, setWindowsGroups] = useState([]);
  const [windowsError, setWindowsError] = useState('');
  const [profileIds, setProfileIds] = useState({});
  const [showHistory, setShowHistory] = useState(false);
  const [showStopped, setShowStopped] = useState(false);
  const [showLocationHistory, setShowLocationHistory] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [selectedSourceId, setSelectedSourceId] = useState('');
  const latestSourceById = new Map();
  for (const source of detail?.sources || []) {
    const previous = latestSourceById.get(source.managedCertificateId);
    if (!previous || new Date(source.startedAt) > new Date(previous.startedAt))
      latestSourceById.set(source.managedCertificateId, source);
  }
  const sourceOptions = [...latestSourceById.values()];
  const eligibleRenewalChoices = sourceOptions.filter(
    source =>
      !storeHasMatchingIis(source, detail?.sources || [], detail?.identityId)
  );
  const isEndedSource = source =>
    Boolean(source.periodEndedAt || source.endedAt);
  // With exactly one current registration, preselect it so the operator does
  // not have to open the dropdown. Ended ones stay one click away.
  const currentSourceOptions = eligibleRenewalChoices.filter(
    source => !isEndedSource(source)
  );
  const renewalChoices =
    showStopped || showHistory || !currentSourceOptions.length
      ? eligibleRenewalChoices
      : currentSourceOptions;
  const defaultManagedId =
    sourceOptions.length > 1 && currentSourceOptions.length === 1
      ? currentSourceOptions[0].managedCertificateId
      : '';
  const selectedSource = sourceOptions.find(
    source => source.managedCertificateId === selectedSourceId
  );
  const selectedManagedId =
    (selectedSource &&
    renewalChoices.includes(selectedSource) &&
    !storeHasMatchingIis(
      selectedSource,
      detail?.sources || [],
      detail?.identityId
    )
      ? selectedSourceId
      : '') ||
    defaultManagedId ||
    (sourceOptions.length === 1
      ? sourceOptions[0].managedCertificateId
      : sourceOptions.length
        ? null
        : detail?.managedCertificateId ||
          (!detail?.identityId ? detail?.id : null));

  useEffect(() => {
    if (!isOpen || !workspaceId || !certificate) return undefined;
    let active = true;
    setBusy(false);
    setDetail(certificate);
    setSelectedSourceId(certificate.selectedManagedCertificateId || '');
    setToken(null);
    setCertificateFields(null);
    setError('');
    setShowHistory(false);
    setShowStopped(false);
    setShowLocationHistory(false);
    setProfileIds({});
    setWindowsGroups([]);
    setWindowsError('');
    if (certificate.identityId) {
      if (canManage)
        getWindowsRenewal(workspaceId, certificate.identityId)
          .then(value => {
            if (active) setWindowsGroups(value.groups || []);
          })
          .catch(() => {
            if (active)
              setWindowsError('Windows renewal settings could not be loaded.');
          });
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

  useEffect(() => {
    setContactGroups([]);
    setWorkspaceContacts([]);
    if (!isOpen || !workspaceId) return undefined;
    let active = true;
    // Workspace routing definitions also describe retained, verified assets
    // after their last certificate-management registration has stopped.
    Promise.all([
      workspaceAPI.getAlertSettings(workspaceId).catch(() => null),
      apiClient
        .get(`/api/v1/workspaces/${workspaceId}/contacts`)
        .catch(() => null),
    ]).then(([settings, contacts]) => {
      if (!active) return;
      setContactGroups(
        Array.isArray(settings?.contact_groups) ? settings.contact_groups : []
      );
      setWorkspaceContacts(
        Array.isArray(contacts?.data?.items) ? contacts.data.items : []
      );
    });
    return () => {
      active = false;
    };
  }, [isOpen, workspaceId]);

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
      setCertificateFields(
        sourceOptions.length <= 1
          ? identityFields
          : detail.certificateSnapshot || null
      );
      setTokenError('');
      if (!tokenId && sourceOptions.length > 1 && selectedManagedId) {
        let active = true;
        getCertificate(workspaceId, selectedManagedId)
          .then(data => {
            const matching = data?.certificate || data;
            const normalize = value =>
              String(value || '')
                .replace(/:/g, '')
                .toLowerCase();
            if (
              active &&
              matching?.id === selectedManagedId &&
              normalize(matching.fingerprintSha256) ===
                normalize(detail.fingerprintSha256)
            ) {
              setCertificateFields({
                ...matching,
                ...detail.certificateSnapshot,
              });
            }
          })
          .catch(() => {
            if (active)
              setError('Selected registration details could not be loaded.');
          });
        return () => {
          active = false;
        };
      }
      if (!tokenId || !detail.tokenSnapshot || detail.managed === false)
        return undefined;
      let active = true;
      getManagedCertificatesForToken(workspaceId, tokenId)
        .then(certificates => {
          if (!active) return;
          const normalize = value =>
            String(value || '')
              .replace(/:/g, '')
              .trim()
              .toLowerCase();
          const matching = (certificates || []).find(
            item =>
              item.id === selectedManagedId &&
              normalize(item.fingerprintSha256) ===
                normalize(detail.fingerprintSha256)
          );
          setCertificateFields(
            selectedManagedId || sourceOptions.length <= 1
              ? {
                  ...identityFields,
                  ...matching,
                  ...detail.certificateSnapshot,
                }
              : detail.certificateSnapshot || null
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
      getManagedCertificatesForToken(workspaceId, tokenId),
    ])
      .then(([tokenData, certificates]) => {
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
          matching.find(item => item.id === selectedManagedId) || null
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
    detail,
    selectedManagedId,
    sourceOptions.length,
  ]);

  const refresh = async version => {
    if (!isCurrent(version)) return;
    if (!certificate.identityId) {
      onChanged?.();
      onClose?.();
      return;
    }
    const value = await getCertificateIdentity(
      workspaceId,
      certificate.identityId
    );
    if (!isCurrent(version)) return;
    setDetail(value);
    if (canManage) {
      try {
        const value = await getWindowsRenewal(
          workspaceId,
          certificate.identityId
        );
        if (!isCurrent(version)) return;
        setWindowsGroups(value.groups || []);
        setWindowsError('');
      } catch {
        if (isCurrent(version))
          setWindowsError('Windows renewal settings could not be loaded.');
      }
    }
    if (isCurrent(version)) onChanged?.();
  };

  const stop = async periodId => {
    const version = session.current.version;
    setBusy(true);
    setError('');
    try {
      const result = await stopManagingSource(workspaceId, periodId);
      if (!isCurrent(version)) return;
      if (result.runningJobs) {
        setError(
          `${result.runningJobs} operation(s) are already running and may still complete.`
        );
      }
      await refresh(version);
    } catch (err) {
      if (isCurrent(version))
        setError(err?.response?.data?.error || err.message);
    } finally {
      if (isCurrent(version)) setBusy(false);
    }
  };

  const readd = async managedCertificateId => {
    const version = session.current.version;
    setBusy(true);
    setError('');
    try {
      const profileId = profileIds[managedCertificateId] || '';
      const source = [
        ...(detail.sources || []),
        ...(detail.restartableSources || []),
      ].find(item => item.managedCertificateId === managedCertificateId);
      if (
        source &&
        storeHasIisBinding(source) &&
        profiles.find(profile => profile.id === profileId)?.renewalProfile
          ?.target?.type === 'windows-iis'
      ) {
        throw new Error(
          'Assign the IIS renewal profile to the IIS binding instead of its store copy.'
        );
      }
      await readdManagingSource(workspaceId, managedCertificateId, {
        renewalProfileId: profileId || null,
        automationEnabled: Boolean(profileId),
      });
      await refresh(version);
    } catch (err) {
      if (isCurrent(version))
        setError(err?.response?.data?.error || err.message);
    } finally {
      if (isCurrent(version)) setBusy(false);
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
  const activeProfileCounts = new Map();
  for (const source of activeSources) {
    if (source.renewalProfileId) {
      activeProfileCounts.set(
        source.renewalProfileId,
        (activeProfileCounts.get(source.renewalProfileId) || 0) + 1
      );
    }
  }
  const windowsLocations = activeSources
    .filter(source => source.source === 'agent_windows')
    .map(source => ({
      source,
      match: String(source.sourceRef || '').match(
        /^[^/]+\/([^/]+)\/(windows_store|iis_binding)\/(.+)$/i
      ),
    }))
    .filter(item => item.match);
  const hasStoreAndIis = windowsLocations.some(
    item =>
      item.match[2].toLowerCase() === 'windows_store' &&
      windowsLocations.some(
        other =>
          other.match[2].toLowerCase() === 'iis_binding' &&
          other.match[1].toLowerCase() === item.match[1].toLowerCase()
      )
  );
  const storeHasIisBinding = source =>
    storeHasMatchingIis(source, detail.sources || [], detail.identityId);
  const duplicateStores = activeSources.filter(
    source =>
      storeHasIisBinding(source) &&
      source.renewalProfileId &&
      source.periodId &&
      activeSources.some(
        other =>
          other !== source &&
          other.renewalProfileId === source.renewalProfileId &&
          /\/iis_binding\//i.test(other.sourceRef || '')
      )
  );
  const correctDuplicateRenewal = async () => {
    const version = session.current.version;
    setBusy(true);
    setError('');
    try {
      for (const source of duplicateStores) {
        if (!isCurrent(version)) return;
        await replaceManagingSource(workspaceId, source.managedCertificateId, {
          periodId: source.periodId,
          renewalProfileId: null,
          automationEnabled: false,
        });
      }
      await refresh(version);
    } catch (err) {
      if (isCurrent(version))
        setError(err?.response?.data?.error || err.message);
      await refresh(version);
    } finally {
      if (isCurrent(version)) setBusy(false);
    }
  };
  // When a current registration exists, show stopped registrations in history.
  // If all registrations are stopped, keep the restart action accessible.
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
    !['revoked', 'decommissioned'].includes(detail.lifecycleStatus) &&
    (source.restartCandidate ||
      (Boolean(source.periodEndedAt) &&
        latestSources.get(source.managedCertificateId) === source &&
        source.endedReason !== 'endpoint_monitor_deleted' &&
        (!detail.identityId ||
          source.currentIdentityId === detail.identityId) &&
        !openSourceIds.has(source.managedCertificateId)));
  const periodSources = (detail.sources || []).filter(source => {
    if (activeSources.includes(source)) return true;
    if (canRestart(source)) return showStopped || !activeSources.length;
    return showHistory;
  });
  const visibleSources = [
    ...periodSources,
    ...(showStopped || !activeSources.length
      ? detail.restartableSources || []
      : []
    ).map(source => ({ ...source, restartCandidate: true })),
  ];
  const hiddenPeriodCount =
    (detail.sources || []).length - periodSources.length;
  // Job history and deployment details follow an explicitly selected registration.
  // An immutable identity ID is never a managed certificate ID.
  const managedCertificateId = selectedManagedId;
  const certificateFacts = {
    ...(certificateFields?.id && certificateFields.id !== managedCertificateId
      ? detail.certificateSnapshot
      : certificateFields),
    ...(managedCertificateId ? { id: managedCertificateId } : {}),
    lifecycleStatus: detail.lifecycleStatus,
    lifecycleDisplay: detail.lifecycleDisplay,
    observedRevocation: detail.observedRevocation,
    revocationObservable: detail.revocationObservable,
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
        {hasObservedRevocationContext(detail) ? (
          <ObservedRevocationBadge result={detail.observedRevocation} />
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
        headerAction={
          <CertificateObservationHistory
            workspaceId={workspaceId}
            certificateId={managedCertificateId}
            fingerprintSha256={detail.fingerprintSha256}
            enabled={isOpen}
          />
        }
        description='Where this certificate has been seen, with the latest observation at each location and previous observations in history.'
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
                      <Td>
                        <SourceCell item={location} />
                      </Td>
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
        description='One certificate can have separate registrations for its stored copy and service bindings. Each registration has its own renewal settings.'
        icon={Settings}
        enclosed
        mb={0}
      >
        <SectionContent>
          {windowsError ? (
            <Alert status='warning' mb={3}>
              <AlertIcon />
              <AlertDescription>{windowsError}</AlertDescription>
            </Alert>
          ) : null}
          {canManage
            ? sourceOptions
                .filter(
                  source =>
                    source.renewalProfileId &&
                    String(source.sourceRef || '').includes(
                      '/windows_store/'
                    ) &&
                    !isEndedSource(source)
                )
                .map(source => (
                  <IisReassociation
                    key={source.managedCertificateId}
                    workspaceId={workspaceId}
                    sourceId={source.managedCertificateId}
                    onChanged={() => {
                      onChanged?.();
                      onClose?.();
                    }}
                  />
                ))
            : null}
          {hasStoreAndIis && !windowsGroups.some(group => group.profileId) ? (
            <Box
              mb={3}
              p={3}
              borderWidth='1px'
              borderRadius='md'
              borderColor='dashboard.modal.border'
            >
              <Text fontSize='xs' color='dashboard.modal.muted' mb={2}>
                Renewal target
              </Text>
              {renewalChoices.length > 1 ? (
                <Select
                  aria-label='Renewal target'
                  size='sm'
                  value={selectedManagedId || ''}
                  onChange={event => setSelectedSourceId(event.target.value)}
                >
                  <option value=''>Select a target</option>
                  {renewalChoices.map(source => (
                    <option
                      key={source.managedCertificateId}
                      value={source.managedCertificateId}
                    >
                      {registrationLabel(source)}
                    </option>
                  ))}
                </Select>
              ) : null}
              {windowsLocations
                .filter(
                  item => item.source.managedCertificateId === selectedManagedId
                )
                .map(({ source, match }) => (
                  <HStack
                    key={source.managedCertificateId}
                    align='start'
                    spacing={3}
                  >
                    <Box
                      as={Server}
                      boxSize={5}
                      mt={1}
                      color='dashboard.modal.muted'
                    />
                    <Box>
                      <Text fontSize='sm' fontWeight='semibold'>
                        IIS · {match[3]}
                      </Text>
                      <Text fontSize='xs' color='dashboard.modal.muted'>
                        {match[1]}
                      </Text>
                      <HStack mt={2} spacing={1}>
                        <Box as={HardDrive} boxSize={3} />
                        <Text fontSize='xs' color='dashboard.modal.muted'>
                          Windows store:{' '}
                          {windowsLocations
                            .filter(
                              item =>
                                item.match[2].toLowerCase() ===
                                  'windows_store' &&
                                item.match[1].toLowerCase() ===
                                  match[1].toLowerCase()
                            )
                            .map(item =>
                              item.match[3].split('/').slice(0, 2).join('\\')
                            )
                            .filter(
                              (value, index, all) =>
                                all.indexOf(value) === index
                            )
                            .join(', ')}
                        </Text>
                        <Tooltip label='Renewing this target installs the certificate in Windows and updates this IIS binding. The store copy is included, so it has no separate renewal choice.'>
                          <Box
                            as='button'
                            type='button'
                            aria-label='How IIS renewal updates the Windows store'
                          >
                            <Info size={14} />
                          </Box>
                        </Tooltip>
                      </HStack>
                    </Box>
                  </HStack>
                ))}
            </Box>
          ) : sourceOptions.length > 1 ? (
            <FormControl mb={3}>
              <FormLabel fontSize='sm' mb={1}>
                Management registration
              </FormLabel>
              <Select
                size='sm'
                aria-label='Management registration to inspect'
                value={selectedManagedId || ''}
                onChange={event => setSelectedSourceId(event.target.value)}
              >
                {defaultManagedId ? null : (
                  <option value=''>Select a management registration</option>
                )}
                {renewalChoices.map((source, index) => (
                  <option
                    key={source.managedCertificateId}
                    value={source.managedCertificateId}
                  >
                    {registrationLabel(source)}
                    {registrationLabel(source) === sourceLabel(source.source)
                      ? ` · ${source.sourceRef || `Registration ${index + 1}`}`
                      : ''}
                    {isEndedSource(source)
                      ? ' · Ended'
                      : registrationLabel(source) === sourceLabel(source.source)
                        ? ' · Current'
                        : ''}
                  </option>
                ))}
              </Select>
              <FormHelperText fontSize='xs' color='dashboard.modal.muted'>
                Picks which registration&apos;s jobs, deployment and renewal
                profile are shown for this certificate.
              </FormHelperText>
              {!selectedManagedId ? (
                <Text fontSize='sm' mt={2}>
                  Select a registration to see its jobs, deployment and renewal
                  profile.
                </Text>
              ) : null}
            </FormControl>
          ) : null}
          {[...activeProfileCounts.values()].some(count => count > 1) ? (
            <Alert status='warning' borderRadius='md' mb={3}>
              <AlertIcon />
              <AlertDescription fontSize='sm'>
                {hasStoreAndIis
                  ? 'Automatic renewal is configured twice for this target. Keep renewal on IIS and track the store copy without a separate renewal.'
                  : 'The same renewal profile is assigned to multiple registrations. Check each target and its renewal settings before starting a renewal.'}
              </AlertDescription>
              {canManage && duplicateStores.length > 0 ? (
                <Button
                  ml={3}
                  size='sm'
                  isLoading={busy}
                  onClick={correctDuplicateRenewal}
                >
                  Keep renewal on IIS only
                </Button>
              ) : null}
            </Alert>
          ) : null}
          <Box as={hasStoreAndIis ? 'details' : 'div'}>
            {hasStoreAndIis ? (
              <Box
                as='summary'
                cursor='pointer'
                fontSize='xs'
                color='dashboard.modal.muted'
                mb={3}
              >
                Advanced registrations and history
              </Box>
            ) : null}
            <FormControl display='flex' alignItems='center' mb={3}>
              <Switch
                id='certificate-management-stopped'
                isChecked={showStopped}
                onChange={event => setShowStopped(event.target.checked)}
                mr={2}
              />
              <FormLabel
                htmlFor='certificate-management-stopped'
                mb={0}
                fontSize='sm'
              >
                Show stopped registrations
              </FormLabel>
            </FormControl>
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
                      <Th w='24%'>Registration</Th>
                      <Th w='15%'>Source</Th>
                      <Th w='18%'>Management period</Th>
                      <Th w='11%'>State</Th>
                      <Th w='15%'>Renewal</Th>
                      <Th w='17%'>Actions</Th>
                    </Tr>
                  </Thead>
                  <Tbody>
                    {visibleSources.map(source => {
                      const current = activeSources.includes(source);
                      const canReadd = canRestart(source);
                      return (
                        <Tr
                          key={`${source.periodId || source.managedCertificateId}-${source.startedAt || 'replacement'}`}
                        >
                          <Td>
                            <Text fontSize='sm' fontWeight='semibold'>
                              {registrationLabel(source, false)}
                            </Text>
                            {source.sourceRef ? (
                              <Box
                                as='details'
                                maxW='100%'
                                overflowWrap='anywhere'
                                sx={{
                                  '& .chakra-text': {
                                    whiteSpace: 'normal',
                                    overflowWrap: 'anywhere',
                                  },
                                }}
                              >
                                <Box
                                  as='summary'
                                  cursor='pointer'
                                  fontSize='xs'
                                  color='dashboard.modal.muted'
                                >
                                  Technical reference
                                </Box>
                                <CopyableId id={source.sourceRef} size='xs' />
                              </Box>
                            ) : null}
                          </Td>
                          <Td>
                            <SourceCell item={source} />
                          </Td>
                          <Td>
                            <Text fontSize='xs' color='dashboard.modal.muted'>
                              {source.restartCandidate ? (
                                'No active period'
                              ) : (
                                <>
                                  {formatDate(source.startedAt)} –{' '}
                                  {source.endedAt || source.periodEndedAt
                                    ? formatDate(
                                        source.endedAt || source.periodEndedAt
                                      )
                                    : 'present'}
                                </>
                              )}
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
                                {storeHasIisBinding(source) ? (
                                  <HStack spacing={1}>
                                    <Text fontSize='xs'>
                                      IIS renewal unavailable here
                                    </Text>
                                    <Tooltip label='This certificate is used by IIS. Assign the IIS renewal profile to the IIS binding to update the service and its store copy together.'>
                                      <Box
                                        as='button'
                                        type='button'
                                        aria-label='Why IIS renewal is unavailable for this store copy'
                                      >
                                        <Info size={14} />
                                      </Box>
                                    </Tooltip>
                                  </HStack>
                                ) : null}
                                <Select
                                  aria-label={`Renewal settings for ${source.sourceRef || source.managedCertificateId}`}
                                  size='xs'
                                  value={
                                    profileIds[source.managedCertificateId] ||
                                    ''
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
                                    <option
                                      key={profile.id}
                                      value={profile.id}
                                      disabled={
                                        profile.renewalProfile?.target?.type ===
                                          'windows-iis' &&
                                        storeHasIisBinding(source)
                                      }
                                    >
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
                                <Text
                                  fontSize='xs'
                                  color='dashboard.modal.muted'
                                >
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
                {hiddenPeriodCount} stopped or ended period(s) hidden.
              </Text>
            ) : null}
            {detail.sourceCount > (detail.sources || []).length ? (
              <Text fontSize='xs' mt={2}>
                Showing {(detail.sources || []).length} of {detail.sourceCount}{' '}
                source periods.
              </Text>
            ) : null}
          </Box>
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
      workspaceId={workspaceId}
      identityId={detail.identityId}
      managedCertificateId={managedCertificateId}
      focusDeployments={focusDeployments}
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
