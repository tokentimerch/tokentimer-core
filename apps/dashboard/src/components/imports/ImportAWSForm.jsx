import React from 'react';
import {
  Box,
  VStack,
  HStack,
  Text,
  Input,
  Button,
  Badge,
  Checkbox,
  InputGroup,
  InputRightElement,
  IconButton,
  useColorModeValue,
  Link as ChakraLink,
} from '@chakra-ui/react';
import { FiEye, FiEyeOff } from 'react-icons/fi';
import { awsAPI, integrationAPI, formatDate } from '../../utils/apiClient';
import { logger } from '../../utils/logger';
import IntegrationImportTable from '../IntegrationImportTable';
import BulkIntegrationAssignment from '../BulkIntegrationAssignment';

function getAWSItemDetails(item) {
  const details = [];
  if (item.domains) {
    const domains = Array.isArray(item.domains)
      ? item.domains.join(', ')
      : item.domains;
    details.push({ label: 'Domains', value: domains, maxLines: 2 });
  }
  if (item.issuer) {
    details.push({ label: 'Issuer', value: item.issuer });
  }
  if (item.user_name) {
    details.push({ label: 'User', value: item.user_name });
  }
  if (item.last_used_at) {
    details.push({ label: 'Last Used', value: formatDate(item.last_used_at) });
  }
  if (item.created_at) {
    details.push({ label: 'Created', value: formatDate(item.created_at) });
  }
  if (item.description) {
    details.push({ label: 'Info', value: item.description, maxLines: 2 });
  }
  if (item.location) {
    details.push({ label: 'Location', value: item.location });
  }
  return details;
}

async function checkDuplicatesForItems(items, workspaceId) {
  if (!workspaceId || !items || items.length === 0) return new Set();

  try {
    const checkItems = items.map(item => ({
      name: item.name,
      location: item.location || null,
    }));
    const duplicateCheck = await integrationAPI.checkDuplicates({
      workspaceId,
      items: checkItems,
    });

    if (duplicateCheck.duplicate_count > 0) {
      const duplicateSet = new Set();
      duplicateCheck.duplicates.forEach(dup => {
        items.forEach((item, idx) => {
          if (
            item.name === dup.name &&
            (item.location || null) === (dup.location || null)
          ) {
            duplicateSet.add(idx);
          }
        });
      });
      return duplicateSet;
    }
  } catch (e) {
    logger.error('Duplicate check failed:', e);
  }
  return new Set();
}

export function buildAwsAutoSyncPayload({
  accessKeyId,
  secretAccessKey,
  awsRegion,
  awsDetectedRegions = [],
}) {
  const scanMode =
    awsRegion === 'all-regions'
      ? 'all-regions'
      : awsRegion === 'global'
        ? 'global'
        : 'single';
  const region = scanMode === 'single' ? awsRegion || 'us-east-1' : 'us-east-1';

  return {
    credentials: {
      accessKeyId,
      secretAccessKey,
      region,
    },
    scanParams: {
      scanMode,
      region,
      detectedRegions:
        scanMode === 'all-regions' ? [...awsDetectedRegions] : [],
      maxItems: 500,
    },
  };
}

const ImportAWSForm = React.forwardRef(function ImportAWSForm(
  {
    workspaceId,
    onImportComplete,
    onError,
    onScanSuccess,
    borderColor,
    helpTextColor,
    autoSyncTokenPlaceholder,
    updateQuotaFromResponse,
    refreshIntegrationQuota,
    isQuotaExceededError,
    formatQuotaError,
    extractQuotaFromError,
    contactGroups,
    onSelectionChange,
    initialAutoSyncScanParams = null,
  },
  ref
) {
  const isLight = useColorModeValue(true, false);

  const [awsAccessKeyId, setAwsAccessKeyId] = React.useState('');
  const [awsSecretAccessKey, setAwsSecretAccessKey] = React.useState('');
  const [awsRegion, setAwsRegion] = React.useState('us-east-1');
  const [awsDetectedRegions, setAwsDetectedRegions] = React.useState([]);
  const [awsDetectionResults, setAwsDetectionResults] = React.useState(null);
  const [awsIamInfo, setAwsIamInfo] = React.useState(null);
  const [awsDetecting, setAwsDetecting] = React.useState(false);
  const [awsItems, setAwsItems] = React.useState([]);
  const [awsSummary, setAwsSummary] = React.useState([]);
  const [selectedRowsAws, setSelectedRowsAws] = React.useState(new Set());
  const [awsDuplicates, setAwsDuplicates] = React.useState(new Set());
  const [isScanning, setIsScanning] = React.useState(false);
  const [showSecret, setShowSecret] = React.useState(false);
  const [bulkSection, setBulkSection] = React.useState('');
  const [bulkContactGroupId, setBulkContactGroupId] = React.useState('');
  const [cleanupObsolete, setCleanupObsolete] = React.useState(false);
  // The backend-authoritative scan record cleanup is driven from. Only set
  // when a single backend scan call covers this scan (global or one
  // specific region); "all regions" makes multiple backend calls (one per
  // region, since AWS has no single "list every region" secrets API), so
  // there's no single scan_id that covers the whole sweep yet -- cleanup
  // stays unavailable for that mode until scan persistence supports
  // combining multiple scan calls into one record.
  const [lastScanId, setLastScanId] = React.useState(null);

  React.useEffect(() => {
    onSelectionChange && onSelectionChange(selectedRowsAws.size);
  }, [selectedRowsAws.size, onSelectionChange]);

  React.useEffect(() => {
    if (!initialAutoSyncScanParams) return;
    const sp = initialAutoSyncScanParams;
    if (sp.scanMode === 'all-regions' || sp.region === 'all-regions') {
      setAwsRegion('all-regions');
    } else if (sp.scanMode === 'global' || sp.region === 'global') {
      setAwsRegion('global');
    } else if (sp.region) {
      setAwsRegion(sp.region);
    }
    if (Array.isArray(sp.detectedRegions)) {
      setAwsDetectedRegions(sp.detectedRegions);
    }
  }, [initialAutoSyncScanParams]);

  const detectAwsRegions = async () => {
    if (!workspaceId) {
      onError && onError('Please select a workspace first.');
      return;
    }
    onError && onError(null);
    setAwsDetecting(true);
    try {
      const res = await awsAPI.detectRegions({
        workspaceId,
        accessKeyId: awsAccessKeyId,
        secretAccessKey: awsSecretAccessKey,
      });
      const secretRegions = res?.regionsWithSecrets || [];
      const certRegions = res?.regionsWithCertificates || [];
      const iamInfo = res?.iam || null;

      const allRegions = [
        ...new Set([...secretRegions, ...certRegions]),
      ].sort();

      setAwsDetectedRegions(allRegions);
      setAwsDetectionResults(res);
      setAwsIamInfo(iamInfo);

      if (
        allRegions.length > 1 ||
        (allRegions.length > 0 && iamInfo && iamInfo.keysCount > 0)
      ) {
        setAwsRegion('all-regions');
      } else if (
        allRegions.length === 1 &&
        (!iamInfo || iamInfo.keysCount === 0)
      ) {
        setAwsRegion(allRegions[0]);
      } else if (iamInfo && iamInfo.keysCount > 0) {
        setAwsRegion('global');
      } else {
        onError &&
          onError(
            'No regions with secrets/certificates found and no IAM keys detected. You may need to create resources in AWS first.'
          );
      }
    } catch (e) {
      onError && onError(e?.message || 'AWS region detection failed');
    } finally {
      setAwsDetecting(false);
    }
  };

  const doAwsScan = async () => {
    if (!workspaceId) {
      onError && onError('Please select a workspace first.');
      return;
    }
    if (!awsAccessKeyId || !awsAccessKeyId.trim()) {
      onError && onError('AWS Access Key ID is required');
      return;
    }
    if (!awsSecretAccessKey || !awsSecretAccessKey.trim()) {
      onError && onError('AWS Secret Access Key is required');
      return;
    }
    if (!awsRegion || awsRegion.trim() === '') {
      onError && onError('AWS Region is required');
      return;
    }

    onError && onError(null);
    setIsScanning(true);
    setAwsItems([]);
    setAwsSummary([]);
    try {
      const isGlobalScan = awsRegion === 'global';
      const isAllRegionsScan = awsRegion === 'all-regions';

      if (isAllRegionsScan) {
        const allItems = [];
        const summaryByType = {};

        const iamRes = await awsAPI.scan({
          workspaceId,
          accessKeyId: awsAccessKeyId,
          secretAccessKey: awsSecretAccessKey,
          region: 'us-east-1',
          maxItems: 2000,
          include: { secrets: false, iam: true, certificates: false },
          isContinuation: false,
        });
        allItems.push(...(iamRes?.items || []));

        (iamRes?.summary || []).forEach(s => {
          if (!summaryByType[s.type]) {
            summaryByType[s.type] = {
              type: s.type,
              found: 0,
              error: null,
              note: null,
            };
          }
          if (s.found !== undefined) summaryByType[s.type].found += s.found;
          if (s.error) summaryByType[s.type].error = s.error;
          if (s.note) summaryByType[s.type].note = s.note;
        });

        for (const region of awsDetectedRegions) {
          const regionRes = await awsAPI.scan({
            workspaceId,
            accessKeyId: awsAccessKeyId,
            secretAccessKey: awsSecretAccessKey,
            region,
            maxItems: 2000,
            include: { secrets: true, iam: false, certificates: true },
            isContinuation: true,
          });
          allItems.push(...(regionRes?.items || []));

          (regionRes?.summary || []).forEach(s => {
            if (!summaryByType[s.type]) {
              summaryByType[s.type] = {
                type: s.type,
                found: 0,
                error: null,
                note: null,
              };
            }
            if (s.found !== undefined) summaryByType[s.type].found += s.found;
            if (s.error && !summaryByType[s.type].error)
              summaryByType[s.type].error = s.error;
            if (s.note && !summaryByType[s.type].note)
              summaryByType[s.type].note = s.note;
          });
        }

        const aggregatedSummary = Object.values(summaryByType);
        setAwsItems(allItems);
        setAwsSummary(aggregatedSummary);
        // Each region (and the IAM call) is a separate backend scan record,
        // so there is no single scan_id covering the whole sweep -- cleanup
        // stays unavailable for this mode.
        setLastScanId(null);
        if (allItems.length > 0) {
          onScanSuccess && onScanSuccess('aws');
        }

        const dups = await checkDuplicatesForItems(allItems, workspaceId);
        setAwsDuplicates(dups);

        if (updateQuotaFromResponse && !updateQuotaFromResponse(iamRes)) {
          if (refreshIntegrationQuota) await refreshIntegrationQuota();
        }
      } else {
        const scanRegion = isGlobalScan ? 'us-east-1' : awsRegion;
        const res = await awsAPI.scan({
          workspaceId,
          accessKeyId: awsAccessKeyId,
          secretAccessKey: awsSecretAccessKey,
          region: scanRegion,
          maxItems: 2000,
          include: {
            secrets: !isGlobalScan,
            iam: isGlobalScan,
            certificates: !isGlobalScan,
          },
        });
        const items = Array.isArray(res?.items) ? res.items : [];
        setAwsItems(items);
        setAwsSummary(Array.isArray(res?.summary) ? res.summary : []);
        // A single backend call (global IAM sweep, or one specific region)
        // maps to exactly one persisted scan record, so its scan_id can
        // drive cleanup scoped to whatever the backend confirms it fully
        // covered (account-wide IAM, or that one region's secrets/certs).
        setLastScanId(res?.scan_id || null);
        if (items.length > 0) {
          onScanSuccess && onScanSuccess('aws');
        }

        const dups = await checkDuplicatesForItems(items, workspaceId);
        setAwsDuplicates(dups);

        if (updateQuotaFromResponse && !updateQuotaFromResponse(res)) {
          if (refreshIntegrationQuota) await refreshIntegrationQuota();
        }
      }
    } catch (e) {
      setAwsItems([]);
      setAwsSummary([]);
      setLastScanId(null);
      if (isQuotaExceededError && isQuotaExceededError(e)) {
        onError && onError(formatQuotaError ? formatQuotaError(e) : e?.message);
      } else {
        onError && onError(e?.message || 'AWS scan failed');
      }
      if (extractQuotaFromError && !extractQuotaFromError(e)) {
        if (refreshIntegrationQuota) await refreshIntegrationQuota();
      }
    } finally {
      setIsScanning(false);
    }
  };

  const updateAwsItem = (index, updates) => {
    setAwsItems(prev => {
      const updated = [...prev];
      updated[index] = { ...updated[index], ...updates };
      return updated;
    });
  };

  const importAwsSelected = async () => {
    try {
      const selected = awsItems
        .filter((_, i) => selectedRowsAws.has(i))
        .map(item => ({
          ...item,
          section: bulkSection || item.section || null,
          contact_group_id: bulkContactGroupId || null,
        }));
      if (!workspaceId) {
        onError && onError('Please select a workspace first.');
        return;
      }

      await integrationAPI.import({
        workspaceId,
        items: selected,
        defaults: {},
        // scan_id is sent whenever this import followed a scan, regardless
        // of whether cleanup is enabled -- provenance attribution must not
        // depend on the cleanup toggle (see apiClient.js).
        scanId: lastScanId || undefined,
        cleanup:
          cleanupObsolete && lastScanId
            ? {
                enabled: true,
                provider: 'aws',
                scanId: lastScanId,
              }
            : undefined,
      });
      onImportComplete && onImportComplete(selected);
    } catch (e) {
      onError && onError(e?.message || 'AWS import failed');
    }
  };

  React.useImperativeHandle(ref, () => ({
    importSelected: importAwsSelected,
    getSelectedCount: () => selectedRowsAws.size,
    getCredentials: () =>
      buildAwsAutoSyncPayload({
        accessKeyId: awsAccessKeyId,
        secretAccessKey: awsSecretAccessKey,
        awsRegion,
        awsDetectedRegions,
      }),
  }));

  return (
    <VStack align='stretch' spacing={3}>
      <Box>
        <Text fontSize='sm' color={helpTextColor}>
          Scans AWS Secrets Manager and IAM for secrets and access keys.
          Credentials are used for scanning and stored encrypted if auto-sync is
          enabled.
        </Text>
        <Text fontSize='sm' mt={1}>
          <ChakraLink
            onClick={() =>
              window.open(
                'https://tokentimer.ch/docs/tokens#import-aws',
                '_blank',
                'noopener,noreferrer'
              )
            }
            cursor='pointer'
            color='blue.500'
            textDecoration='underline'
            isExternal
          >
            Learn more about importing from AWS →
          </ChakraLink>
        </Text>
      </Box>
      <HStack spacing={3} align='flex-end' flexWrap='wrap'>
        <Box minW='220px'>
          <Text fontSize='sm' mb={1}>
            Access Key ID
          </Text>
          <Input
            placeholder='AKIAIOSFODNN7EXAMPLE'
            value={awsAccessKeyId}
            onChange={e => setAwsAccessKeyId(e.target.value)}
          />
        </Box>
        <Box minW='280px'>
          <Text fontSize='sm' mb={1}>
            Secret Access Key
          </Text>
          <InputGroup>
            <Input
              type={showSecret ? 'text' : 'password'}
              placeholder={autoSyncTokenPlaceholder || 'Secret key'}
              value={awsSecretAccessKey}
              onChange={e => setAwsSecretAccessKey(e.target.value)}
            />
            <InputRightElement>
              <IconButton
                size='xs'
                variant='ghost'
                icon={showSecret ? <FiEyeOff /> : <FiEye />}
                onClick={() => setShowSecret(!showSecret)}
                aria-label={showSecret ? 'Hide' : 'Show'}
              />
            </InputRightElement>
          </InputGroup>
        </Box>
        <Button
          colorScheme='purple'
          onClick={detectAwsRegions}
          isLoading={awsDetecting}
          isDisabled={!awsAccessKeyId || !awsSecretAccessKey}
        >
          Detect Regions
        </Button>
      </HStack>
      <Box border='1px solid' borderColor={borderColor} borderRadius='md' p={3}>
        <VStack align='stretch' spacing={2}>
          <Checkbox
            isChecked={cleanupObsolete}
            onChange={e => setCleanupObsolete(e.target.checked)}
            isDisabled={!lastScanId}
            size='sm'
            colorScheme='red'
          >
            Remove previously imported items no longer found at the source
          </Checkbox>
          <Text fontSize='xs' color={helpTextColor} pl={6}>
            Only available for a &quot;Global (IAM only)&quot; scan, or a single
            specific region, right after that scan completes. Each region is
            checked independently, so a single scan_id can only certify what it
            actually covered; an &quot;All Regions&quot; sweep makes one backend
            call per region and has no single scan record to attach cleanup to
            yet.
          </Text>
          {lastScanId && awsSummary.some(s => s.complete === false) ? (
            <Text fontSize='xs' color='orange.400' pl={6}>
              The last scan didn't fully complete for every item type above (see
              the errors below). The backend will only clean up item types it
              confirmed were fully scanned; nothing incomplete or errored is
              ever touched.
            </Text>
          ) : null}
          {cleanupObsolete ? (
            <Text fontSize='xs' color='red.400' pl={6}>
              Deletes previously imported items of the item types scanned above
              (secrets, certificates, and/or IAM keys, depending on the scan you
              run) that no longer appear anywhere in this scan's results,
              regardless of which items you select for import below. Item types
              you did not scan for are never affected. This cannot be undone.
            </Text>
          ) : null}
        </VStack>
      </Box>
      {(awsDetectedRegions.length > 0 ||
        (awsIamInfo && awsIamInfo.keysCount > 0)) && (
        <VStack align='stretch' spacing={3}>
          {awsDetectedRegions.length > 0 && awsDetectionResults && (
            <Box>
              <Text fontSize='sm' mb={2} fontWeight='semibold'>
                Select Resources to Scan:
              </Text>
              <VStack align='stretch' spacing={2}>
                {awsDetectedRegions.length > 0 &&
                  awsIamInfo &&
                  awsIamInfo.keysCount > 0 && (
                    <Box
                      p={2}
                      borderRadius='md'
                      border='2px solid'
                      borderColor='purple.400'
                      bg={
                        awsRegion === 'all-regions'
                          ? isLight
                            ? 'purple.50'
                            : 'purple.900'
                          : 'transparent'
                      }
                    >
                      <HStack spacing={2} justify='space-between'>
                        <HStack spacing={2}>
                          <Text fontSize='sm' fontWeight='bold'>
                            All Regions + Global
                          </Text>
                          <Badge colorScheme='purple' fontSize='xs'>
                            {awsDetectedRegions.length} region
                            {awsDetectedRegions.length !== 1 ? 's' : ''} + IAM
                          </Badge>
                        </HStack>
                        <Button
                          size='xs'
                          colorScheme='purple'
                          onClick={() => setAwsRegion('all-regions')}
                          isDisabled={awsRegion === 'all-regions'}
                        >
                          {awsRegion === 'all-regions' ? 'Selected' : 'Select'}
                        </Button>
                      </HStack>
                    </Box>
                  )}
                {awsIamInfo && awsIamInfo.keysCount > 0 && (
                  <Box
                    p={2}
                    borderRadius='md'
                    border='1px solid'
                    borderColor={borderColor}
                    bg={
                      awsRegion === 'global'
                        ? isLight
                          ? 'blue.50'
                          : 'blue.900'
                        : 'transparent'
                    }
                  >
                    <HStack spacing={2} justify='space-between'>
                      <HStack spacing={2}>
                        <Text fontSize='sm' fontWeight='medium'>
                          Global (IAM only)
                        </Text>
                        <Badge colorScheme='orange' fontSize='xs'>
                          {awsIamInfo.keysCount} access key
                          {awsIamInfo.keysCount !== 1 ? 's' : ''}
                        </Badge>
                      </HStack>
                      <Button
                        size='xs'
                        colorScheme='blue'
                        onClick={() => setAwsRegion('global')}
                        isDisabled={awsRegion === 'global'}
                      >
                        {awsRegion === 'global' ? 'Selected' : 'Select'}
                      </Button>
                    </HStack>
                  </Box>
                )}
                {awsDetectedRegions.map(region => {
                  const hasSecrets =
                    awsDetectionResults.regionsWithSecrets?.includes(region);
                  const hasCerts =
                    awsDetectionResults.regionsWithCertificates?.includes(
                      region
                    );
                  return (
                    <Box
                      key={region}
                      p={2}
                      borderRadius='md'
                      border='1px solid'
                      borderColor={borderColor}
                      bg={
                        awsRegion === region
                          ? isLight
                            ? 'blue.50'
                            : 'blue.900'
                          : 'transparent'
                      }
                    >
                      <HStack spacing={2} justify='space-between'>
                        <HStack spacing={2}>
                          <Text fontSize='sm' fontWeight='medium'>
                            {region}
                          </Text>
                          {hasSecrets && (
                            <Badge colorScheme='green' fontSize='xs'>
                              Secrets
                            </Badge>
                          )}
                          {hasCerts && (
                            <Badge colorScheme='purple' fontSize='xs'>
                              Certificates
                            </Badge>
                          )}
                        </HStack>
                        <Button
                          size='xs'
                          colorScheme='blue'
                          onClick={() => setAwsRegion(region)}
                          isDisabled={awsRegion === region}
                        >
                          {awsRegion === region ? 'Selected' : 'Select'}
                        </Button>
                      </HStack>
                    </Box>
                  );
                })}
              </VStack>
              <Button
                mt={3}
                colorScheme='blue'
                onClick={doAwsScan}
                isLoading={isScanning}
                width='full'
              >
                {awsRegion === 'all-regions'
                  ? `Scan All Regions + Global (${awsDetectedRegions.length + 1} scans)`
                  : awsRegion === 'global'
                    ? 'Scan IAM Keys (Global)'
                    : `Scan ${awsRegion}`}
              </Button>
            </Box>
          )}
          {awsDetectedRegions.length === 0 &&
            awsIamInfo &&
            awsIamInfo.keysCount > 0 && (
              <Box>
                <Text fontSize='sm' mb={2}>
                  Only IAM keys found (no regional resources detected):
                </Text>
                <Box
                  p={2}
                  borderRadius='md'
                  border='1px solid'
                  borderColor={borderColor}
                  bg={isLight ? 'blue.50' : 'blue.900'}
                >
                  <HStack spacing={2} justify='space-between'>
                    <HStack spacing={2}>
                      <Text fontSize='sm' fontWeight='medium'>
                        Global (IAM only)
                      </Text>
                      <Badge colorScheme='orange' fontSize='xs'>
                        {awsIamInfo.keysCount} access key
                        {awsIamInfo.keysCount !== 1 ? 's' : ''}
                      </Badge>
                    </HStack>
                  </HStack>
                </Box>
                <Button
                  mt={3}
                  colorScheme='blue'
                  onClick={doAwsScan}
                  isLoading={isScanning}
                  width='full'
                >
                  Scan IAM Keys (Global)
                </Button>
              </Box>
            )}
        </VStack>
      )}
      {awsSummary.length > 0 && (
        <Box
          border='1px solid'
          borderColor={borderColor}
          borderRadius='md'
          p={3}
        >
          <VStack align='stretch' spacing={2}>
            {awsSummary.map((s, i) => (
              <HStack key={i} justify='space-between'>
                <Text fontSize='sm'>{s.type}</Text>
                {s.error ? (
                  <Badge colorScheme='red'>{s.error}</Badge>
                ) : s.note ? (
                  <Badge colorScheme='yellow'>{s.note}</Badge>
                ) : (
                  <Badge colorScheme='green'>found {s.found}</Badge>
                )}
              </HStack>
            ))}
          </VStack>
        </Box>
      )}
      {awsItems.length > 0 && (
        <>
          <IntegrationImportTable
            items={awsItems}
            selectedRows={selectedRowsAws}
            onToggleRow={i =>
              setSelectedRowsAws(prev => {
                const n = new Set(prev);
                n.has(i) ? n.delete(i) : n.add(i);
                return n;
              })
            }
            onToggleAll={() => {
              if (selectedRowsAws.size === awsItems.length) {
                setSelectedRowsAws(new Set());
              } else {
                setSelectedRowsAws(new Set(awsItems.map((_, i) => i)));
              }
            }}
            borderColor={borderColor}
            getDetailsForItem={getAWSItemDetails}
            onUpdateItem={updateAwsItem}
            duplicateIndices={awsDuplicates}
          />
          <BulkIntegrationAssignment
            selectedCount={selectedRowsAws.size}
            section={bulkSection}
            onSectionChange={setBulkSection}
            contactGroupId={bulkContactGroupId}
            onContactGroupChange={setBulkContactGroupId}
            contactGroups={contactGroups}
            borderColor={borderColor}
          />
        </>
      )}
    </VStack>
  );
});

export default ImportAWSForm;
