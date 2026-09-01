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
  Link as ChakraLink,
} from '@chakra-ui/react';
import { FiEye, FiEyeOff } from 'react-icons/fi';
import { gcpAPI, integrationAPI } from '../../utils/apiClient';
import { logger } from '../../utils/logger';
import { IMPORT_DOCS } from '../../utils/docsUrls';
import IntegrationImportTable from '../IntegrationImportTable';
import BulkIntegrationAssignment from '../BulkIntegrationAssignment';

function getGCPItemDetails(item) {
  const details = [];
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

const ImportGCPForm = React.forwardRef(function ImportGCPForm(
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
  },
  ref
) {
  const [gcpProjectId, setGcpProjectId] = React.useState('');
  const [gcpAccessToken, setGcpAccessToken] = React.useState('');
  const [gcpItems, setGcpItems] = React.useState([]);
  const [gcpSummary, setGcpSummary] = React.useState([]);
  const [selectedRowsGcp, setSelectedRowsGcp] = React.useState(new Set());
  const [gcpDuplicates, setGcpDuplicates] = React.useState(new Set());
  const [isScanning, setIsScanning] = React.useState(false);
  const [showSecret, setShowSecret] = React.useState(false);
  const [bulkSection, setBulkSection] = React.useState('');
  const [bulkContactGroupId, setBulkContactGroupId] = React.useState('');
  const [cleanupObsolete, setCleanupObsolete] = React.useState(false);
  // The backend-authoritative scan record cleanup is driven from.
  const [lastScanId, setLastScanId] = React.useState(null);

  React.useEffect(() => {
    onSelectionChange && onSelectionChange(selectedRowsGcp.size);
  }, [selectedRowsGcp.size, onSelectionChange]);

  const doGcpScan = async () => {
    if (!workspaceId) {
      onError && onError('Please select a workspace first.');
      return;
    }
    if (!gcpProjectId || !gcpProjectId.trim()) {
      onError && onError('GCP Project ID is required');
      return;
    }
    if (!gcpAccessToken || !gcpAccessToken.trim()) {
      onError && onError('GCP access token is required');
      return;
    }

    onError && onError(null);
    setIsScanning(true);
    setGcpItems([]);
    setGcpSummary([]);
    try {
      const res = await gcpAPI.scan({
        workspaceId,
        projectId: gcpProjectId,
        accessToken: gcpAccessToken,
        maxItems: 2000,
      });
      const items = Array.isArray(res?.items) ? res.items : [];
      setGcpItems(items);
      setGcpSummary(Array.isArray(res?.summary) ? res.summary : []);
      setLastScanId(res?.scan_id || null);
      if (items.length > 0) {
        onScanSuccess && onScanSuccess('gcp');
      }

      if (updateQuotaFromResponse && !updateQuotaFromResponse(res)) {
        if (refreshIntegrationQuota) await refreshIntegrationQuota();
      }

      const dups = await checkDuplicatesForItems(items, workspaceId);
      setGcpDuplicates(dups);
    } catch (e) {
      setGcpItems([]);
      setGcpSummary([]);
      setLastScanId(null);
      if (isQuotaExceededError && isQuotaExceededError(e)) {
        onError && onError(formatQuotaError ? formatQuotaError(e) : e?.message);
      } else {
        onError && onError(e?.message || 'GCP scan failed');
      }
      if (extractQuotaFromError && !extractQuotaFromError(e)) {
        if (refreshIntegrationQuota) await refreshIntegrationQuota();
      }
    } finally {
      setIsScanning(false);
    }
  };

  const updateGcpItem = (index, updates) => {
    setGcpItems(prev => {
      const updated = [...prev];
      updated[index] = { ...updated[index], ...updates };
      return updated;
    });
  };

  const importGcpSelected = async () => {
    try {
      const selected = gcpItems
        .filter((_, i) => selectedRowsGcp.has(i))
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
                provider: 'gcp',
                scanId: lastScanId,
              }
            : undefined,
      });
      onImportComplete && onImportComplete(selected);
    } catch (e) {
      onError && onError(e?.message || 'GCP import failed');
    }
  };

  React.useImperativeHandle(ref, () => ({
    importSelected: importGcpSelected,
    getSelectedCount: () => selectedRowsGcp.size,
    getCredentials: () => ({
      credentials: { projectId: gcpProjectId, accessToken: gcpAccessToken },
      scanParams: {
        projectId: gcpProjectId,
        include: { secrets: true },
      },
    }),
  }));

  return (
    <VStack align='stretch' spacing={3}>
      <Box>
        <Text fontSize='sm' color={helpTextColor}>
          Scans GCP Secret Manager for secrets with expiration dates. Paste an
          access token from Cloud Shell (`gcloud auth print-access-token`), not
          a JSON key. Grant Secret Manager Viewer on the project; Secret
          Accessor cannot list secrets. Token is used for this scan and not
          stored. If auto-sync is enabled, the token is stored encrypted.
        </Text>
        <Text fontSize='sm' mt={1}>
          <ChakraLink
            href={IMPORT_DOCS.gcp}
            color='blue.500'
            textDecoration='underline'
            isExternal
          >
            Learn more about importing from GCP Secret Manager →
          </ChakraLink>
        </Text>
      </Box>
      <HStack spacing={3} align='flex-end' flexWrap='wrap'>
        <Box minW='240px'>
          <Text fontSize='sm' mb={1}>
            Project ID
          </Text>
          <Input
            placeholder='my-project-123'
            value={gcpProjectId}
            onChange={e => setGcpProjectId(e.target.value)}
          />
        </Box>
        <Box minW='320px'>
          <Text fontSize='sm' mb={1}>
            Access Token
          </Text>
          <InputGroup>
            <Input
              type={showSecret ? 'text' : 'password'}
              placeholder={autoSyncTokenPlaceholder || 'Paste OAuth2 token'}
              value={gcpAccessToken}
              onChange={e => setGcpAccessToken(e.target.value)}
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
        <Button colorScheme='blue' onClick={doGcpScan} isLoading={isScanning}>
          Scan
        </Button>
      </HStack>
      <Box border='1px solid' borderColor={borderColor} borderRadius='md' p={3}>
        <VStack align='stretch' spacing={2}>
          <Checkbox
            isChecked={cleanupObsolete}
            onChange={e => setCleanupObsolete(e.target.checked)}
            size='sm'
            colorScheme='red'
            isDisabled={!lastScanId}
          >
            Remove previously imported secrets no longer found at the source
          </Checkbox>
          {!lastScanId ? (
            <Text fontSize='xs' color={helpTextColor} pl={6}>
              Run a scan first; cleanup is driven by the backend's record of
              what that scan covered.
            </Text>
          ) : gcpSummary.some(s => s.complete === false) ? (
            <Text fontSize='xs' color='orange.400' pl={6}>
              The last scan didn't fully complete (see the errors below). The
              backend refuses to clean up an incomplete or truncated scan.
            </Text>
          ) : gcpSummary.some(s => s.failedCount > 0) ? (
            <Text fontSize='xs' color='orange.400' pl={6}>
              Some listed secrets have no expiration because their version
              lookup failed. Cleanup still runs against the listed set.
            </Text>
          ) : null}
          {cleanupObsolete ? (
            <Text fontSize='xs' color='red.400' pl={6}>
              Deletes previously imported secrets from this GCP project that no
              longer appear anywhere in this scan's results, regardless of which
              items you select for import below. This cannot be undone.
            </Text>
          ) : null}
        </VStack>
      </Box>
      {gcpSummary.length > 0 && (
        <Box
          border='1px solid'
          borderColor={borderColor}
          borderRadius='md'
          p={3}
        >
          <VStack align='stretch' spacing={2}>
            {gcpSummary.map((s, i) => (
              <HStack key={i} justify='space-between'>
                <Text fontSize='sm'>{s.type}</Text>
                {s.error ? (
                  <Badge colorScheme='red'>{s.error}</Badge>
                ) : (
                  <HStack spacing={2}>
                    <Badge colorScheme='green'>found {s.found}</Badge>
                    {s.failedCount > 0 ? (
                      <Badge colorScheme='orange'>
                        {s.failedCount} without expiration
                      </Badge>
                    ) : null}
                  </HStack>
                )}
              </HStack>
            ))}
          </VStack>
        </Box>
      )}
      {gcpItems.length > 0 && (
        <>
          <IntegrationImportTable
            items={gcpItems}
            selectedRows={selectedRowsGcp}
            onToggleRow={i =>
              setSelectedRowsGcp(prev => {
                const n = new Set(prev);
                n.has(i) ? n.delete(i) : n.add(i);
                return n;
              })
            }
            onToggleAll={() => {
              if (selectedRowsGcp.size === gcpItems.length) {
                setSelectedRowsGcp(new Set());
              } else {
                setSelectedRowsGcp(new Set(gcpItems.map((_, i) => i)));
              }
            }}
            borderColor={borderColor}
            getDetailsForItem={getGCPItemDetails}
            onUpdateItem={updateGcpItem}
            duplicateIndices={gcpDuplicates}
          />
          <BulkIntegrationAssignment
            selectedCount={selectedRowsGcp.size}
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

export default ImportGCPForm;
