import React from 'react';
import { useScanVerification } from '../../hooks/useScanVerification.js';
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
  Code,
} from '@chakra-ui/react';
import { FiEye, FiEyeOff } from 'react-icons/fi';
import { gcpAPI, integrationAPI } from '../../utils/apiClient';
import { logger } from '../../utils/logger';
import { IMPORT_DOCS } from '../../utils/docsUrls';
import LearnMorePanel from '../LearnMorePanel';
import FilterRulesEditor, {
  sanitizeFilterRules,
  FilterRulesSummary,
} from '../FilterRulesEditor';
import IntegrationImportTable from '../IntegrationImportTable';
import BulkIntegrationAssignment from '../BulkIntegrationAssignment';
import {
  canonicalContactGroupFields,
  contactGroupFieldsForImportDefaults,
} from '../../utils/contactGroupAssignment.js';

const GCP_SUMMARY_LABELS = {
  secrets: 'Secrets',
  certificate_manager_certs: 'Certificate Manager',
  compute_ssl_certs: 'Compute Engine SSL certificates',
  scan: 'Scan',
};

function gcpSummaryLabel(type) {
  return GCP_SUMMARY_LABELS[type] || type;
}

function gcpSummaryErrorText(summary) {
  if (!summary?.error) return null;
  const prefix = `${gcpSummaryLabel(summary.type)}: `;
  return summary.error.startsWith(prefix)
    ? summary.error.slice(prefix.length)
    : summary.error;
}

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
    errorContent,
    onScanSuccess,
    onScanInvalidated,
    scanContext,
    borderColor,
    helpTextColor,
    hideDocs = false,
    autoSyncTokenPlaceholder,
    updateQuotaFromResponse,
    refreshIntegrationQuota,
    isQuotaExceededError,
    formatQuotaError,
    extractQuotaFromError,
    contactGroups,
    onSelectionChange,
    initialScanParams = null,
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
  const [bulkContactGroupIds, setBulkContactGroupIds] = React.useState([]);
  const [scanSecrets, setScanSecrets] = React.useState(true);
  const [scanCertificates, setScanCertificates] = React.useState(false);
  const [cleanupObsolete, setCleanupObsolete] = React.useState(false);
  const [filterRules, setFilterRules] = React.useState([]);
  const [filterSummary, setFilterSummary] = React.useState(null);
  const [previewReady, setPreviewReady] = React.useState(false);
  React.useEffect(() => {
    if (!initialScanParams) return;
    const sp = initialScanParams;
    setFilterRules(Array.isArray(sp.filterRules) ? sp.filterRules : []);
    setGcpProjectId(sp.projectId || '');
    setScanSecrets(sp.include?.secrets ?? true);
    setScanCertificates(sp.include?.certificates ?? false);
  }, [initialScanParams]);
  // The backend-authoritative scan record cleanup is driven from.
  const [lastScanId, setLastScanId] = React.useState(null);

  React.useEffect(() => {
    onSelectionChange &&
      onSelectionChange(previewReady ? selectedRowsGcp.size : 0);
  }, [selectedRowsGcp.size, previewReady, onSelectionChange]);

  const doGcpScan = async () => {
    const scanTicket = beginScanVerification();
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
    if (!scanSecrets && !scanCertificates) {
      onError && onError('Select secrets, certificates, or both.');
      return;
    }

    onError && onError(null);
    setIsScanning(true);
    setGcpItems([]);
    setGcpSummary([]);
    setFilterSummary(null);
    try {
      const res = await gcpAPI.scan({
        workspaceId,
        projectId: gcpProjectId,
        accessToken: gcpAccessToken,
        include: { secrets: scanSecrets, certificates: scanCertificates },
        filterRules: sanitizeFilterRules(filterRules),
        maxItems: 2000,
      });
      if (!isScanCurrent(scanTicket)) return;
      const items = Array.isArray(res?.items) ? res.items : [];
      setGcpItems(items);
      setGcpSummary(Array.isArray(res?.summary) ? res.summary : []);
      setFilterSummary(res?.filterSummary || null);
      setLastScanId(res?.scan_id || null);

      if (updateQuotaFromResponse && !updateQuotaFromResponse(res)) {
        if (refreshIntegrationQuota) await refreshIntegrationQuota();
      }

      const dups = await checkDuplicatesForItems(items, workspaceId);
      if (!isScanCurrent(scanTicket)) return;
      setGcpDuplicates(dups);
      setPreviewReady(true);
      completeScanVerification(scanTicket);
    } catch (e) {
      if (!isScanCurrent(scanTicket)) return;
      setGcpItems([]);
      setGcpSummary([]);
      setFilterSummary(null);
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
      if (isScanCurrent(scanTicket)) setIsScanning(false);
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
    if (!previewReady || isScanning) {
      onError?.('Run a scan with the current settings before importing.');
      return;
    }
    try {
      const selected = gcpItems
        .filter((_, i) => selectedRowsGcp.has(i))
        .map(item => ({
          ...item,
          section: bulkSection || item.section || null,
          ...canonicalContactGroupFields(bulkContactGroupIds),
        }));
      if (!workspaceId) {
        onError && onError('Please select a workspace first.');
        return;
      }

      await integrationAPI.import({
        workspaceId,
        items: selected,
        filterRules: sanitizeFilterRules(filterRules),
        defaults: contactGroupFieldsForImportDefaults(bulkContactGroupIds),
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

  const getCredentials = () => ({
    credentials: { projectId: gcpProjectId, accessToken: gcpAccessToken },
    scanParams: {
      projectId: gcpProjectId,
      include: { secrets: scanSecrets, certificates: scanCertificates },
      filterRules: sanitizeFilterRules(filterRules),
    },
  });
  const { beginScanVerification, completeScanVerification, isScanCurrent } =
    useScanVerification({
      identity: {
        workspaceId,
        scanContext,
        payload: getCredentials(),
        filterRules,
      },
      provider: 'gcp',
      onScanSuccess,
      onScanInvalidated: () => {
        setPreviewReady(false);
        setIsScanning(false);
        setGcpItems([]);
        setGcpSummary([]);
        setFilterSummary(null);
        setSelectedRowsGcp(new Set());
        setGcpDuplicates(new Set());
        setLastScanId(null);
        onScanInvalidated?.();
      },
    });

  React.useImperativeHandle(ref, () => ({
    importSelected: importGcpSelected,
    getSelectedCount: () => (previewReady ? selectedRowsGcp.size : 0),
    getCredentials,
  }));

  return (
    <VStack align='stretch' spacing={3} minW={0} maxW='100%'>
      <Box>
        <Text fontSize='sm' color={helpTextColor}>
          <strong>Scope:</strong> Scans GCP Secret Manager and SSL certificates.{' '}
          <br />
          <strong>Access:</strong> Grant Secret Manager Viewer on the project.
          For certificate scans, also grant Certificate Manager Viewer and
          Compute Viewer. Secret Accessor cannot list secrets. <br />
          <strong>Credentials:</strong> Token is used for scanning and stored
          encrypted if auto-sync is enabled.
        </Text>
        <Text fontSize='xs' color={helpTextColor} mt={1}>
          Get token from Cloud Shell:{' '}
          <Code fontSize='xs'>gcloud auth print-access-token</Code>. That token
          belongs to the account you are logged in as. Roles on a service
          account apply only if you impersonate it (
          <Code fontSize='xs'>
            gcloud auth print-access-token
            --impersonate-service-account=SA_EMAIL
          </Code>
          ).
        </Text>
        {hideDocs ? null : (
          <LearnMorePanel
            variant='compact'
            mt={2}
            links={[{ label: 'Importing from GCP', url: IMPORT_DOCS.gcp }]}
          />
        )}
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
              placeholder={
                autoSyncTokenPlaceholder || 'gcloud auth print-access-token'
              }
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
        <Button
          colorScheme='blue'
          onClick={doGcpScan}
          isLoading={isScanning}
          isDisabled={!scanSecrets && !scanCertificates}
        >
          Scan
        </Button>
      </HStack>
      {errorContent}
      <Box border='1px solid' borderColor={borderColor} borderRadius='md' p={3}>
        <VStack align='stretch' spacing={2}>
          <Checkbox
            isChecked={scanSecrets}
            onChange={e => setScanSecrets(e.target.checked)}
            size='sm'
          >
            Secrets
          </Checkbox>
          <Checkbox
            isChecked={scanCertificates}
            onChange={e => setScanCertificates(e.target.checked)}
            size='sm'
          >
            Certificates
          </Checkbox>
          <FilterRulesEditor
            rules={filterRules}
            onChange={setFilterRules}
            borderColor={borderColor}
            helpTextColor={helpTextColor}
          />
          <FilterRulesSummary summary={filterSummary} />
          <Checkbox
            isChecked={cleanupObsolete}
            onChange={e => setCleanupObsolete(e.target.checked)}
            size='sm'
            colorScheme='red'
            isDisabled={!lastScanId}
          >
            Remove previously imported items no longer found at the source
          </Checkbox>
          {!lastScanId ? (
            <Text fontSize='xs' color={helpTextColor} pl={6}>
              Run a scan first; cleanup is driven by the backend's record of
              what that scan covered.
            </Text>
          ) : gcpSummary.some(s => s.complete === false) ? (
            <Text
              fontSize='sm'
              color='orange.400'
              pl={6}
              role='alert'
              p={3}
              borderWidth='1px'
              borderRadius='md'
              _light={{ color: 'orange.800', bg: 'orange.50' }}
              _dark={{ color: 'orange.100', bg: 'orange.900' }}
            >
              <strong>Incomplete scan:</strong> This scan is incomplete. See
              errors below. Cleanup is blocked for incomplete or truncated
              scans.
            </Text>
          ) : gcpSummary.some(s => s.failedCount > 0) ? (
            <Text fontSize='xs' color='orange.400' pl={6}>
              Some listed secrets have no expiration because their version
              lookup failed. Cleanup still runs against the listed set.
            </Text>
          ) : null}
          {cleanupObsolete ? (
            <Text
              fontSize='sm'
              color='red.400'
              pl={6}
              role='alert'
              p={3}
              borderWidth='1px'
              borderRadius='md'
              _light={{ color: 'red.800', bg: 'red.50' }}
              _dark={{ color: 'red.100', bg: 'red.900' }}
            >
              <strong>Permanent deletion:</strong> Permanently deletes
              previously imported items from this GCP project that are missing
              from the scan, regardless of selections below. This cannot be
              undone.
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
          minW={0}
          maxW='100%'
        >
          <VStack align='stretch' spacing={2} minW={0} maxW='100%'>
            {gcpSummary.map((s, i) => (
              <Box key={i} minW={0} maxW='100%'>
                <HStack
                  justify='space-between'
                  align='flex-start'
                  spacing={3}
                  minW={0}
                >
                  <Text fontSize='sm' minW={0}>
                    {gcpSummaryLabel(s.type)}
                  </Text>
                  {s.error ? (
                    <Badge colorScheme='red' flexShrink={0}>
                      Failed
                    </Badge>
                  ) : (
                    <HStack spacing={2} flexShrink={0}>
                      <Badge colorScheme='green'>found {s.found}</Badge>
                      {s.failedCount > 0 ? (
                        <Badge colorScheme='orange'>
                          {s.failedCount} without expiration
                        </Badge>
                      ) : null}
                    </HStack>
                  )}
                </HStack>
                {s.error ? (
                  <Text
                    fontSize='xs'
                    color={helpTextColor}
                    mt={1}
                    whiteSpace='normal'
                    overflowWrap='anywhere'
                    wordBreak='break-word'
                  >
                    {gcpSummaryErrorText(s)}
                  </Text>
                ) : null}
              </Box>
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
            contactGroupIds={bulkContactGroupIds}
            onContactGroupChange={setBulkContactGroupIds}
            contactGroups={contactGroups}
            borderColor={borderColor}
          />
        </>
      )}
    </VStack>
  );
});

export default ImportGCPForm;
