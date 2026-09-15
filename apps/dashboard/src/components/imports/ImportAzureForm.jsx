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
  Link as ChakraLink,
} from '@chakra-ui/react';
import { azureAPI, integrationAPI } from '../../utils/apiClient';
import { logger } from '../../utils/logger';
import { IMPORT_DOCS } from '../../utils/docsUrls';
import IntegrationImportTable from '../IntegrationImportTable';
import BulkIntegrationAssignment from '../BulkIntegrationAssignment';
import {
  canonicalContactGroupFields,
  contactGroupFieldsForImportDefaults,
} from '../../utils/contactGroupAssignment.js';
import AzureInventoryAuthFields from './AzureInventoryAuthFields';
import {
  azureInventoryScanAuthPayload,
  azureReplacementAuthError,
  azureVaultUrlLocked,
  buildAzureInventoryCredentials,
  validateAzureInventoryAuth,
} from './azureInventoryAuth';

function getAzureItemDetails(item) {
  const details = [];
  if (item.issuer) {
    details.push({ label: 'Issuer', value: item.issuer });
  }
  if (item.subject) {
    details.push({ label: 'Subject', value: item.subject, maxLines: 2 });
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

const ImportAzureForm = React.forwardRef(function ImportAzureForm(
  {
    workspaceId,
    onImportComplete,
    onError,
    onScanSuccess,
    borderColor,
    helpTextColor,
    autoSyncTokenPlaceholder,
    autoSyncManageMode = false,
    initialVaultUrl = '',
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
  const [azureVaultUrl, setAzureVaultUrl] = React.useState(() =>
    String(initialVaultUrl || '').trim()
  );
  const [persistedAzureVaultUrl, setPersistedAzureVaultUrl] = React.useState(
    () => String(initialVaultUrl || '').trim()
  );
  const [azureAuthMethod, setAzureAuthMethod] = React.useState('token');
  const [azureToken, setAzureToken] = React.useState('');
  const [azureTenantId, setAzureTenantId] = React.useState('');
  const [azureClientId, setAzureClientId] = React.useState('');
  const [azureClientSecret, setAzureClientSecret] = React.useState('');
  const [replacingCredentials, setReplacingCredentials] = React.useState(false);
  const [azureItems, setAzureItems] = React.useState([]);
  const [azureSummary, setAzureSummary] = React.useState([]);
  const [selectedRowsAzure, setSelectedRowsAzure] = React.useState(new Set());
  const [azureDuplicates, setAzureDuplicates] = React.useState(new Set());
  const [isScanning, setIsScanning] = React.useState(false);
  const [showSecret, setShowSecret] = React.useState(false);
  const [bulkSection, setBulkSection] = React.useState('');
  const [bulkContactGroupIds, setBulkContactGroupIds] = React.useState([]);
  const [cleanupObsolete, setCleanupObsolete] = React.useState(false);
  // The backend-authoritative scan record cleanup is driven from.
  const [lastScanId, setLastScanId] = React.useState(null);

  React.useEffect(() => {
    onSelectionChange && onSelectionChange(selectedRowsAzure.size);
  }, [selectedRowsAzure.size, onSelectionChange]);

  React.useEffect(() => {
    const next = String(initialVaultUrl || '').trim();
    if (!next) return;
    setPersistedAzureVaultUrl(next);
    setAzureVaultUrl(current =>
      azureVaultUrlLocked(autoSyncManageMode, replacingCredentials)
        ? next
        : current || next
    );
  }, [initialVaultUrl, autoSyncManageMode, replacingCredentials]);

  const doAzureScan = async () => {
    if (!workspaceId) {
      onError && onError('Please select a workspace first.');
      return;
    }
    const authError = validateAzureInventoryAuth({
      authMethod: azureAuthMethod,
      token: azureToken,
      tenantId: azureTenantId,
      clientId: azureClientId,
      clientSecret: azureClientSecret,
      requireVaultUrl: true,
      vaultUrl: azureVaultUrl,
    });
    if (authError) {
      onError && onError(authError);
      return;
    }

    onError && onError(null);
    setIsScanning(true);
    setAzureItems([]);
    setAzureSummary([]);
    try {
      const credentials = buildAzureInventoryCredentials({
        vaultUrl: azureVaultUrl,
        authMethod: azureAuthMethod,
        token: azureToken,
        tenantId: azureTenantId,
        clientId: azureClientId,
        clientSecret: azureClientSecret,
      });
      const res = await azureAPI.scan({
        workspaceId,
        vaultUrl: azureVaultUrl,
        maxItems: 2000,
        ...azureInventoryScanAuthPayload(credentials),
      });
      const items = Array.isArray(res?.items) ? res.items : [];
      setAzureItems(items);
      setAzureSummary(Array.isArray(res?.summary) ? res.summary : []);
      setLastScanId(res?.scan_id || null);
      if (items.length > 0) {
        onScanSuccess && onScanSuccess('azure');
      }

      if (updateQuotaFromResponse && !updateQuotaFromResponse(res)) {
        if (refreshIntegrationQuota) await refreshIntegrationQuota();
      }

      const dups = await checkDuplicatesForItems(items, workspaceId);
      setAzureDuplicates(dups);
    } catch (e) {
      setAzureItems([]);
      setAzureSummary([]);
      setLastScanId(null);
      if (isQuotaExceededError && isQuotaExceededError(e)) {
        onError && onError(formatQuotaError ? formatQuotaError(e) : e?.message);
      } else {
        onError && onError(e?.message || 'Azure scan failed');
      }
      if (extractQuotaFromError && !extractQuotaFromError(e)) {
        if (refreshIntegrationQuota) await refreshIntegrationQuota();
      }
    } finally {
      setIsScanning(false);
    }
  };

  const updateAzureItem = (index, updates) => {
    setAzureItems(prev => {
      const updated = [...prev];
      updated[index] = { ...updated[index], ...updates };
      return updated;
    });
  };

  const importAzureSelected = async () => {
    try {
      const selected = azureItems
        .filter((_, i) => selectedRowsAzure.has(i))
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
        defaults: contactGroupFieldsForImportDefaults(bulkContactGroupIds),
        // scan_id is sent whenever this import followed a scan, regardless
        // of whether cleanup is enabled -- provenance attribution must not
        // depend on the cleanup toggle (see apiClient.js).
        scanId: lastScanId || undefined,
        cleanup:
          cleanupObsolete && lastScanId
            ? {
                enabled: true,
                provider: 'azure',
                scanId: lastScanId,
              }
            : undefined,
      });
      onImportComplete && onImportComplete(selected);
    } catch (e) {
      onError && onError(e?.message || 'Azure import failed');
    }
  };

  const clearAzureAuthFields = () => {
    setAzureToken('');
    setAzureTenantId('');
    setAzureClientId('');
    setAzureClientSecret('');
    setAzureAuthMethod('token');
  };

  React.useImperativeHandle(ref, () => ({
    importSelected: importAzureSelected,
    getSelectedCount: () => selectedRowsAzure.size,
    validateReplacement: () =>
      azureReplacementAuthError({
        replacing: replacingCredentials,
        requireVaultUrl: true,
        vaultUrl: azureVaultUrl,
        authMethod: azureAuthMethod,
        token: azureToken,
        tenantId: azureTenantId,
        clientId: azureClientId,
        clientSecret: azureClientSecret,
      }),
    resetReplacement: () => {
      setReplacingCredentials(false);
      setPersistedAzureVaultUrl(azureVaultUrl);
      clearAzureAuthFields();
    },
    getCredentials: () => {
      const scanParams = {
        vaultUrl: azureVaultUrl,
        include: { secrets: true, certificates: true, keys: true },
      };
      if (autoSyncManageMode && !replacingCredentials) {
        return { credentials: {}, scanParams };
      }
      const credentials = buildAzureInventoryCredentials({
        vaultUrl: azureVaultUrl,
        authMethod: azureAuthMethod,
        token: azureToken,
        tenantId: azureTenantId,
        clientId: azureClientId,
        clientSecret: azureClientSecret,
      });
      return { credentials, scanParams };
    },
  }));

  return (
    <VStack align='stretch' spacing={3}>
      {!autoSyncManageMode ? (
        <Box>
          <Text fontSize='sm' color={helpTextColor}>
            Scans Azure Key Vault for secrets, certificates, and keys. Inventory
            uses list metadata only, so Key Vault Reader is enough. Pasted
            tokens and Entra app client credentials are stored encrypted if
            auto-sync is enabled.
          </Text>
          <Text fontSize='sm' mt={1}>
            <ChakraLink
              href={IMPORT_DOCS.azureKeyVault}
              color='blue.500'
              textDecoration='underline'
              isExternal
            >
              Learn more about importing from Azure Key Vault →
            </ChakraLink>
          </Text>
        </Box>
      ) : null}
      <HStack spacing={3} align='flex-end' flexWrap='wrap'>
        <Box minW='320px'>
          <Text fontSize='sm' mb={1}>
            Key Vault URL
          </Text>
          <Input
            placeholder='https://my-vault.vault.azure.net'
            value={azureVaultUrl}
            onChange={e => setAzureVaultUrl(e.target.value)}
            isDisabled={azureVaultUrlLocked(
              autoSyncManageMode,
              replacingCredentials
            )}
          />
        </Box>
        {!autoSyncManageMode ? (
          <Button
            colorScheme='blue'
            onClick={doAzureScan}
            isLoading={isScanning}
          >
            Scan
          </Button>
        ) : null}
      </HStack>
      <AzureInventoryAuthFields
        audienceHint={{
          prefix: 'Get a vault token from Azure CLI:',
          command:
            'az account get-access-token --resource https://vault.azure.net',
        }}
        tokenPlaceholder={autoSyncTokenPlaceholder || 'Paste token'}
        helpTextColor={helpTextColor}
        authMethod={azureAuthMethod}
        onAuthMethodChange={setAzureAuthMethod}
        token={azureToken}
        onTokenChange={setAzureToken}
        tenantId={azureTenantId}
        onTenantIdChange={setAzureTenantId}
        clientId={azureClientId}
        onClientIdChange={setAzureClientId}
        clientSecret={azureClientSecret}
        onClientSecretChange={setAzureClientSecret}
        showSecret={showSecret}
        onToggleSecret={() => setShowSecret(v => !v)}
        autoSyncManageMode={autoSyncManageMode}
        replacingCredentials={replacingCredentials}
        onStartReplace={() => setReplacingCredentials(true)}
        onCancelReplace={() => {
          setReplacingCredentials(false);
          setAzureVaultUrl(persistedAzureVaultUrl);
          clearAzureAuthFields();
        }}
      />
      <Box border='1px solid' borderColor={borderColor} borderRadius='md' p={3}>
        <VStack align='stretch' spacing={2}>
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
          ) : azureSummary.some(s => s.complete === false) ? (
            <Text fontSize='xs' color='orange.400' pl={6}>
              The last scan didn't fully complete for every item type above (see
              the errors below). The backend will only clean up secrets,
              certificates, or keys it confirmed were fully scanned; nothing
              incomplete or errored is ever touched.
            </Text>
          ) : null}
          {cleanupObsolete ? (
            <Text fontSize='xs' color='red.400' pl={6}>
              Deletes previously imported secrets, certificates, and keys from
              this Key Vault that no longer appear anywhere in this scan's
              results, regardless of which items you select for import below.
              Item types this scan couldn't fully complete are never affected.
              This cannot be undone.
            </Text>
          ) : null}
        </VStack>
      </Box>
      {!autoSyncManageMode && azureSummary.length > 0 && (
        <Box
          border='1px solid'
          borderColor={borderColor}
          borderRadius='md'
          p={3}
        >
          <VStack align='stretch' spacing={2}>
            {azureSummary.map((s, i) => (
              <HStack key={i} justify='space-between'>
                <Text fontSize='sm'>{s.type}</Text>
                {s.error ? (
                  <Badge colorScheme='red'>{s.error}</Badge>
                ) : (
                  <Badge colorScheme='green'>found {s.found}</Badge>
                )}
              </HStack>
            ))}
          </VStack>
        </Box>
      )}
      {!autoSyncManageMode && azureItems.length > 0 && (
        <>
          <IntegrationImportTable
            items={azureItems}
            selectedRows={selectedRowsAzure}
            onToggleRow={i =>
              setSelectedRowsAzure(prev => {
                const n = new Set(prev);
                n.has(i) ? n.delete(i) : n.add(i);
                return n;
              })
            }
            onToggleAll={() => {
              if (selectedRowsAzure.size === azureItems.length) {
                setSelectedRowsAzure(new Set());
              } else {
                setSelectedRowsAzure(new Set(azureItems.map((_, i) => i)));
              }
            }}
            borderColor={borderColor}
            getDetailsForItem={getAzureItemDetails}
            onUpdateItem={updateAzureItem}
            duplicateIndices={azureDuplicates}
          />
          <BulkIntegrationAssignment
            selectedCount={selectedRowsAzure.size}
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

export default ImportAzureForm;
