import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  VStack,
  HStack,
  Text,
  Input,
  Button,
  Badge,
  InputGroup,
  InputRightElement,
  IconButton,
  Code,
  Link as ChakraLink,
} from '@chakra-ui/react';
import { FiEye, FiEyeOff } from 'react-icons/fi';
import { azureAPI, integrationAPI } from '../../utils/apiClient';
import { logger } from '../../utils/logger';
import IntegrationImportTable from '../IntegrationImportTable';
import BulkIntegrationAssignment from '../BulkIntegrationAssignment';

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
  const navigate = useNavigate();

  const [azureVaultUrl, setAzureVaultUrl] = React.useState('');
  const [azureToken, setAzureToken] = React.useState('');
  const [azureItems, setAzureItems] = React.useState([]);
  const [azureSummary, setAzureSummary] = React.useState([]);
  const [selectedRowsAzure, setSelectedRowsAzure] = React.useState(new Set());
  const [azureDuplicates, setAzureDuplicates] = React.useState(new Set());
  const [isScanning, setIsScanning] = React.useState(false);
  const [showSecret, setShowSecret] = React.useState(false);
  const [bulkSection, setBulkSection] = React.useState('');
  const [bulkContactGroupId, setBulkContactGroupId] = React.useState('');

  React.useEffect(() => {
    onSelectionChange && onSelectionChange(selectedRowsAzure.size);
  }, [selectedRowsAzure.size, onSelectionChange]);

  const doAzureScan = async () => {
    if (!workspaceId) {
      onError && onError('Please select a workspace first.');
      return;
    }
    if (!azureVaultUrl || !azureVaultUrl.trim()) {
      onError && onError('Azure Key Vault URL is required');
      return;
    }
    if (!azureToken || !azureToken.trim()) {
      onError && onError('Azure access token is required');
      return;
    }

    onError && onError(null);
    setIsScanning(true);
    setAzureItems([]);
    setAzureSummary([]);
    try {
      const res = await azureAPI.scan({
        workspaceId,
        vaultUrl: azureVaultUrl,
        token: azureToken,
        maxItems: 2000,
      });
      const items = Array.isArray(res?.items) ? res.items : [];
      setAzureItems(items);
      setAzureSummary(Array.isArray(res?.summary) ? res.summary : []);
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
      });
      onImportComplete && onImportComplete(selected);
    } catch (e) {
      onError && onError(e?.message || 'Azure import failed');
    }
  };

  React.useImperativeHandle(ref, () => ({
    importSelected: importAzureSelected,
    getSelectedCount: () => selectedRowsAzure.size,
  }));

  return (
    <VStack align='stretch' spacing={3}>
      <Box>
        <Text fontSize='sm' color={helpTextColor}>
          Scans Azure Key Vault for secrets, certificates, and keys. Token is
          used for scanning and stored encrypted if auto-sync is enabled.
        </Text>
        <Text fontSize='xs' color={helpTextColor} mt={1}>
          Get token from Azure CLI:{' '}
          <Code fontSize='xs'>
            az account get-access-token --resource https://vault.azure.net
          </Code>
        </Text>
        <Text fontSize='sm' mt={1}>
          <ChakraLink
            onClick={() => navigate('/docs/tokens#import-azure')}
            cursor='pointer'
            color='blue.500'
            textDecoration='underline'
            isExternal
          >
            Learn more about importing from Azure Key Vault →
          </ChakraLink>
        </Text>
      </Box>
      <HStack spacing={3} align='flex-end' flexWrap='wrap'>
        <Box minW='320px'>
          <Text fontSize='sm' mb={1}>
            Key Vault URL
          </Text>
          <Input
            placeholder='https://my-vault.vault.azure.net'
            value={azureVaultUrl}
            onChange={e => setAzureVaultUrl(e.target.value)}
          />
        </Box>
        <Box minW='320px'>
          <Text fontSize='sm' mb={1}>
            Access Token
          </Text>
          <InputGroup>
            <Input
              type={showSecret ? 'text' : 'password'}
              placeholder={autoSyncTokenPlaceholder || 'Paste token'}
              value={azureToken}
              onChange={e => setAzureToken(e.target.value)}
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
        <Button colorScheme='blue' onClick={doAzureScan} isLoading={isScanning}>
          Scan
        </Button>
      </HStack>
      {azureSummary.length > 0 && (
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
      {azureItems.length > 0 && (
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

export default ImportAzureForm;
