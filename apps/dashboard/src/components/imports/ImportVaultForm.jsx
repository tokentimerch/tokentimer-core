import React from 'react';
import {
  Box,
  VStack,
  HStack,
  Text,
  Input,
  Switch,
  Checkbox,
  Button,
  Badge,
  Accordion,
  AccordionItem,
  AccordionButton,
  AccordionPanel,
  AccordionIcon,
  InputGroup,
  InputRightElement,
  IconButton,
  Tooltip,
  Link as ChakraLink,
  Spinner,
} from '@chakra-ui/react';
import { FiEye, FiEyeOff, FiHelpCircle, FiRefreshCw } from 'react-icons/fi';
import { vaultAPI, integrationAPI } from '../../utils/apiClient';
import { logger } from '../../utils/logger';
import IntegrationImportTable from '../IntegrationImportTable';
import BulkIntegrationAssignment from '../BulkIntegrationAssignment';
import FilterRulesEditor, { sanitizeFilterRules } from '../FilterRulesEditor';

const VAULT_CATEGORY_OPTIONS = [
  { value: 'cert', label: 'Certificates' },
  { value: 'key_secret', label: 'Secrets & keys' },
];

function getVaultItemDetails(item) {
  const details = [];
  if (item.mount || item.path) {
    details.push({
      label: 'Path',
      value: `${item.mount || ''}${item.path || ''}`,
    });
  }
  if (item.issuer) {
    details.push({ label: 'Issuer', value: item.issuer });
  }
  if (item.subject) {
    details.push({ label: 'Subject', value: item.subject, maxLines: 2 });
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

const ImportVaultForm = React.forwardRef(function ImportVaultForm(
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
  const maxItemsPerMount = 1000;

  // Vault integration state
  const [vaultAddress, setVaultAddress] = React.useState(() => {
    try {
      return localStorage.getItem('tt_vault_address') || '';
    } catch (_) {
      return '';
    }
  });
  const [vaultToken, setVaultToken] = React.useState('');
  const [includeKV, setIncludeKV] = React.useState(() => {
    try {
      return (localStorage.getItem('tt_vault_include_kv') || 'true') === 'true';
    } catch (_) {
      return true;
    }
  });
  const [includePKI, setIncludePKI] = React.useState(() => {
    try {
      return (
        (localStorage.getItem('tt_vault_include_pki') || 'true') === 'true'
      );
    } catch (_) {
      return true;
    }
  });
  const [pathPrefix, setPathPrefix] = React.useState(() => {
    try {
      return localStorage.getItem('tt_vault_path_prefix') || '';
    } catch (_) {
      return '';
    }
  });

  // Secrets-engine (mount) picker. Empty `availableMounts` means the picker
  // hasn't been engaged yet, so scans keep scanning every mount (unchanged
  // default behavior) until the user explicitly loads and narrows the list.
  const [availableMounts, setAvailableMounts] = React.useState([]);
  const [selectedMountPaths, setSelectedMountPaths] = React.useState(new Set());
  const [isLoadingMounts, setIsLoadingMounts] = React.useState(false);
  const [mountsError, setMountsError] = React.useState(null);

  // Asset-kind filter: all kinds Vault can produce are included by default.
  const [selectedCategories, setSelectedCategories] = React.useState(
    new Set(VAULT_CATEGORY_OPTIONS.map(c => c.value))
  );

  const [filterRules, setFilterRules] = React.useState([]);
  const [filterSummary, setFilterSummary] = React.useState(null);

  const [isScanning, setIsScanning] = React.useState(false);
  const [vaultItems, setVaultItems] = React.useState([]);
  const [summary, setSummary] = React.useState([]);
  const [vaultDefaults, _setVaultDefaults] = React.useState({
    category: 'general',
    type: 'other',
  });
  const [selectedRowsVault, setSelectedRowsVault] = React.useState(new Set());
  const [vaultDuplicates, setVaultDuplicates] = React.useState(new Set());
  const [showSecret, setShowSecret] = React.useState(false);

  // Shared bulk assignment state
  const [bulkSection, setBulkSection] = React.useState('');
  const [bulkContactGroupId, setBulkContactGroupId] = React.useState('');

  React.useEffect(() => {
    onSelectionChange && onSelectionChange(selectedRowsVault.size);
  }, [selectedRowsVault.size, onSelectionChange]);

  const loadMounts = async () => {
    if (!vaultAddress || !vaultAddress.trim()) {
      setMountsError('Vault address is required');
      return;
    }
    if (!vaultToken || !vaultToken.trim()) {
      setMountsError('Vault token is required');
      return;
    }
    setIsLoadingMounts(true);
    setMountsError(null);
    try {
      const mounts = await vaultAPI.listMounts({
        workspaceId,
        address: vaultAddress,
        token: vaultToken,
      });
      const scannable = mounts.filter(m => m.type === 'kv' || m.type === 'pki');
      setAvailableMounts(scannable);
      setSelectedMountPaths(new Set(scannable.map(m => m.path)));
    } catch (e) {
      setAvailableMounts([]);
      setMountsError(e?.message || 'Failed to load secrets engines');
    } finally {
      setIsLoadingMounts(false);
    }
  };

  const toggleMount = path => {
    setSelectedMountPaths(prev => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  };

  const toggleCategory = value => {
    setSelectedCategories(prev => {
      const next = new Set(prev);
      if (next.has(value)) next.delete(value);
      else next.add(value);
      return next;
    });
  };

  // Only send an explicit mount list when the picker was used and the user
  // narrowed it down; otherwise every mount is scanned (unchanged default).
  const mountsFilterForScan = () => {
    if (availableMounts.length === 0) return null;
    if (selectedMountPaths.size >= availableMounts.length) return null;
    return Array.from(selectedMountPaths);
  };

  const doVaultScan = async () => {
    if (!workspaceId) {
      onError && onError('Please select a workspace first.');
      return;
    }

    if (!vaultAddress || !vaultAddress.trim()) {
      onError && onError('Vault address is required');
      return;
    }
    if (!vaultToken || !vaultToken.trim()) {
      onError && onError('Vault token is required');
      return;
    }
    if (availableMounts.length > 0 && selectedMountPaths.size === 0) {
      onError && onError('Select at least one secrets engine to scan.');
      return;
    }
    if (selectedCategories.size === 0) {
      onError && onError('Select at least one asset kind to scan.');
      return;
    }

    onError && onError(null);
    setIsScanning(true);
    setVaultItems([]);
    setSummary([]);
    setFilterSummary(null);
    try {
      const res = await vaultAPI.scan({
        workspaceId,
        address: vaultAddress,
        token: vaultToken,
        include: { kv: includeKV, pki: includePKI },
        mounts: mountsFilterForScan(),
        maxItemsPerMount,
        pathPrefix,
        categories: Array.from(selectedCategories),
        filterRules: sanitizeFilterRules(filterRules),
      });
      const items = Array.isArray(res?.items) ? res.items : [];
      setVaultItems(items);
      setSummary(Array.isArray(res?.summary) ? res.summary : []);
      setFilterSummary(res?.filterSummary || null);
      if (items.length > 0) {
        onScanSuccess && onScanSuccess('vault');
      }

      if (updateQuotaFromResponse && !updateQuotaFromResponse(res)) {
        if (refreshIntegrationQuota) await refreshIntegrationQuota();
      }

      const dups = await checkDuplicatesForItems(items, workspaceId);
      setVaultDuplicates(dups);
    } catch (e) {
      setVaultItems([]);
      setSummary([]);
      if (isQuotaExceededError && isQuotaExceededError(e)) {
        onError && onError(formatQuotaError ? formatQuotaError(e) : e?.message);
      } else {
        onError && onError(e?.message || 'Vault scan failed');
      }
      if (extractQuotaFromError && !extractQuotaFromError(e)) {
        if (refreshIntegrationQuota) await refreshIntegrationQuota();
      }
    } finally {
      setIsScanning(false);
    }
  };

  const toggleVaultRow = idx => {
    setSelectedRowsVault(prev => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  const updateVaultItem = (index, updates) => {
    setVaultItems(prev => {
      const updated = [...prev];
      updated[index] = { ...updated[index], ...updates };
      return updated;
    });
  };

  const importVaultSelected = async () => {
    try {
      const selected = vaultItems
        .filter((_, i) => selectedRowsVault.has(i))
        .map(item => ({
          ...item,
          section: bulkSection || item.section || null,
          contact_group_id: bulkContactGroupId || null,
        }));
      if (!workspaceId) {
        onError && onError('Please select a workspace first.');
        return;
      }
      await vaultAPI.import({
        workspaceId,
        items: selected,
        defaults: vaultDefaults,
      });
      onImportComplete && onImportComplete(selected);
    } catch (e) {
      onError && onError(e?.message || 'Vault import failed');
    }
  };

  React.useImperativeHandle(ref, () => ({
    importSelected: importVaultSelected,
    getSelectedCount: () => selectedRowsVault.size,
    getCredentials: () => ({
      credentials: { address: vaultAddress, token: vaultToken },
      scanParams: {
        address: vaultAddress,
        include: { kv: includeKV, pki: includePKI },
        pathPrefix: pathPrefix || '',
        maxItemsPerMount,
        mounts: mountsFilterForScan(),
        categories: Array.from(selectedCategories),
        filterRules: sanitizeFilterRules(filterRules),
      },
    }),
  }));

  return (
    <VStack align='stretch' spacing={3}>
      <Box>
        <Text fontSize='sm' color={helpTextColor}>
          Scans KV v2 and PKI engines to extract expirations. Base64
          certificates are decoded to read expiry. Token is used for scanning
          and stored encrypted if auto-sync is enabled. The Vault host must have
          a valid TLS certificate for the import to work.
        </Text>
        <Text fontSize='sm' mt={1}>
          <ChakraLink
            onClick={() =>
              window.open(
                'https://tokentimer.ch/docs/tokens#import-hashicorp',
                '_blank',
                'noopener,noreferrer'
              )
            }
            cursor='pointer'
            color='blue.500'
            textDecoration='underline'
            isExternal
          >
            Learn more about importing from HashiCorp Vault →
          </ChakraLink>
        </Text>
      </Box>
      <VStack align='stretch' spacing={3}>
        <HStack spacing={3} align='flex-end' flexWrap='wrap'>
          <Box minW='280px'>
            <Text fontSize='sm' mb={1}>
              Vault Address
            </Text>
            <Input
              placeholder='https://vault.your-org.com'
              value={vaultAddress}
              onChange={e => {
                setVaultAddress(e.target.value);
                try {
                  localStorage.setItem('tt_vault_address', e.target.value);
                } catch (_) {}
              }}
            />
          </Box>
          <Box minW='320px'>
            <Text fontSize='sm' mb={1}>
              Token
            </Text>
            <InputGroup>
              <Input
                type={showSecret ? 'text' : 'password'}
                placeholder={autoSyncTokenPlaceholder || 'Paste Vault token'}
                value={vaultToken}
                onChange={e => setVaultToken(e.target.value)}
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
        </HStack>

        <HStack spacing={4} flexWrap='wrap'>
          <HStack>
            <Text fontSize='sm'>Scan KV v2</Text>
            <Tooltip
              label='Scan KV v2 secrets recursively to detect expirations and PEM/base64 certificates.'
              fontSize='xs'
            >
              <IconButton
                aria-label='KV help'
                icon={<FiHelpCircle />}
                size='xs'
                variant='ghost'
              />
            </Tooltip>
            <Switch
              isChecked={includeKV}
              onChange={e => {
                setIncludeKV(e.target.checked);
                try {
                  localStorage.setItem(
                    'tt_vault_include_kv',
                    String(e.target.checked)
                  );
                } catch (_) {}
              }}
              colorScheme='blue'
            />
          </HStack>
          <HStack>
            <Text fontSize='sm'>Scan PKI</Text>
            <Tooltip
              label='Scan Vault PKI to list certificates and extract expiration dates.'
              fontSize='xs'
            >
              <IconButton
                aria-label='PKI help'
                icon={<FiHelpCircle />}
                size='xs'
                variant='ghost'
              />
            </Tooltip>
            <Switch
              isChecked={includePKI}
              onChange={e => {
                setIncludePKI(e.target.checked);
                try {
                  localStorage.setItem(
                    'tt_vault_include_pki',
                    String(e.target.checked)
                  );
                } catch (_) {}
              }}
              colorScheme='blue'
            />
          </HStack>
          <Button
            colorScheme='blue'
            onClick={doVaultScan}
            isLoading={isScanning}
            isDisabled={!vaultAddress || !vaultToken}
          >
            Scan
          </Button>
        </HStack>

        <Box>
          <Text fontSize='sm' mb={1}>
            Asset kinds to scan
          </Text>
          <HStack spacing={4} flexWrap='wrap'>
            {VAULT_CATEGORY_OPTIONS.map(opt => (
              <Checkbox
                key={opt.value}
                size='sm'
                isChecked={selectedCategories.has(opt.value)}
                onChange={() => toggleCategory(opt.value)}
              >
                {opt.label}
              </Checkbox>
            ))}
          </HStack>
          <Text fontSize='xs' color={helpTextColor} mt={1}>
            All kinds are scanned by default. Uncheck a kind to skip it, e.g.
            uncheck Secrets &amp; keys to only import certificates.
          </Text>
        </Box>

        {/* Advanced options - collapsible */}
        <Accordion allowToggle>
          <AccordionItem border='none'>
            <AccordionButton px={0}>
              <Box flex='1' textAlign='left'>
                <Text fontSize='sm' color={helpTextColor}>
                  Advanced: Secrets engines and path filtering
                </Text>
              </Box>
              <AccordionIcon />
            </AccordionButton>
            <AccordionPanel pb={4} px={0}>
              <VStack align='stretch' spacing={4}>
                <Box>
                  <HStack justify='space-between' mb={1}>
                    <Text fontSize='sm'>Secrets engines (mounts)</Text>
                    <Button
                      size='xs'
                      variant='outline'
                      leftIcon={
                        isLoadingMounts ? (
                          <Spinner size='xs' />
                        ) : (
                          <FiRefreshCw />
                        )
                      }
                      onClick={loadMounts}
                      isDisabled={
                        isLoadingMounts || !vaultAddress || !vaultToken
                      }
                    >
                      {availableMounts.length > 0 ? 'Refresh' : 'Load engines'}
                    </Button>
                  </HStack>
                  {mountsError ? (
                    <Text fontSize='xs' color='red.400' mb={1}>
                      {mountsError}
                    </Text>
                  ) : null}
                  {availableMounts.length > 0 ? (
                    <Box
                      border='1px solid'
                      borderColor={borderColor}
                      borderRadius='md'
                      p={2}
                      maxH='180px'
                      overflowY='auto'
                    >
                      <VStack align='stretch' spacing={1}>
                        {availableMounts.map(m => {
                          const kvVersion =
                            m.type === 'kv'
                              ? String(m.options?.version || '1')
                              : null;
                          const unsupported = kvVersion === '1';
                          return (
                            <Checkbox
                              key={m.path}
                              size='sm'
                              isChecked={selectedMountPaths.has(m.path)}
                              onChange={() => toggleMount(m.path)}
                            >
                              {m.path} ({m.type}
                              {kvVersion ? ` v${kvVersion}` : ''})
                              {unsupported ? (
                                <Text
                                  as='span'
                                  fontSize='2xs'
                                  color='orange.400'
                                  ml={1}
                                >
                                  KV v1 not supported
                                </Text>
                              ) : null}
                            </Checkbox>
                          );
                        })}
                      </VStack>
                    </Box>
                  ) : (
                    <Text fontSize='xs' color={helpTextColor}>
                      All secrets engines are scanned by default. Load the list
                      to include or exclude specific ones (e.g. only the
                      &quot;staging&quot; KV engine).
                    </Text>
                  )}
                </Box>
                <Box>
                  <Text fontSize='sm' mb={1}>
                    Path prefix (KV only)
                  </Text>
                  <Input
                    placeholder='e.g., prod/api (optional)'
                    value={pathPrefix}
                    onChange={e => {
                      setPathPrefix(e.target.value);
                      try {
                        localStorage.setItem(
                          'tt_vault_path_prefix',
                          e.target.value
                        );
                      } catch (_) {}
                    }}
                    size='sm'
                  />
                  <Text fontSize='xs' color={helpTextColor} mt={1}>
                    Folder inside each KV engine (e.g., prod/api) or an exact
                    secret path. Leave empty to scan all. Do not include the
                    engine name itself, use the secrets engines picker above for
                    that.
                  </Text>
                </Box>
              </VStack>
            </AccordionPanel>
          </AccordionItem>
        </Accordion>

        <FilterRulesEditor
          rules={filterRules}
          onChange={setFilterRules}
          borderColor={borderColor}
          helpTextColor={helpTextColor}
        />
        {filterSummary ? (
          <HStack spacing={2}>
            <Badge colorScheme='green'>
              {filterSummary.matchedCount} matched
            </Badge>
            <Badge colorScheme='red'>
              {filterSummary.excludedCount} excluded by rules
            </Badge>
          </HStack>
        ) : null}
      </VStack>

      {summary.length > 0 ? (
        <Box
          border='1px solid'
          borderColor={borderColor}
          borderRadius='md'
          p={3}
        >
          <VStack align='stretch' spacing={2}>
            {summary.map((s, i) => (
              <HStack key={i} justify='space-between'>
                <Text fontSize='sm'>
                  {s.mount} ({s.type})
                </Text>
                {s.error ? (
                  <Badge colorScheme='red'>{s.error}</Badge>
                ) : (
                  <Badge colorScheme='green'>
                    found {s.found}
                    {s.truncated ? '+' : ''}
                  </Badge>
                )}
              </HStack>
            ))}
          </VStack>
        </Box>
      ) : null}

      {vaultItems.length > 0 ? (
        <>
          <IntegrationImportTable
            items={vaultItems}
            selectedRows={selectedRowsVault}
            onToggleRow={toggleVaultRow}
            onToggleAll={() => {
              if (selectedRowsVault.size === vaultItems.length) {
                setSelectedRowsVault(new Set());
              } else {
                setSelectedRowsVault(new Set(vaultItems.map((_, i) => i)));
              }
            }}
            borderColor={borderColor}
            getDetailsForItem={getVaultItemDetails}
            showCategory={true}
            onUpdateItem={updateVaultItem}
            categoryOptions={['cert', 'key_secret', 'license', 'general']}
            duplicateIndices={vaultDuplicates}
          />

          <BulkIntegrationAssignment
            selectedCount={selectedRowsVault.size}
            section={bulkSection}
            onSectionChange={setBulkSection}
            contactGroupId={bulkContactGroupId}
            onContactGroupChange={setBulkContactGroupId}
            contactGroups={contactGroups}
            borderColor={borderColor}
          />
        </>
      ) : null}
    </VStack>
  );
});

export default ImportVaultForm;
