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
  Checkbox,
  InputGroup,
  InputRightElement,
  IconButton,
  Link as ChakraLink,
} from '@chakra-ui/react';
import { FiEye, FiEyeOff } from 'react-icons/fi';
import { githubAPI, integrationAPI, formatDate } from '../../utils/apiClient';
import { logger } from '../../utils/logger';
import IntegrationImportTable from '../IntegrationImportTable';
import BulkIntegrationAssignment from '../BulkIntegrationAssignment';

function getGitHubItemDetails(item) {
  const details = [];
  if (item.repository) {
    details.push({ label: 'Repository', value: item.repository });
  } else {
    details.push({
      label: 'Level',
      value: 'User-level',
      badge: true,
      badgeColor: 'purple',
    });
  }
  if (item.scopes && item.scopes.length > 0) {
    const scopes = Array.isArray(item.scopes)
      ? item.scopes.join(', ')
      : item.scopes;
    details.push({ label: 'Scopes', value: scopes, maxLines: 2 });
  }
  if (item.last_used_at) {
    details.push({ label: 'Last Used', value: formatDate(item.last_used_at) });
  }
  if (item.created_at) {
    details.push({ label: 'Created', value: formatDate(item.created_at) });
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

const ImportGitHubForm = React.forwardRef(function ImportGitHubForm(
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

  const [githubBaseUrl, setGithubBaseUrl] = React.useState(() => {
    try {
      return (
        localStorage.getItem('tt_github_baseurl') || 'https://api.github.com'
      );
    } catch (_) {
      return 'https://api.github.com';
    }
  });
  const [githubToken, setGithubToken] = React.useState('');
  const [githubItems, setGithubItems] = React.useState([]);
  const [githubSummary, setGithubSummary] = React.useState([]);
  const [githubIncludeTokens, setGithubIncludeTokens] = React.useState(true);
  const [githubIncludeSSHKeys, setGithubIncludeSSHKeys] = React.useState(false);
  const [githubIncludeDeployKeys, setGithubIncludeDeployKeys] =
    React.useState(true);
  const [githubIncludeSecrets, setGithubIncludeSecrets] = React.useState(true);
  const [selectedRowsGithub, setSelectedRowsGithub] = React.useState(new Set());
  const [githubDuplicates, setGithubDuplicates] = React.useState(new Set());
  const [isScanning, setIsScanning] = React.useState(false);
  const [showSecret, setShowSecret] = React.useState(false);
  const [bulkSection, setBulkSection] = React.useState('');
  const [bulkContactGroupId, setBulkContactGroupId] = React.useState('');

  React.useEffect(() => {
    onSelectionChange && onSelectionChange(selectedRowsGithub.size);
  }, [selectedRowsGithub.size, onSelectionChange]);

  const doGithubScan = async () => {
    if (!workspaceId) {
      onError && onError('Please select a workspace first.');
      return;
    }
    if (!githubBaseUrl || !githubBaseUrl.trim()) {
      onError && onError('GitHub URL is required');
      return;
    }
    if (!githubToken || !githubToken.trim()) {
      onError && onError('GitHub token is required');
      return;
    }

    onError && onError(null);
    setIsScanning(true);
    setGithubItems([]);
    setGithubSummary([]);
    try {
      const res = await githubAPI.scan({
        workspaceId,
        baseUrl: githubBaseUrl,
        token: githubToken,
        maxItems: 2000,
        include: {
          tokens: githubIncludeTokens,
          sshKeys: githubIncludeSSHKeys,
          deployKeys: githubIncludeDeployKeys,
          secrets: githubIncludeSecrets,
        },
      });
      const items = Array.isArray(res?.items) ? res.items : [];
      setGithubItems(items);
      setGithubSummary(Array.isArray(res?.summary) ? res.summary : []);
      if (items.length > 0) {
        onScanSuccess && onScanSuccess('github');
      }
      try {
        localStorage.setItem('tt_github_baseurl', githubBaseUrl);
      } catch (_) {}

      if (updateQuotaFromResponse && !updateQuotaFromResponse(res)) {
        if (refreshIntegrationQuota) await refreshIntegrationQuota();
      }

      const dups = await checkDuplicatesForItems(items, workspaceId);
      setGithubDuplicates(dups);
    } catch (e) {
      setGithubItems([]);
      setGithubSummary([]);
      if (isQuotaExceededError && isQuotaExceededError(e)) {
        onError && onError(formatQuotaError ? formatQuotaError(e) : e?.message);
      } else {
        onError && onError(e?.message || 'GitHub scan failed');
      }
      if (extractQuotaFromError && !extractQuotaFromError(e)) {
        if (refreshIntegrationQuota) await refreshIntegrationQuota();
      }
    } finally {
      setIsScanning(false);
    }
  };

  const updateGithubItem = (index, updates) => {
    setGithubItems(prev => {
      const updated = [...prev];
      updated[index] = { ...updated[index], ...updates };
      return updated;
    });
  };

  const importGithubSelected = async () => {
    try {
      const selected = githubItems
        .filter((_, i) => selectedRowsGithub.has(i))
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
      onError && onError(e?.message || 'GitHub import failed');
    }
  };

  React.useImperativeHandle(ref, () => ({
    importSelected: importGithubSelected,
    getSelectedCount: () => selectedRowsGithub.size,
  }));

  return (
    <VStack align='stretch' spacing={3}>
      <Box>
        <Text fontSize='sm' color={helpTextColor}>
          Scans GitHub for tokens, secrets, SSH keys or deploy tokens. The
          read-only PAT is used for scanning and stored encrypted if auto-sync
          is enabled.
        </Text>
        <Text fontSize='sm' mt={1}>
          <ChakraLink
            onClick={() => navigate('/docs/tokens#import-github')}
            cursor='pointer'
            color='blue.500'
            textDecoration='underline'
            isExternal
          >
            Learn more about importing from GitHub →
          </ChakraLink>
        </Text>
      </Box>
      <HStack spacing={3} align='flex-end' flexWrap='wrap'>
        <Box minW='280px'>
          <Text fontSize='sm' mb={1}>
            GitHub URL (leave default for GitHub.com)
          </Text>
          <Input
            placeholder='https://api.github.com'
            value={githubBaseUrl}
            onChange={e => setGithubBaseUrl(e.target.value)}
          />
        </Box>
        <Box minW='320px'>
          <Text fontSize='sm' mb={1}>
            Personal Access Token (repo scope)
          </Text>
          <InputGroup>
            <Input
              type={showSecret ? 'text' : 'password'}
              placeholder={autoSyncTokenPlaceholder || 'Paste token'}
              value={githubToken}
              onChange={e => setGithubToken(e.target.value)}
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
          onClick={doGithubScan}
          isLoading={isScanning}
        >
          Scan
        </Button>
      </HStack>
      <Box border='1px solid' borderColor={borderColor} borderRadius='md' p={3}>
        <Text fontSize='sm' fontWeight='medium' mb={3}>
          Scan Filters
        </Text>
        <VStack align='stretch' spacing={2}>
          <Checkbox
            isChecked={githubIncludeTokens}
            onChange={e => setGithubIncludeTokens(e.target.checked)}
            size='sm'
          >
            Personal Access Tokens
          </Checkbox>
          <Checkbox
            isChecked={githubIncludeSSHKeys}
            onChange={e => setGithubIncludeSSHKeys(e.target.checked)}
            size='sm'
          >
            SSH Authentication Keys (user only)
          </Checkbox>
          <Checkbox
            isChecked={githubIncludeDeployKeys}
            onChange={e => setGithubIncludeDeployKeys(e.target.checked)}
            size='sm'
          >
            Deploy Keys (repository)
          </Checkbox>
          <Checkbox
            isChecked={githubIncludeSecrets}
            onChange={e => setGithubIncludeSecrets(e.target.checked)}
            size='sm'
          >
            Repository Secrets
          </Checkbox>
        </VStack>
      </Box>
      {githubSummary.length > 0 && (
        <Box
          border='1px solid'
          borderColor={borderColor}
          borderRadius='md'
          p={3}
        >
          <VStack align='stretch' spacing={2}>
            {githubSummary.map((s, i) => (
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
      {githubItems.length > 0 && (
        <>
          <IntegrationImportTable
            items={githubItems}
            selectedRows={selectedRowsGithub}
            onToggleRow={i =>
              setSelectedRowsGithub(prev => {
                const n = new Set(prev);
                n.has(i) ? n.delete(i) : n.add(i);
                return n;
              })
            }
            onToggleAll={() => {
              if (selectedRowsGithub.size === githubItems.length) {
                setSelectedRowsGithub(new Set());
              } else {
                setSelectedRowsGithub(new Set(githubItems.map((_, i) => i)));
              }
            }}
            borderColor={borderColor}
            getDetailsForItem={getGitHubItemDetails}
            onUpdateItem={updateGithubItem}
            duplicateIndices={githubDuplicates}
          />
          <BulkIntegrationAssignment
            selectedCount={selectedRowsGithub.size}
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

export default ImportGitHubForm;
