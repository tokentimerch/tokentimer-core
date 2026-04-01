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
import { gitlabAPI, integrationAPI, formatDate } from '../../utils/apiClient';
import { logger } from '../../utils/logger';
import IntegrationImportTable from '../IntegrationImportTable';
import BulkIntegrationAssignment from '../BulkIntegrationAssignment';

function getGitLabItemDetails(item) {
  const details = [];
  if (item.project_name) {
    details.push({ label: 'Project', value: item.project_name });
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

const ImportGitLabForm = React.forwardRef(function ImportGitLabForm(
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

  const [gitlabBaseUrl, setGitlabBaseUrl] = React.useState(() => {
    try {
      return localStorage.getItem('tt_gitlab_baseurl') || 'https://gitlab.com';
    } catch (_) {
      return 'https://gitlab.com';
    }
  });
  const [gitlabToken, setGitlabToken] = React.useState('');
  const [gitlabItems, setGitlabItems] = React.useState([]);
  const [gitlabSummary, setGitlabSummary] = React.useState([]);
  const [gitlabIncludePATs, setGitlabIncludePATs] = React.useState(true);
  const [gitlabIncludeProjectTokens, setGitlabIncludeProjectTokens] =
    React.useState(true);
  const [gitlabIncludeGroupTokens, setGitlabIncludeGroupTokens] =
    React.useState(true);
  const [gitlabIncludeDeployTokens, setGitlabIncludeDeployTokens] =
    React.useState(true);
  const [gitlabIncludeSSHKeys, setGitlabIncludeSSHKeys] = React.useState(false);
  const [gitlabExcludeUserPATs, setGitlabExcludeUserPATs] =
    React.useState(true);
  const [gitlabIncludeExpired, setGitlabIncludeExpired] = React.useState(false);
  const [gitlabIncludeRevoked, setGitlabIncludeRevoked] = React.useState(false);
  const [selectedRowsGitlab, setSelectedRowsGitlab] = React.useState(new Set());
  const [gitlabDuplicates, setGitlabDuplicates] = React.useState(new Set());
  const [isScanning, setIsScanning] = React.useState(false);
  const [showSecret, setShowSecret] = React.useState(false);
  const [bulkSection, setBulkSection] = React.useState('');
  const [bulkContactGroupId, setBulkContactGroupId] = React.useState('');

  React.useEffect(() => {
    onSelectionChange && onSelectionChange(selectedRowsGitlab.size);
  }, [selectedRowsGitlab.size, onSelectionChange]);

  const doGitlabScan = async () => {
    if (!workspaceId) {
      onError && onError('Please select a workspace first.');
      return;
    }

    if (!gitlabBaseUrl || !gitlabBaseUrl.trim()) {
      onError && onError('GitLab URL is required');
      return;
    }
    if (!gitlabToken || !gitlabToken.trim()) {
      onError && onError('GitLab token is required');
      return;
    }

    onError && onError(null);
    setIsScanning(true);
    setGitlabItems([]);
    setGitlabSummary([]);
    try {
      const res = await gitlabAPI.scan({
        workspaceId,
        baseUrl: gitlabBaseUrl,
        token: gitlabToken,
        maxItems: 2000,
        filters: {
          includePATs: gitlabIncludePATs,
          includeProjectTokens: gitlabIncludeProjectTokens,
          includeGroupTokens: gitlabIncludeGroupTokens,
          includeDeployTokens: gitlabIncludeDeployTokens,
          includeSSHKeys: gitlabIncludeSSHKeys,
          excludeUserPATs: gitlabExcludeUserPATs,
          includeExpired: gitlabIncludeExpired,
          includeRevoked: gitlabIncludeRevoked,
        },
      });
      const items = Array.isArray(res?.items) ? res.items : [];
      setGitlabItems(items);
      setGitlabSummary(Array.isArray(res?.summary) ? res.summary : []);
      if (items.length > 0) {
        onScanSuccess && onScanSuccess('gitlab');
      }
      try {
        localStorage.setItem('tt_gitlab_baseurl', gitlabBaseUrl);
      } catch (_) {}

      if (updateQuotaFromResponse && !updateQuotaFromResponse(res)) {
        if (refreshIntegrationQuota) await refreshIntegrationQuota();
      }

      const dups = await checkDuplicatesForItems(items, workspaceId);
      setGitlabDuplicates(dups);
    } catch (e) {
      setGitlabItems([]);
      setGitlabSummary([]);
      if (isQuotaExceededError && isQuotaExceededError(e)) {
        onError && onError(formatQuotaError ? formatQuotaError(e) : e?.message);
      } else {
        onError && onError(e?.message || 'GitLab scan failed');
      }
      if (extractQuotaFromError && !extractQuotaFromError(e)) {
        if (refreshIntegrationQuota) await refreshIntegrationQuota();
      }
    } finally {
      setIsScanning(false);
    }
  };

  const updateGitlabItem = (index, updates) => {
    setGitlabItems(prev => {
      const updated = [...prev];
      updated[index] = { ...updated[index], ...updates };
      return updated;
    });
  };

  const importGitlabSelected = async () => {
    try {
      const selected = gitlabItems
        .filter((_, i) => selectedRowsGitlab.has(i))
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
      onError && onError(e?.message || 'GitLab import failed');
    }
  };

  React.useImperativeHandle(ref, () => ({
    importSelected: importGitlabSelected,
    getSelectedCount: () => selectedRowsGitlab.size,
  }));

  return (
    <VStack align='stretch' spacing={3}>
      <Box>
        <Text fontSize='sm' color={helpTextColor}>
          Scans GitLab for Personal Access Tokens, Project Access Tokens, Deploy
          Tokens, and SSH Keys. Token is used for scanning and stored encrypted
          if auto-sync is enabled.
        </Text>
        <Text fontSize='sm' mt={1}>
          <ChakraLink
            onClick={() => navigate('/docs/tokens#import-gitlab')}
            cursor='pointer'
            color='blue.500'
            textDecoration='underline'
            isExternal
          >
            Learn more about importing from GitLab →
          </ChakraLink>
        </Text>
      </Box>
      <HStack spacing={3} align='flex-end' flexWrap='wrap'>
        <Box minW='280px'>
          <Text fontSize='sm' mb={1}>
            GitLab URL
          </Text>
          <Input
            placeholder='https://gitlab.com'
            value={gitlabBaseUrl}
            onChange={e => setGitlabBaseUrl(e.target.value)}
          />
        </Box>
        <Box minW='320px'>
          <Text fontSize='sm' mb={1}>
            Personal Access Token (read_api scope)
          </Text>
          <InputGroup>
            <Input
              type={showSecret ? 'text' : 'password'}
              placeholder={autoSyncTokenPlaceholder || 'Paste token'}
              value={gitlabToken}
              onChange={e => setGitlabToken(e.target.value)}
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
          onClick={doGitlabScan}
          isLoading={isScanning}
        >
          Scan
        </Button>
      </HStack>
      <Box border='1px solid' borderColor={borderColor} borderRadius='md' p={3}>
        <Text fontSize='sm' fontWeight='medium' mb={3}>
          Scan Filters
        </Text>
        <VStack align='stretch' spacing={3}>
          <Box>
            <Text fontSize='xs' fontWeight='medium' mb={2} color='gray.600'>
              Token Types
            </Text>
            <VStack align='stretch' spacing={1.5}>
              <Checkbox
                isChecked={gitlabIncludePATs}
                onChange={e => setGitlabIncludePATs(e.target.checked)}
                size='sm'
              >
                Personal Access Tokens
              </Checkbox>
              <Checkbox
                isChecked={gitlabIncludeProjectTokens}
                onChange={e => setGitlabIncludeProjectTokens(e.target.checked)}
                size='sm'
              >
                Project Access Tokens
              </Checkbox>
              <Checkbox
                isChecked={gitlabIncludeGroupTokens}
                onChange={e => setGitlabIncludeGroupTokens(e.target.checked)}
                size='sm'
              >
                Group Access Tokens
              </Checkbox>
              <Checkbox
                isChecked={gitlabIncludeDeployTokens}
                onChange={e => setGitlabIncludeDeployTokens(e.target.checked)}
                size='sm'
              >
                Deploy Tokens
              </Checkbox>
              <Checkbox
                isChecked={gitlabIncludeSSHKeys}
                onChange={e => setGitlabIncludeSSHKeys(e.target.checked)}
                size='sm'
              >
                SSH Keys (user only)
              </Checkbox>
            </VStack>
          </Box>

          <Box pt={2} borderTop='1px solid' borderColor={borderColor}>
            <Text fontSize='xs' fontWeight='medium' mb={2} color='gray.600'>
              Additional Filters
            </Text>
            <VStack align='stretch' spacing={1.5}>
              <Checkbox
                isChecked={gitlabExcludeUserPATs}
                onChange={e => setGitlabExcludeUserPATs(e.target.checked)}
                isDisabled={!gitlabIncludePATs}
                size='sm'
                colorScheme='purple'
              >
                Exclude users Personal Access Tokens
              </Checkbox>
              <Checkbox
                isChecked={gitlabIncludeExpired}
                onChange={e => setGitlabIncludeExpired(e.target.checked)}
                size='sm'
                colorScheme='orange'
              >
                Include expired tokens
              </Checkbox>
              <Checkbox
                isChecked={gitlabIncludeRevoked}
                onChange={e => setGitlabIncludeRevoked(e.target.checked)}
                size='sm'
                colorScheme='red'
              >
                Include revoked tokens
              </Checkbox>
            </VStack>
          </Box>
        </VStack>
      </Box>
      {gitlabSummary.length > 0 && (
        <Box
          border='1px solid'
          borderColor={borderColor}
          borderRadius='md'
          p={3}
        >
          <VStack align='stretch' spacing={2}>
            {gitlabSummary.map((s, i) => (
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
      {gitlabItems.length > 0 && (
        <>
          <IntegrationImportTable
            items={gitlabItems}
            selectedRows={selectedRowsGitlab}
            onToggleRow={i =>
              setSelectedRowsGitlab(prev => {
                const n = new Set(prev);
                n.has(i) ? n.delete(i) : n.add(i);
                return n;
              })
            }
            onToggleAll={() => {
              if (selectedRowsGitlab.size === gitlabItems.length) {
                setSelectedRowsGitlab(new Set());
              } else {
                setSelectedRowsGitlab(new Set(gitlabItems.map((_, i) => i)));
              }
            }}
            borderColor={borderColor}
            getDetailsForItem={getGitLabItemDetails}
            onUpdateItem={updateGitlabItem}
            duplicateIndices={gitlabDuplicates}
          />
          <BulkIntegrationAssignment
            selectedCount={selectedRowsGitlab.size}
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

export default ImportGitLabForm;
