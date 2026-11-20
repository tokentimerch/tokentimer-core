import { useMemo, useState } from 'react';
import {
  Box,
  Button,
  FormControl,
  FormLabel,
  Textarea,
  VStack,
  Text,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Badge,
  Alert,
  AlertIcon,
  AlertDescription,
  HStack,
  Select,
} from '@chakra-ui/react';
import apiClient from '../utils/apiClient';

const ROLE_LABELS = {
  admin: 'System Admin',
  workspace_manager: 'Workspace Manager',
  viewer: 'Viewer',
};

/**
 * Dry-run group mapping resolution (never persists). Uses existing mappings API.
 */
export default function SsoGroupMappingSimulator({
  providers = [],
  defaultProviderSlug = '',
}) {
  const [providerSlug, setProviderSlug] = useState(
    defaultProviderSlug || providers[0]?.slug || ''
  );
  const [input, setInput] = useState('{\n  "groups": ["devops"]\n}');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const providerOptions = useMemo(
    () =>
      providers.map(p => ({ slug: p.slug, label: p.displayName || p.slug })),
    [providers]
  );

  async function runSimulation() {
    setError('');
    setResult(null);
    let parsed;
    try {
      parsed = JSON.parse(input);
    } catch (e) {
      setError('Invalid JSON');
      return;
    }
    const groups = Array.isArray(parsed?.groups)
      ? parsed.groups
      : Array.isArray(parsed?.claims?.groups)
        ? parsed.claims.groups
        : [];
    if (!providerSlug) {
      setError('Select a provider');
      return;
    }
    try {
      setLoading(true);
      const res = await apiClient.post(
        '/api/admin/sso/group-mappings/simulate',
        {
          provider_slug: providerSlug,
          groups,
          strict_sync_preview: true,
        }
      );
      setResult(res.data || null);
    } catch (e) {
      const local = await simulateLocally(providerSlug, groups);
      if (local) {
        setResult(local);
        setError(
          e?.response?.data?.error
            ? `${e.response.data.error} (showing client-side preview from loaded mappings)`
            : 'Simulation API unavailable; showing client-side preview from loaded mappings only.'
        );
      } else {
        setError(e?.response?.data?.error || 'Simulation failed');
      }
    } finally {
      setLoading(false);
    }
  }

  async function simulateLocally(slug, groups) {
    try {
      const res = await apiClient.get('/api/admin/sso/group-mappings');
      const mappings = (res.data?.mappings || []).filter(
        m => m.provider_slug === slug
      );
      const groupSet = new Set(
        groups.map(g => String(g).trim().toLowerCase()).filter(Boolean)
      );
      const grants = [];
      const matchedGroups = new Set();
      let isAdmin = false;
      for (const m of mappings) {
        const group = String(m.idp_group).toLowerCase();
        if (!groupSet.has(group)) continue;
        matchedGroups.add(group);
        if (m.role === 'admin') {
          isAdmin = true;
          grants.push({ role: 'admin', workspace: 'system-wide' });
        } else {
          grants.push({
            role: m.role,
            workspace: m.workspace_id ? m.workspace_id : 'all workspaces',
          });
        }
      }
      return {
        provider_slug: slug,
        matched_groups: groups.filter(g =>
          matchedGroups.has(String(g).trim().toLowerCase())
        ),
        grants,
        is_admin: isAdmin,
        strict_sync_note:
          'Strict sync revokes only workspace memberships with source=sso for this provider. SSO system-admin mappings are grant-only: they promote matching users but never auto-revoke system admin; demote from Workspaces.',
        users_who_would_no_longer_match_admin_mapping: isAdmin
          ? 0
          : 'N/A (no admin mapping matched)',
      };
    } catch (_) {
      return null;
    }
  }

  return (
    <Box borderWidth='1px' borderRadius='md' p={4}>
      <Text fontWeight='semibold' mb={2}>
        Group mapping simulator
      </Text>
      <Text fontSize='sm' color='gray.500' mb={3}>
        Paste sample groups from an IdP token. Nothing is saved.
      </Text>
      <VStack align='stretch' spacing={3}>
        <FormControl>
          <FormLabel fontSize='sm'>Provider</FormLabel>
          <Select
            size='sm'
            value={providerSlug}
            onChange={e => setProviderSlug(e.target.value)}
          >
            {providerOptions.map(p => (
              <option key={p.slug} value={p.slug}>
                {p.label}
              </option>
            ))}
          </Select>
        </FormControl>
        <FormControl>
          <FormLabel fontSize='sm'>Sample payload</FormLabel>
          <Textarea
            size='sm'
            fontFamily='mono'
            rows={5}
            value={input}
            onChange={e => setInput(e.target.value)}
          />
        </FormControl>
        <Button
          size='sm'
          colorScheme='blue'
          isLoading={loading}
          onClick={runSimulation}
        >
          Simulate
        </Button>
        {error && (
          <Alert status='warning' fontSize='sm'>
            <AlertIcon />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {result && (
          <Box fontSize='sm'>
            <HStack mb={2}>
              <Badge colorScheme={result.is_admin ? 'purple' : 'gray'}>
                {result.is_admin ? 'Would grant admin' : 'No admin mapping'}
              </Badge>
            </HStack>
            {Array.isArray(result.grants) && result.grants.length > 0 ? (
              <Table size='sm'>
                <Thead>
                  <Tr>
                    <Th>Role</Th>
                    <Th>Scope</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {result.grants.map((g, i) => (
                    <Tr key={i}>
                      <Td>{ROLE_LABELS[g.role] || g.role}</Td>
                      <Td>{g.workspace}</Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            ) : (
              <Text>No workspace grants from current mappings.</Text>
            )}
            <Text mt={2} color='gray.500'>
              {result.strict_sync_note}
            </Text>
          </Box>
        )}
      </VStack>
    </Box>
  );
}
