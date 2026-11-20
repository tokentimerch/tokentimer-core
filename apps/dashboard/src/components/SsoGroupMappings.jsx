import { useEffect, useState } from 'react';
import {
  Badge,
  Box,
  Button,
  FormControl,
  FormHelperText,
  FormLabel,
  Heading,
  HStack,
  IconButton,
  Input,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Select,
  Spinner,
  Table,
  Tag,
  TagLabel,
  Tbody,
  Td,
  Text,
  Th,
  Thead,
  Tooltip,
  Tr,
  VStack,
  useDisclosure,
} from '@chakra-ui/react';
import { FiEdit2, FiPlus, FiTrash2, FiUsers } from 'react-icons/fi';
import apiClient from '../utils/apiClient';
import { showSuccess, showWarning } from '../utils/toast.js';
import { logger } from '../utils/logger.js';
import PrimaryButton from './onboarding/PrimaryButton.jsx';
import { StatusPanel, StatusTag } from './onboarding/panels.jsx';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from './DashboardModalFrame.jsx';
import { useDashboardTheme } from '../hooks/useDashboardTheme';

const ROLE_LABELS = {
  admin: 'System Admin',
  workspace_manager: 'Workspace Manager',
  viewer: 'Viewer',
};

const ROLE_COLOR_SCHEMES = {
  admin: 'purple',
  workspace_manager: 'blue',
  viewer: 'gray',
};

/** Fixed column shares so the mappings table uses the full width evenly. */
const MAPPING_TABLE_COLUMN_WIDTHS = {
  provider: '17%',
  idpGroup: '30%',
  role: '16%',
  workspace: '24%',
  actions: '13%',
};

const EMPTY_MAPPING_FORM = {
  id: null,
  provider_slug: '',
  idp_group: '',
  role: 'workspace_manager',
  workspace_id: '',
};

/**
 * State and actions for the SSO group-to-role mappings. Used by System
 * Settings and by the setup guide, so both talk to the same endpoints.
 */
export function useSsoGroupMappings() {
  const [mappings, setMappings] = useState([]);
  const [mappingsLoading, setMappingsLoading] = useState(true);
  const [mappingWorkspaces, setMappingWorkspaces] = useState([]);
  const [mappingProviders, setMappingProviders] = useState([]);
  const [mappingForm, setMappingForm] = useState(EMPTY_MAPPING_FORM);
  const [savingMapping, setSavingMapping] = useState(false);
  const [deletingMappingId, setDeletingMappingId] = useState(null);
  const {
    isOpen: isMappingModalOpen,
    onOpen: onOpenMappingModal,
    onClose: onCloseMappingModal,
  } = useDisclosure();

  async function loadMappings() {
    try {
      setMappingsLoading(true);
      const res = await apiClient.get('/api/admin/sso/group-mappings');
      setMappings(Array.isArray(res.data?.mappings) ? res.data.mappings : []);
      setMappingWorkspaces(
        Array.isArray(res.data?.workspaces) ? res.data.workspaces : []
      );
      setMappingProviders(
        Array.isArray(res.data?.providers) ? res.data.providers : []
      );
    } catch (e) {
      logger.error('Failed to load SSO group mappings', e);
      setMappings([]);
      setMappingWorkspaces([]);
    } finally {
      setMappingsLoading(false);
    }
  }

  function openAddMapping() {
    // Default to a workspace-scoped mapping when at least one workspace exists.
    // Without this, a brand-new mapping starts with workspace_id='' which the
    // backend interprets as "All workspaces (global)" - a footgun for an admin
    // who clicks Save without changing anything else.
    const defaultWsId =
      Array.isArray(mappingWorkspaces) && mappingWorkspaces.length > 0
        ? mappingWorkspaces[0].id
        : '';
    const defaultSlug =
      mappingProviders.length > 0 ? mappingProviders[0].slug : '';
    setMappingForm({
      ...EMPTY_MAPPING_FORM,
      provider_slug: defaultSlug,
      workspace_id: defaultWsId,
    });
    onOpenMappingModal();
  }

  function openEditMapping(m) {
    setMappingForm({
      id: m.id,
      provider_slug: m.provider_slug,
      idp_group: m.idp_group,
      role: m.role,
      workspace_id: m.workspace_id || '',
    });
    onOpenMappingModal();
  }

  function closeMappingModal() {
    if (savingMapping) return;
    onCloseMappingModal();
    setMappingForm(EMPTY_MAPPING_FORM);
  }

  function updateMappingForm(patch) {
    setMappingForm(prev => {
      const next = { ...prev, ...patch };
      // Switching role to admin clears the workspace (admin is always system-wide).
      // Switching role from admin to a workspace-scoped role defaults the
      // workspace to the first available one so the admin does not silently
      // create a "global" mapping just by changing the role dropdown. They
      // must explicitly pick "All workspaces (global)" if that is intended.
      if (patch.role === 'admin') {
        next.workspace_id = '';
      } else if (
        prev.role === 'admin' &&
        next.role !== 'admin' &&
        Array.isArray(mappingWorkspaces) &&
        mappingWorkspaces.length > 0
      ) {
        next.workspace_id = mappingWorkspaces[0].id;
      }
      return next;
    });
  }

  async function handleSaveMapping() {
    const trimmedGroup = mappingForm.idp_group.trim();
    if (!trimmedGroup) {
      showWarning('Enter an IdP group name');
      return;
    }
    if (!mappingForm.provider_slug) {
      showWarning('Select an SSO provider');
      return;
    }
    const payload = {
      provider_slug: mappingForm.provider_slug,
      idp_group: trimmedGroup,
      role: mappingForm.role,
      // Empty string in the dropdown means "All workspaces" (global) for
      // workspace_manager / viewer. admin is always system-wide.
      workspace_id:
        mappingForm.role === 'admin' || !mappingForm.workspace_id
          ? null
          : mappingForm.workspace_id,
    };
    try {
      setSavingMapping(true);
      if (mappingForm.id) {
        await apiClient.put(
          `/api/admin/sso/group-mappings/${mappingForm.id}`,
          payload
        );
        showSuccess('Group mapping updated');
      } else {
        await apiClient.post('/api/admin/sso/group-mappings', payload);
        showSuccess('Group mapping created');
      }
      await loadMappings();
      onCloseMappingModal();
      setMappingForm(EMPTY_MAPPING_FORM);
    } catch (e) {
      logger.error('Failed to save SSO group mapping', e);
      showWarning(
        e?.response?.data?.error || 'Failed to save the group mapping'
      );
    } finally {
      setSavingMapping(false);
    }
  }

  async function handleDeleteMapping(id) {
    if (!id) return;
    if (
      !window.confirm(
        'Delete this mapping? Users matched only by this rule will lose the granted role on their next SSO login.'
      )
    ) {
      return;
    }
    try {
      setDeletingMappingId(id);
      await apiClient.delete(`/api/admin/sso/group-mappings/${id}`);
      showSuccess('Group mapping removed');
      await loadMappings();
    } catch (e) {
      logger.error('Failed to delete SSO group mapping', e);
      showWarning(
        e?.response?.data?.error || 'Failed to delete the group mapping'
      );
    } finally {
      setDeletingMappingId(null);
    }
  }

  function workspaceNameFor(id) {
    if (!id) return null;
    const w = mappingWorkspaces.find(x => x.id === id);
    return w ? w.name : id;
  }

  useEffect(() => {
    loadMappings();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return {
    mappings,
    mappingsLoading,
    mappingWorkspaces,
    mappingProviders,
    mappingForm,
    savingMapping,
    deletingMappingId,
    isMappingModalOpen,
    loadMappings,
    openAddMapping,
    openEditMapping,
    closeMappingModal,
    updateMappingForm,
    handleSaveMapping,
    handleDeleteMapping,
    workspaceNameFor,
  };
}

/** The mappings table with its add, edit and delete actions. */
export function SsoGroupMappingsSection({ state, hint = null }) {
  const {
    mappings,
    mappingsLoading,
    mappingProviders,
    deletingMappingId,
    openAddMapping,
    openEditMapping,
    handleDeleteMapping,
    workspaceNameFor,
  } = state;
  const { muted, border, dashboard } = useDashboardTheme();
  const tableHeaderBg = dashboard.bg.nested;
  const tableRowHoverBg = dashboard.bg.panelHover;

  return (
    <Box id='sso-group-mappings'>
      <HStack justify='space-between' mb={4} flexWrap='wrap' gap={2}>
        <HStack spacing={2}>
          <FiUsers aria-hidden />
          <Heading
            as='h3'
            size='sm'
            color='inherit'
            fontFamily='Archivo, system-ui, sans-serif'
            fontWeight='bold'
            lineHeight='short'
          >
            Group &rarr; Role mappings
          </Heading>
          <StatusTag tone={mappings.length > 0 ? 'green' : 'gray'}>
            {mappings.length} active
          </StatusTag>
        </HStack>
        <PrimaryButton leftIcon={<FiPlus />} onClick={openAddMapping}>
          Add mapping
        </PrimaryButton>
      </HStack>
      {hint ? (
        <Box mb={4}>
          <StatusPanel status='warning'>{hint}</StatusPanel>
        </Box>
      ) : null}
      <Text fontSize='sm' color={muted} mb={4}>
        Bind IdP groups to TokenTimer roles. Memberships are reconciled on every
        SSO login.
      </Text>

      {mappingsLoading ? (
        <HStack role='status' aria-busy='true'>
          <Spinner size='sm' />
          <Text fontSize='sm'>Loading group mappings...</Text>
        </HStack>
      ) : mappings.length === 0 ? (
        <StatusPanel status='info'>
          No mappings yet. SSO users will land in their personal workspace only.
          Add a mapping to grant roles automatically from IdP group claims.
        </StatusPanel>
      ) : (
        <Box
          w='100%'
          minW={0}
          overflowX='auto'
          borderWidth='1px'
          borderColor={border}
          borderRadius='md'
          role='region'
          aria-label='Group to role mappings'
          tabIndex={0}
          _focusVisible={{ boxShadow: 'outline', outline: 'none' }}
        >
          <Table
            size='sm'
            variant='simple'
            w='100%'
            minW='700px'
            layout='fixed'
          >
            <Thead bg={tableHeaderBg}>
              <Tr>
                <Th w={MAPPING_TABLE_COLUMN_WIDTHS.provider} textAlign='left'>
                  Provider
                </Th>
                <Th w={MAPPING_TABLE_COLUMN_WIDTHS.idpGroup} textAlign='left'>
                  IdP Group
                </Th>
                <Th w={MAPPING_TABLE_COLUMN_WIDTHS.role} textAlign='left'>
                  Role
                </Th>
                <Th w={MAPPING_TABLE_COLUMN_WIDTHS.workspace} textAlign='left'>
                  Workspace
                </Th>
                <Th w={MAPPING_TABLE_COLUMN_WIDTHS.actions} textAlign='right'>
                  Actions
                </Th>
              </Tr>
            </Thead>
            <Tbody>
              {mappings.map(m => {
                const providerName =
                  mappingProviders.find(p => p.slug === m.provider_slug)
                    ?.displayName || m.provider_slug;
                const workspaceLabel = m.workspace_id
                  ? workspaceNameFor(m.workspace_id)
                  : m.role === 'admin'
                    ? 'system-wide'
                    : 'all workspaces';
                return (
                  <Tr key={m.id} _hover={{ bg: tableRowHoverBg }}>
                    <Td w={MAPPING_TABLE_COLUMN_WIDTHS.provider} py={3}>
                      <Tooltip
                        label={providerName}
                        placement='top'
                        hasArrow
                        openDelay={300}
                      >
                        <Tag
                          size='sm'
                          variant='subtle'
                          colorScheme='cyan'
                          maxW='100%'
                        >
                          <TagLabel isTruncated>{providerName}</TagLabel>
                        </Tag>
                      </Tooltip>
                    </Td>
                    <Td
                      w={MAPPING_TABLE_COLUMN_WIDTHS.idpGroup}
                      overflow='hidden'
                      py={3}
                    >
                      <Tooltip
                        label={m.idp_group}
                        placement='top'
                        hasArrow
                        openDelay={300}
                      >
                        <Text
                          fontSize='sm'
                          fontFamily='mono'
                          noOfLines={1}
                          wordBreak='break-all'
                        >
                          {m.idp_group}
                        </Text>
                      </Tooltip>
                    </Td>
                    <Td w={MAPPING_TABLE_COLUMN_WIDTHS.role} py={3}>
                      <Badge
                        colorScheme={ROLE_COLOR_SCHEMES[m.role] || 'gray'}
                        variant='subtle'
                        whiteSpace='normal'
                        display='inline-flex'
                        alignItems='center'
                        justifyContent='center'
                        textAlign='center'
                        maxW='100%'
                        py={1}
                        lineHeight='short'
                      >
                        {ROLE_LABELS[m.role] || m.role}
                      </Badge>
                    </Td>
                    <Td
                      w={MAPPING_TABLE_COLUMN_WIDTHS.workspace}
                      overflow='hidden'
                      py={3}
                    >
                      {m.workspace_id ? (
                        <Tooltip
                          label={workspaceLabel}
                          placement='top'
                          hasArrow
                          openDelay={300}
                        >
                          <Text fontSize='sm' noOfLines={1}>
                            {workspaceLabel}
                          </Text>
                        </Tooltip>
                      ) : (
                        <Text
                          fontSize='sm'
                          color={muted}
                          fontStyle='italic'
                          noOfLines={1}
                        >
                          {workspaceLabel}
                        </Text>
                      )}
                    </Td>
                    <Td
                      w={MAPPING_TABLE_COLUMN_WIDTHS.actions}
                      textAlign='right'
                      py={3}
                    >
                      <HStack spacing={1} justify='flex-end'>
                        <Tooltip label='Edit mapping' openDelay={300}>
                          <IconButton
                            aria-label='Edit mapping'
                            icon={<FiEdit2 />}
                            size='sm'
                            variant='ghost'
                            onClick={() => openEditMapping(m)}
                          />
                        </Tooltip>
                        <Tooltip label='Delete mapping' openDelay={300}>
                          <IconButton
                            aria-label='Delete mapping'
                            icon={<FiTrash2 />}
                            size='sm'
                            variant='ghost'
                            colorScheme='red'
                            isLoading={deletingMappingId === m.id}
                            onClick={() => handleDeleteMapping(m.id)}
                          />
                        </Tooltip>
                      </HStack>
                    </Td>
                  </Tr>
                );
              })}
            </Tbody>
          </Table>
        </Box>
      )}
    </Box>
  );
}

/** The add and edit dialog for one mapping. */
export function SsoGroupMappingModal({ state }) {
  const {
    mappingForm,
    mappingProviders,
    mappingWorkspaces,
    savingMapping,
    isMappingModalOpen,
    closeMappingModal,
    updateMappingForm,
    handleSaveMapping,
  } = state;
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    outlineButtonProps,
    primaryButtonProps,
  } = useDashboardModalProps();

  return (
    <Modal
      isOpen={isMappingModalOpen}
      onClose={closeMappingModal}
      size='lg'
      closeOnOverlayClick={!savingMapping}
      isCentered
      scrollBehavior='inside'
    >
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame maxW='560px'>
        <ModalHeader {...headerProps}>
          <DashboardModalTitle>
            {mappingForm.id ? 'Edit group mapping' : 'Add group mapping'}
          </DashboardModalTitle>
          <DashboardModalDescription>
            Map an IdP group claim to a TokenTimer role and workspace scope.
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} isDisabled={savingMapping} />
        <ModalBody {...bodyProps}>
          <VStack align='stretch' spacing={4}>
            <FormControl>
              <FormLabel fontSize='sm'>Identity provider</FormLabel>
              <Select
                size='sm'
                value={mappingForm.provider_slug}
                onChange={e =>
                  updateMappingForm({ provider_slug: e.target.value })
                }
                placeholder={
                  mappingProviders.length === 0
                    ? 'No SSO providers configured'
                    : 'Select provider'
                }
              >
                {mappingProviders.map(p => (
                  <option key={p.slug} value={p.slug}>
                    {p.displayName} ({p.type})
                  </option>
                ))}
              </Select>
              <FormHelperText>
                SSO provider slug from the providers registry.
              </FormHelperText>
            </FormControl>

            <FormControl>
              <FormLabel fontSize='sm'>IdP group name</FormLabel>
              <Input
                size='sm'
                fontFamily='mono'
                value={mappingForm.idp_group}
                onChange={e => updateMappingForm({ idp_group: e.target.value })}
                placeholder='e.g. devops, security-team, tt-platform-admins'
              />
              <FormHelperText>
                Matched case-insensitively against groups/roles claims from the
                IdP. For Entra SAML, use the exact value in the assertion (often
                a group object ID, not the display name). Re-login after
                changing mappings.
              </FormHelperText>
            </FormControl>

            <FormControl>
              <FormLabel fontSize='sm'>TokenTimer role to grant</FormLabel>
              <Select
                size='sm'
                value={mappingForm.role}
                onChange={e => updateMappingForm({ role: e.target.value })}
              >
                <option value='admin'>System Admin (global)</option>
                <option value='workspace_manager'>Workspace Manager</option>
                <option value='viewer'>Viewer</option>
              </Select>
              <FormHelperText>
                System Admin is global. Workspace Manager and Viewer can target
                a specific workspace or apply across all workspaces.
              </FormHelperText>
            </FormControl>

            <FormControl isDisabled={mappingForm.role === 'admin'}>
              <FormLabel fontSize='sm'>Target workspace</FormLabel>
              <Select
                size='sm'
                value={mappingForm.workspace_id}
                onChange={e =>
                  updateMappingForm({ workspace_id: e.target.value })
                }
                placeholder={
                  mappingForm.role === 'admin'
                    ? 'Not applicable for System Admin'
                    : undefined
                }
              >
                {mappingForm.role !== 'admin' && (
                  <option value=''>All workspaces (global)</option>
                )}
                {mappingWorkspaces.map(w => (
                  <option key={w.id} value={w.id}>
                    {w.name}
                  </option>
                ))}
              </Select>
              {mappingForm.role === 'admin' ? (
                <FormHelperText>
                  System admins receive Workspace Manager (not workspace Admin)
                  on every workspace, plus System Settings access. Sign out and
                  back in after creating or editing this mapping.
                </FormHelperText>
              ) : (
                <FormHelperText>
                  Leave on &ldquo;All workspaces&rdquo; to grant this role in
                  every workspace, including those created later.
                </FormHelperText>
              )}
            </FormControl>

            {mappingForm.role !== 'admin' &&
              mappingForm.workspace_id === '' && (
                <StatusPanel status='warning'>
                  This mapping is GLOBAL: every authenticated SSO user in the
                  selected IdP group will become{' '}
                  {ROLE_LABELS[mappingForm.role] || mappingForm.role} in every
                  workspace, including any future workspace. Pick a specific
                  workspace above to scope the mapping.
                </StatusPanel>
              )}

            <StatusPanel status='info'>
              Existing memberships granted via the UI are preserved. SSO
              mappings only manage rows they created themselves.
            </StatusPanel>
          </VStack>
        </ModalBody>
        <ModalFooter {...footerProps}>
          <Button
            onClick={closeMappingModal}
            isDisabled={savingMapping}
            minW={{ base: '100%', sm: '104px' }}
            {...outlineButtonProps}
          >
            Cancel
          </Button>
          <Button
            isLoading={savingMapping}
            onClick={handleSaveMapping}
            minW={{ base: '100%', sm: '160px' }}
            {...primaryButtonProps}
          >
            {mappingForm.id ? 'Save changes' : 'Create mapping'}
          </Button>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}
