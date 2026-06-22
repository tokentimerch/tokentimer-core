import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  VStack,
  HStack,
  Text,
  Select,
  Input,
  Button,
  IconButton,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Badge,
  Checkbox,
  Switch,
  Alert,
  AlertIcon,
  AlertDescription,
  AlertDialog,
  AlertDialogBody,
  AlertDialogCloseButton,
  AlertDialogContent,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogOverlay,
  Flex,
  SimpleGrid,
} from '@chakra-ui/react';
import { FiEdit2, FiCheck, FiX } from 'react-icons/fi';
import DashboardPageLayout from '../components/DashboardPageLayout';
import {
  DashboardActionButton,
  DashboardPanel,
  DashboardPanelHeader,
  DashboardState,
} from '../components/DashboardPrimitives';
import {
  useDashboardModalProps,
  DashboardModalDescription,
  DashboardModalTitle,
} from '../components/DashboardModalFrame.jsx';
import SEO from '../components/SEO.jsx';
import { useDashboardTheme } from '../hooks/useDashboardTheme';
import apiClient, {
  API_ENDPOINTS,
  workspaceAPI,
  adminAPI,
} from '../utils/apiClient';
import { logger } from '../utils/logger';
import { useWorkspace } from '../utils/WorkspaceContext.jsx';
import { showWarning, showError } from '../utils/toast.js';

const MEMBER_ROLE_LABELS = {
  admin: 'Workspace owner',
  workspace_manager: 'Manager',
  viewer: 'Viewer',
};

const MEMBER_ROLE_OPTIONS = [
  { value: 'viewer', label: MEMBER_ROLE_LABELS.viewer },
  { value: 'workspace_manager', label: MEMBER_ROLE_LABELS.workspace_manager },
];

function WorkspaceConfirmSectionTitle({ children, tokens }) {
  return (
    <Text
      gridColumn={{ base: 'auto', sm: '1 / -1' }}
      fontSize='sm'
      fontWeight='bold'
      color={tokens.text}
      pl={3}
      borderLeft='3px solid'
      borderColor={tokens.sectionAccent}
    >
      {children}
    </Text>
  );
}

function WorkspaceConfirmFieldCard({ label, children, tokens }) {
  return (
    <Box
      bg={tokens.fieldBg}
      border='1px solid'
      borderColor={tokens.border}
      borderRadius='12px'
      p={{ base: 3.5, md: 4 }}
      minH='88px'
    >
      <Text fontSize='sm' fontWeight='semibold' color={tokens.muted} mb={2}>
        {label}
      </Text>
      {children}
    </Box>
  );
}

function WorkspaceConfirmValue({ children, tokens }) {
  return (
    <Text fontSize={{ base: 'sm', md: 'md' }} color={tokens.text}>
      {children || '-'}
    </Text>
  );
}

function getMemberName(member) {
  return member?.display_name || member?.email || 'Workspace member';
}

function getWorkspaceActionCopy(action) {
  const isMemberRemoval = action?.type === 'remove-member';
  return {
    title: isMemberRemoval ? 'Remove Member' : 'Cancel Invite',
    description: isMemberRemoval
      ? 'Review this workspace member before removing access.'
      : 'Review this pending invitation before canceling it.',
    warning: isMemberRemoval
      ? 'This member will lose access to the workspace. Existing assets and audit records remain unchanged.'
      : 'This pending invitation will be canceled and the recipient will no longer be able to accept it.',
    confirmLabel: isMemberRemoval ? 'Remove' : 'Cancel Invite',
    sectionTitle: isMemberRemoval
      ? 'Member Information'
      : 'Invitation Information',
  };
}

function WorkspaceActionConfirmModal({
  isOpen,
  action,
  isLoading,
  onClose,
  onConfirm,
}) {
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    outlineButtonProps,
    dangerButtonProps,
    tokens,
  } = useDashboardModalProps();
  const { dashboard } = useDashboardTheme();
  const cancelButtonRef = React.useRef(null);
  const copy = getWorkspaceActionCopy(action);
  const member = action?.member;
  const invitation = action?.invitation;
  const role = member?.role || invitation?.role;
  const roleLabel = MEMBER_ROLE_LABELS[role] || role || '-';

  return (
    <AlertDialog
      isOpen={isOpen}
      leastDestructiveRef={cancelButtonRef}
      onClose={onClose}
      isCentered
      scrollBehavior='inside'
    >
      <AlertDialogOverlay {...overlayProps} />
      <AlertDialogContent
        maxW={{ base: 'calc(100vw - 24px)', md: '760px' }}
        maxH={{ base: 'calc(100dvh - 24px)', md: 'calc(100dvh - 64px)' }}
      >
        <AlertDialogHeader {...headerProps}>
          <DashboardModalTitle>{copy.title}</DashboardModalTitle>
          <DashboardModalDescription>
            {copy.description}
          </DashboardModalDescription>
        </AlertDialogHeader>
        <AlertDialogCloseButton {...closeButtonProps} />
        <AlertDialogBody {...bodyProps}>
          <VStack spacing={4} align='stretch'>
            <Alert
              status='warning'
              bg={dashboard.callout.warningSurface}
              border='1px solid'
              borderColor={dashboard.callout.warningBorder}
              color={dashboard.callout.warningText}
              borderRadius='12px'
            >
              <AlertIcon />
              <AlertDescription>{copy.warning}</AlertDescription>
            </Alert>

            {action ? (
              <SimpleGrid columns={{ base: 1, sm: 2 }} spacing={3}>
                <WorkspaceConfirmSectionTitle tokens={tokens}>
                  {copy.sectionTitle}
                </WorkspaceConfirmSectionTitle>
                <WorkspaceConfirmFieldCard
                  label={member ? 'Member' : 'Invitee'}
                  tokens={tokens}
                >
                  <WorkspaceConfirmValue tokens={tokens}>
                    {member ? getMemberName(member) : invitation?.email}
                  </WorkspaceConfirmValue>
                </WorkspaceConfirmFieldCard>
                <WorkspaceConfirmFieldCard label='Email' tokens={tokens}>
                  <WorkspaceConfirmValue tokens={tokens}>
                    {member?.email || invitation?.email}
                  </WorkspaceConfirmValue>
                </WorkspaceConfirmFieldCard>
                <WorkspaceConfirmFieldCard label='Workspace' tokens={tokens}>
                  <WorkspaceConfirmValue tokens={tokens}>
                    {action.workspaceName}
                  </WorkspaceConfirmValue>
                </WorkspaceConfirmFieldCard>
                <WorkspaceConfirmFieldCard
                  label={member ? 'Workspace Role' : 'Invited Role'}
                  tokens={tokens}
                >
                  <WorkspaceConfirmValue tokens={tokens}>
                    {roleLabel}
                  </WorkspaceConfirmValue>
                </WorkspaceConfirmFieldCard>
                {!member && invitation?.created_at ? (
                  <WorkspaceConfirmFieldCard label='Sent' tokens={tokens}>
                    <WorkspaceConfirmValue tokens={tokens}>
                      {new Date(invitation.created_at).toLocaleString()}
                    </WorkspaceConfirmValue>
                  </WorkspaceConfirmFieldCard>
                ) : null}
              </SimpleGrid>
            ) : null}
          </VStack>
        </AlertDialogBody>
        <AlertDialogFooter {...footerProps}>
          <Flex
            w='100%'
            gap={3}
            justify={{ base: 'stretch', sm: 'flex-end' }}
            direction={{ base: 'column-reverse', sm: 'row' }}
          >
            <Button
              ref={cancelButtonRef}
              onClick={onClose}
              minW={{ base: '100%', sm: '104px' }}
              isDisabled={isLoading}
              {...outlineButtonProps}
            >
              Cancel
            </Button>
            <Button
              onClick={onConfirm}
              minW={{ base: '100%', sm: '128px' }}
              isLoading={isLoading}
              {...dangerButtonProps}
            >
              {copy.confirmLabel}
            </Button>
          </Flex>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

export default function Workspaces({ session, onLogout, onAccountClick }) {
  const navigate = useNavigate();
  const { border, muted, dashboard } = useDashboardTheme();
  const mobileCardBg = dashboard.bg.panelHover;
  const {
    overlayProps,
    contentProps,
    headerProps,
    bodyProps,
    footerProps,
    fieldProps,
    tokens: modalTokens,
    outlineButtonProps,
    primaryButtonProps,
    dangerButtonProps,
  } = useDashboardModalProps();
  const { selectWorkspace, workspaceId } = useWorkspace();
  const [workspaces, setWorkspaces] = React.useState([]);
  const [currentWorkspace, setCurrentWorkspace] = React.useState(null);
  const [members, setMembers] = React.useState([]);
  const [pendingInvitations, setPendingInvitations] = React.useState([]);
  const [inviteEmail, setInviteEmail] = React.useState('');
  const [inviteRole, setInviteRole] = React.useState('viewer');
  const [newWorkspaceName, setNewWorkspaceName] = React.useState('');
  const [creatingWorkspace, setCreatingWorkspace] = React.useState(false);
  const [deleting, setDeleting] = React.useState(false);
  const [confirmOpen, setConfirmOpen] = React.useState(false);
  const [deleteConfirmName, setDeleteConfirmName] = React.useState('');
  const cancelRef = React.useRef();
  const [accountPlan, setAccountPlan] = React.useState(null);
  const [transferOpen, setTransferOpen] = React.useState(false);
  const [transferState, setTransferState] = React.useState({
    fromId: '',
    toId: '',
    search: '',
    tokens: [],
    selected: new Set(),
    categories: [],
    sections: [],
    loading: false,
  });
  const [authorized, setAuthorized] = React.useState(null);
  const [renaming, setRenaming] = React.useState(false);
  const [renameValue, setRenameValue] = React.useState('');
  const [renameSaving, setRenameSaving] = React.useState(false);
  const [workspaceActionConfirm, setWorkspaceActionConfirm] =
    React.useState(null);
  const [workspaceActionSubmitting, setWorkspaceActionSubmitting] =
    React.useState(false);

  // Fetch all tokens for a workspace by paging to avoid missing items (incl. duplicates by name)
  const fetchAllTokensForWorkspace = React.useCallback(async workspaceId => {
    if (!workspaceId) {
      setTransferState(prev => ({
        ...prev,
        tokens: [],
        categories: [],
        sections: [],
        loading: false,
      }));
      return;
    }
    setTransferState(prev => ({ ...prev, loading: true }));
    const pageSize = 500;
    let offset = 0;
    const all = [];
    try {
      // eslint-disable-next-line no-constant-condition
      while (true) {
        // eslint-disable-next-line no-await-in-loop
        const tRes = await apiClient.get(API_ENDPOINTS.GET_TOKENS, {
          params: { workspace_id: workspaceId, limit: pageSize, offset },
        });
        const batch = Array.isArray(tRes?.data?.items)
          ? tRes.data.items
          : Array.isArray(tRes?.data)
            ? tRes.data
            : [];
        logger.info('[Transfer] Fetched tokens batch', {
          workspaceId,
          offset,
          batchSize: batch.length,
          totalSoFar: all.length + batch.length,
        });
        all.push(...batch);
        if (batch.length < pageSize) break;
        offset += pageSize;
        if (offset >= 10000) break; // safety cap
      }
    } catch (err) {
      logger.error('[Transfer] Failed to fetch tokens', {
        workspaceId,
        error: err?.message || String(err),
      });
      // fall through with whatever collected
    }
    const cats = Array.from(new Set(all.map(t => t.category).filter(Boolean)));
    // Section is an array - extract all unique values
    const secs = Array.from(
      new Set(
        all.flatMap(t =>
          Array.isArray(t.section)
            ? t.section.map(s => String(s || '').trim()).filter(Boolean)
            : []
        )
      )
    );
    logger.info('[Transfer] Setting transfer state', {
      workspaceId,
      tokenCount: all.length,
      categories: cats.length,
      sections: secs.length,
    });
    setTransferState(prev => ({
      ...prev,
      tokens: all,
      categories: cats,
      sections: secs,
      loading: false,
    }));
  }, []);

  // Keep selection in sync with current filters so hidden rows are not transferred unintentionally
  React.useEffect(() => {
    if (!transferOpen) return;
    const visible = (transferState.tokens || []).filter(t => {
      const nameMatch = transferState.search
        ? (t.name || '')
            .toLowerCase()
            .includes(transferState.search.toLowerCase())
        : true;
      const catMatch = transferState.filterCategory
        ? t.category === transferState.filterCategory
        : true;
      const secMatch = transferState.filterSection
        ? Array.isArray(t.section)
          ? t.section.includes(transferState.filterSection)
          : false
        : true;
      return nameMatch && catMatch && secMatch;
    });
    const visibleIds = new Set(visible.map(t => t.id));
    const nextSelected = new Set(
      Array.from(transferState.selected || []).filter(id => visibleIds.has(id))
    );
    if (nextSelected.size !== (transferState.selected || new Set()).size) {
      setTransferState(prev => ({ ...prev, selected: nextSelected }));
    }
  }, [
    transferOpen,
    transferState.search,
    transferState.filterCategory,
    transferState.filterSection,
    transferState.tokens,
    transferState.selected,
  ]);

  const canManage =
    currentWorkspace &&
    (currentWorkspace.role === 'admin' ||
      currentWorkspace.role === 'workspace_manager');
  const contextWorkspace = workspaces.find(w => w.id === workspaceId);
  const isViewer = (contextWorkspace || currentWorkspace)?.role === 'viewer';
  const isAdmin = currentWorkspace && currentWorkspace.role === 'admin';
  const isSystemAdmin = session?.isAdmin === true;

  // Load live account plan once on mount (and after navigation back from checkout)
  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await apiClient.get(API_ENDPOINTS.ACCOUNT_PLAN);
        if (!cancelled) {
          setAccountPlan(String(res?.data?.plan || 'oss').toLowerCase());
        }
      } catch (_) {
        if (!cancelled) setAccountPlan('oss');
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Authorization: who can access Workspaces
  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const _planRes = await apiClient
          .get(API_ENDPOINTS.ACCOUNT_PLAN)
          .catch(() => ({ data: { plan: 'oss' } }));
        if (cancelled) return;
        const ws = await workspaceAPI.list(50, 0).catch(() => ({ items: [] }));
        if (cancelled) return;
        const items = ws?.items || [];
        const roles = items.map(w => String(w.role || '').toLowerCase());
        const adminAny = roles.includes('admin');
        // Core: authorize by role. When list empty allow access (bootstrap admin / list not loaded yet).
        const managerAny = adminAny || roles.includes('workspace_manager');
        const allow = items.length === 0 ? true : managerAny;
        setAuthorized(allow);
        if (!allow) {
          try {
            navigate('/dashboard', { replace: true });
          } catch (_) {}
        }
      } catch (_) {
        setAuthorized(false);
        try {
          navigate('/dashboard', { replace: true });
        } catch (_) {}
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [navigate]);

  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const ws = await workspaceAPI.list(50, 0);
        const allItems = ws?.items || [];
        const items = allItems;
        if (cancelled) return;
        setWorkspaces(items);
        // Prefer an admin workspace, then manager, then any
        const selected =
          items.find(w => w.role === 'admin') ||
          items.find(w => w.role === 'workspace_manager') ||
          items[0] ||
          null;
        setCurrentWorkspace(selected);
        // Preselect transfer source/target hints
        if (selected) {
          setTransferState(prev => ({
            ...prev,
            fromId: selected.id,
            toId: items.find(w => w.id !== selected.id)?.id || '',
          }));
        }
        if (selected) {
          const res = await workspaceAPI.listMembers(selected.id, 100, 0);
          if (!cancelled) setMembers(res?.items || []);
          try {
            const inv = await workspaceAPI.listInvitations(selected.id, 100, 0);
            if (!cancelled) setPendingInvitations(inv?.items || []);
          } catch (_) {
            if (!cancelled) setPendingInvitations([]);
          }
        }
      } catch (_) {
        if (!cancelled) {
          setWorkspaces([]);
          setMembers([]);
          setPendingInvitations([]);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  async function reloadMembers(workspaceId) {
    const res = await workspaceAPI.listMembers(workspaceId, 100, 0);
    setMembers(res?.items || []);
  }

  async function reloadInvitations(workspaceId) {
    try {
      const res = await workspaceAPI.listInvitations(workspaceId, 100, 0);
      setPendingInvitations(res?.items || []);
    } catch (_) {
      setPendingInvitations([]);
    }
  }

  function openWorkspaceActionConfirm(type, payload) {
    if (!currentWorkspace) return;
    setWorkspaceActionConfirm({
      type,
      workspaceId: currentWorkspace.id,
      workspaceName: currentWorkspace.name,
      ...payload,
    });
  }

  function closeWorkspaceActionConfirm() {
    if (workspaceActionSubmitting) return;
    setWorkspaceActionConfirm(null);
  }

  async function confirmWorkspaceAction() {
    if (!workspaceActionConfirm) return;

    setWorkspaceActionSubmitting(true);
    try {
      if (workspaceActionConfirm.type === 'remove-member') {
        await workspaceAPI.removeMember(
          workspaceActionConfirm.workspaceId,
          workspaceActionConfirm.member.user_id
        );
        await reloadMembers(workspaceActionConfirm.workspaceId);
      } else if (workspaceActionConfirm.type === 'cancel-invite') {
        await workspaceAPI.cancelInvitation(
          workspaceActionConfirm.workspaceId,
          workspaceActionConfirm.invitation.id
        );
        await reloadInvitations(workspaceActionConfirm.workspaceId);
      }
      setWorkspaceActionConfirm(null);
    } catch (_) {
      // workspaceAPI already routes request failures through the global API toast.
    } finally {
      setWorkspaceActionSubmitting(false);
    }
  }

  return (
    <>
      <SEO
        title='Workspaces'
        description='Manage your workspaces, team members, and workspace settings'
        noindex
      />
      <DashboardPageLayout
        variant='wide'
        session={session}
        onLogout={onLogout}
        onAccountClick={onAccountClick}
        pageTitle='Workspaces'
        isViewer={isViewer}
      >
        {authorized === false ? (
          <DashboardPanel>
            <DashboardState
              title='Workspace management is unavailable'
              description='Only workspace admins and managers can manage members and workspace settings.'
            />
          </DashboardPanel>
        ) : (
          <VStack align='stretch' spacing={6} w='full'>
            <DashboardPanel h='fit-content'>
              <DashboardPanelHeader
                title='Create workspace'
                description='Create an isolated workspace for another team, project, or environment.'
                mb={3}
              />
              <HStack spacing={3} align='center' flexWrap='wrap'>
                <Input
                  placeholder='Workspace name'
                  value={newWorkspaceName}
                  onChange={e => setNewWorkspaceName(e.target.value)}
                  maxW={{ base: '100%', sm: '320px' }}
                  size='sm'
                />
                <DashboardActionButton
                  isLoading={creatingWorkspace}
                  onClick={async () => {
                    const name = (newWorkspaceName || '').trim();
                    if (!name) return;
                    try {
                      setCreatingWorkspace(true);
                      const created = await workspaceAPI.create({
                        name,
                        // Reload workspaces after creation
                        plan: accountPlan || session?.plan || 'oss',
                      });
                      setNewWorkspaceName('');
                      // Retry listing until the newly created workspace appears (eventual consistency)
                      let attempts = 0;
                      let items = [];
                      let sel = null;
                      while (attempts < 15) {
                        const ws = await workspaceAPI.list(50, 0);
                        items = ws?.items || [];
                        sel =
                          (created?.id &&
                            items.find(w => w.id === created.id)) ||
                          null;
                        if (sel) break;
                        attempts++;
                        await new Promise(r =>
                          setTimeout(r, 250 + 100 * attempts)
                        );
                      }
                      if (!sel) {
                        // Fallback to first available if not found
                        sel = items[0] || null;
                      }
                      setWorkspaces(items);
                      setCurrentWorkspace(sel);
                      if (sel) {
                        const res = await workspaceAPI.listMembers(
                          sel.id,
                          100,
                          0
                        );
                        setMembers(res?.items || []);
                        await reloadInvitations(sel.id);
                        try {
                          // Keep user on the same page, only refresh context + nav
                          selectWorkspace(sel.id, { replace: true });
                        } catch (_) {}
                        try {
                          const search = new URLSearchParams(
                            window.location.search
                          );
                          search.set('workspace', sel.id);
                          const qs = search.toString();
                          // Ensure we remain on the Workspaces page after creation
                          if (
                            (window.location.pathname || '') !== '/workspaces'
                          ) {
                            navigate(`/workspaces?${qs}`, { replace: true });
                          } else {
                            window.history.replaceState(
                              null,
                              '',
                              `${window.location.pathname}?${qs}`
                            );
                          }
                        } catch (_) {}
                        try {
                          localStorage.setItem('tt_last_workspace_id', sel.id);
                        } catch (_) {}
                        try {
                          window.dispatchEvent(
                            new CustomEvent('tt:workspaces-updated', {
                              detail: { createdId: sel.id },
                            })
                          );
                        } catch (_) {}
                        // Also emit a nav-refresh without navigation
                        try {
                          window.dispatchEvent(
                            new CustomEvent('tt:plan-updated')
                          );
                        } catch (_) {}
                      } else {
                        setMembers([]);
                        setPendingInvitations([]);
                      }
                      // No redirect to tokens; stay on Workspaces page
                    } catch (_) {
                      // no-op
                    } finally {
                      setCreatingWorkspace(false);
                    }
                  }}
                >
                  Create
                </DashboardActionButton>
              </HStack>
            </DashboardPanel>

            <DashboardPanel minW={0}>
              <DashboardPanelHeader
                title='Workspace management'
                description='Select a workspace, manage its members, and transfer assets between workspaces.'
                mb={3}
              />
              <HStack spacing={3} mb={4} align='center' flexWrap='wrap'>
                <Text fontWeight='semibold'>Workspace:</Text>
                <Select
                  maxW={{ base: '100%', sm: '300px' }}
                  value={currentWorkspace?.id || ''}
                  onChange={async e => {
                    const id = e.target.value;
                    const ws = workspaces.find(w => w.id === id);
                    setCurrentWorkspace(ws || null);
                    setRenaming(false);
                    if (ws) {
                      await reloadMembers(ws.id);
                      await reloadInvitations(ws.id);
                    } else {
                      setMembers([]);
                      setPendingInvitations([]);
                    }
                  }}
                >
                  {workspaces.map(w => (
                    <option key={w.id} value={w.id}>
                      {w.name} ({w.role})
                    </option>
                  ))}
                </Select>
                {currentWorkspace && (
                  <Badge
                    colorScheme={
                      currentWorkspace.role === 'admin'
                        ? 'purple'
                        : currentWorkspace.role === 'workspace_manager'
                          ? 'blue'
                          : 'gray'
                    }
                  >
                    {currentWorkspace.role}
                  </Badge>
                )}
                {isAdmin && currentWorkspace && !renaming && (
                  <IconButton
                    icon={<FiEdit2 />}
                    size='sm'
                    variant='ghost'
                    aria-label='Rename workspace'
                    onClick={() => {
                      setRenameValue(currentWorkspace.name);
                      setRenaming(true);
                    }}
                  />
                )}
              </HStack>
              {renaming && (
                <HStack spacing={2} mb={4}>
                  <Input
                    size='sm'
                    maxW='300px'
                    value={renameValue}
                    onChange={e => setRenameValue(e.target.value)}
                    placeholder='New workspace name'
                    onKeyDown={async e => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        const trimmed = renameValue.trim();
                        if (!trimmed || trimmed === currentWorkspace.name) {
                          setRenaming(false);
                          return;
                        }
                        setRenameSaving(true);
                        try {
                          await workspaceAPI.rename(
                            currentWorkspace.id,
                            trimmed
                          );
                          setCurrentWorkspace(prev => ({
                            ...prev,
                            name: trimmed,
                          }));
                          setWorkspaces(prev =>
                            prev.map(w =>
                              w.id === currentWorkspace.id
                                ? { ...w, name: trimmed }
                                : w
                            )
                          );
                          setRenaming(false);
                          try {
                            window.dispatchEvent(
                              new CustomEvent('tt:workspaces-updated')
                            );
                          } catch (_) {}
                        } catch (err) {
                          showError(
                            err?.response?.data?.error ||
                              'Failed to rename workspace'
                          );
                        } finally {
                          setRenameSaving(false);
                        }
                      } else if (e.key === 'Escape') {
                        setRenaming(false);
                      }
                    }}
                    autoFocus
                  />
                  <IconButton
                    icon={<FiCheck />}
                    size='sm'
                    colorScheme='green'
                    aria-label='Confirm rename'
                    isLoading={renameSaving}
                    onClick={async () => {
                      const trimmed = renameValue.trim();
                      if (!trimmed || trimmed === currentWorkspace.name) {
                        setRenaming(false);
                        return;
                      }
                      setRenameSaving(true);
                      try {
                        await workspaceAPI.rename(currentWorkspace.id, trimmed);
                        setCurrentWorkspace(prev => ({
                          ...prev,
                          name: trimmed,
                        }));
                        setWorkspaces(prev =>
                          prev.map(w =>
                            w.id === currentWorkspace.id
                              ? { ...w, name: trimmed }
                              : w
                          )
                        );
                        setRenaming(false);
                        try {
                          window.dispatchEvent(
                            new CustomEvent('tt:workspaces-updated')
                          );
                        } catch (_) {}
                      } catch (err) {
                        showError(
                          err?.response?.data?.error ||
                            'Failed to rename workspace'
                        );
                      } finally {
                        setRenameSaving(false);
                      }
                    }}
                  />
                  <IconButton
                    icon={<FiX />}
                    size='sm'
                    variant='ghost'
                    aria-label='Cancel rename'
                    onClick={() => setRenaming(false)}
                  />
                </HStack>
              )}

              {currentWorkspace && (
                <HStack spacing={3} mb={4} flexWrap='wrap'>
                  {isAdmin && (
                    <Button
                      colorScheme='red'
                      variant='outline'
                      isLoading={deleting}
                      onClick={() => {
                        setDeleteConfirmName('');
                        setConfirmOpen(true);
                      }}
                    >
                      Delete workspace
                    </Button>
                  )}
                  {/* Transfer Tokens button: admin only */}
                  {currentWorkspace.role === 'admin' && (
                    <Button
                      colorScheme='blue'
                      onClick={async () => {
                        // Load tokens for current "from" workspace
                        const fromId = currentWorkspace.id;
                        const toId =
                          workspaces.find(w => w.id !== fromId)?.id || '';
                        setTransferOpen(true);
                        setTransferState(prev => ({
                          ...prev,
                          fromId,
                          toId,
                          loading: true,
                          search: '',
                          selected: new Set(),
                          categories: [],
                          sections: [],
                          tokens: [],
                        }));
                        try {
                          await fetchAllTokensForWorkspace(fromId);
                        } catch (_) {
                          setTransferState(prev => ({
                            ...prev,
                            loading: false,
                          }));
                        }
                      }}
                    >
                      Transfer tokens
                    </Button>
                  )}
                </HStack>
              )}

              <Text fontSize='sm' color={muted} mb={3}>
                Workspace roles are viewer or manager. System admins
                (installation-wide, System Settings access) can be granted
                below; that is separate from workspace manager.
              </Text>

              <HStack spacing={3} mb={4} flexWrap='wrap'>
                <Input
                  placeholder='Invite by email'
                  value={inviteEmail}
                  onChange={e => setInviteEmail(e.target.value)}
                  isDisabled={!canManage}
                  flex='1'
                  minW='200px'
                />
                <Select
                  value={inviteRole}
                  onChange={e => setInviteRole(e.target.value)}
                  maxW={{ base: '100%', sm: '220px' }}
                  isDisabled={!canManage}
                >
                  <option value='viewer'>Viewer</option>
                  <option value='workspace_manager'>Manager</option>
                </Select>
                <Button
                  onClick={async () => {
                    if (!currentWorkspace || !inviteEmail) return;
                    const email = inviteEmail.trim();
                    if (!/.+@.+\..+/.test(email)) {
                      showWarning('Invalid email');
                      return;
                    }
                    await workspaceAPI.inviteMember(currentWorkspace.id, {
                      email,
                      role: inviteRole,
                    });
                    setInviteEmail('');
                    await reloadMembers(currentWorkspace.id);
                    await reloadInvitations(currentWorkspace.id);
                  }}
                  isDisabled={!canManage}
                >
                  Invite
                </Button>
              </HStack>

              <Box overflowX='auto' display={{ base: 'none', md: 'block' }}>
                <Table size='sm' minW='600px'>
                  <Thead>
                    <Tr>
                      <Th>Name</Th>
                      <Th>Email</Th>
                      <Th>Workspace role</Th>
                      {isSystemAdmin ? <Th>System admin</Th> : null}
                      <Th></Th>
                    </Tr>
                  </Thead>
                  <Tbody>
                    {members.map(m => (
                      <Tr key={m.user_id}>
                        <Td>{m.display_name}</Td>
                        <Td>{m.email}</Td>
                        <Td>
                          {m.role === 'admin' ? (
                            <Badge colorScheme='purple'>
                              {MEMBER_ROLE_LABELS.admin}
                            </Badge>
                          ) : (
                            <Select
                              size='sm'
                              maxW={{ base: '180px', md: 'unset' }}
                              value={m.role}
                              isDisabled={
                                !canManage || m.user_id === session?.id
                              }
                              onChange={async e => {
                                if (!currentWorkspace) return;
                                const nextRole = e.target.value;
                                if (
                                  currentWorkspace.role !== 'admin' &&
                                  currentWorkspace.role !== 'workspace_manager'
                                ) {
                                  showWarning(
                                    'Insufficient permissions',
                                    'Only workspace admins or managers can change member roles.'
                                  );
                                  return;
                                }
                                if (m.user_id === session?.id) {
                                  showWarning(
                                    'Action not allowed',
                                    'You cannot change your own role.'
                                  );
                                  return;
                                }
                                await workspaceAPI.changeRole(
                                  currentWorkspace.id,
                                  m.user_id,
                                  nextRole
                                );
                                await reloadMembers(currentWorkspace.id);
                              }}
                            >
                              {MEMBER_ROLE_OPTIONS.map(opt => (
                                <option key={opt.value} value={opt.value}>
                                  {opt.label}
                                </option>
                              ))}
                            </Select>
                          )}
                        </Td>
                        {isSystemAdmin ? (
                          <Td>
                            <Switch
                              size='sm'
                              isChecked={m.is_admin === true}
                              isDisabled={m.user_id === session?.id}
                              onChange={async e => {
                                try {
                                  await adminAPI.setSystemAdmin(
                                    m.user_id,
                                    e.target.checked
                                  );
                                  await reloadMembers(currentWorkspace.id);
                                } catch (err) {
                                  showError(
                                    'Failed to update system admin',
                                    err.message
                                  );
                                }
                              }}
                            />
                          </Td>
                        ) : null}
                        <Td>
                          <Button
                            size='sm'
                            variant='outline'
                            onClick={() =>
                              openWorkspaceActionConfirm('remove-member', {
                                member: m,
                              })
                            }
                            isDisabled={
                              m.role === 'admin' ||
                              (currentWorkspace?.role !== 'admin' &&
                                m.role === 'admin') ||
                              (currentWorkspace?.role !== 'admin' &&
                                m.user_id === session?.id)
                            }
                          >
                            Remove
                          </Button>
                        </Td>
                      </Tr>
                    ))}
                  </Tbody>
                </Table>
              </Box>
              <VStack
                display={{ base: 'flex', md: 'none' }}
                align='stretch'
                spacing={3}
              >
                {members.map(m => (
                  <Box
                    key={`${m.user_id}-card`}
                    border='1px solid'
                    borderColor={border}
                    borderRadius='md'
                    bg={mobileCardBg}
                    p={4}
                  >
                    <VStack align='stretch' spacing={3}>
                      <Box>
                        <Text fontWeight='semibold' noOfLines={2}>
                          {m.display_name || m.email}
                        </Text>
                        <Text fontSize='sm' color={muted} wordBreak='break-all'>
                          {m.email}
                        </Text>
                      </Box>
                      <Box>
                        <Text fontSize='xs' color={muted} mb={1}>
                          Workspace role
                        </Text>
                        {m.role === 'admin' ? (
                          <Badge colorScheme='purple'>
                            {MEMBER_ROLE_LABELS.admin}
                          </Badge>
                        ) : (
                          <Select
                            size='sm'
                            value={m.role}
                            isDisabled={!canManage || m.user_id === session?.id}
                            onChange={async e => {
                              if (!currentWorkspace) return;
                              const nextRole = e.target.value;
                              if (
                                currentWorkspace.role !== 'admin' &&
                                currentWorkspace.role !== 'workspace_manager'
                              ) {
                                showWarning(
                                  'Insufficient permissions',
                                  'Only workspace admins or managers can change member roles.'
                                );
                                return;
                              }
                              if (m.user_id === session?.id) {
                                showWarning(
                                  'Action not allowed',
                                  'You cannot change your own role.'
                                );
                                return;
                              }
                              await workspaceAPI.changeRole(
                                currentWorkspace.id,
                                m.user_id,
                                nextRole
                              );
                              await reloadMembers(currentWorkspace.id);
                            }}
                          >
                            {MEMBER_ROLE_OPTIONS.map(opt => (
                              <option key={opt.value} value={opt.value}>
                                {opt.label}
                              </option>
                            ))}
                          </Select>
                        )}
                      </Box>
                      {isSystemAdmin ? (
                        <HStack justify='space-between'>
                          <Text fontSize='sm' color={muted}>
                            System admin
                          </Text>
                          <Switch
                            size='sm'
                            isChecked={m.is_admin === true}
                            isDisabled={m.user_id === session?.id}
                            onChange={async e => {
                              try {
                                await adminAPI.setSystemAdmin(
                                  m.user_id,
                                  e.target.checked
                                );
                                await reloadMembers(currentWorkspace.id);
                              } catch (err) {
                                showError(
                                  'Failed to update system admin',
                                  err.message
                                );
                              }
                            }}
                          />
                        </HStack>
                      ) : null}
                      <Button
                        size='sm'
                        variant='outline'
                        alignSelf='flex-start'
                        onClick={() =>
                          openWorkspaceActionConfirm('remove-member', {
                            member: m,
                          })
                        }
                        isDisabled={
                          m.role === 'admin' ||
                          (currentWorkspace?.role !== 'admin' &&
                            m.role === 'admin') ||
                          (currentWorkspace?.role !== 'admin' &&
                            m.user_id === session?.id)
                        }
                      >
                        Remove
                      </Button>
                    </VStack>
                  </Box>
                ))}
              </VStack>

              {pendingInvitations.length > 0 && (
                <Box mt={6}>
                  <Text fontWeight='semibold' mb={2}>
                    Pending invitations ({pendingInvitations.length})
                  </Text>
                  <Text fontSize='sm' color={muted} mb={3}>
                    Invitations that have not yet been accepted. They count
                    toward your workspace member cap when one is configured.
                  </Text>
                  <Box overflowX='auto' display={{ base: 'none', md: 'block' }}>
                    <Table size='sm' minW='600px'>
                      <Thead>
                        <Tr>
                          <Th>Email</Th>
                          <Th>Role</Th>
                          <Th>Sent</Th>
                          <Th></Th>
                        </Tr>
                      </Thead>
                      <Tbody>
                        {pendingInvitations.map(inv => (
                          <Tr key={inv.id}>
                            <Td>{inv.email}</Td>
                            <Td>{inv.role}</Td>
                            <Td>
                              {inv.created_at
                                ? new Date(inv.created_at).toLocaleString()
                                : ''}
                            </Td>
                            <Td>
                              <Button
                                size='sm'
                                variant='outline'
                                isDisabled={!canManage}
                                onClick={() =>
                                  openWorkspaceActionConfirm('cancel-invite', {
                                    invitation: inv,
                                  })
                                }
                              >
                                Cancel invite
                              </Button>
                            </Td>
                          </Tr>
                        ))}
                      </Tbody>
                    </Table>
                  </Box>
                  <VStack
                    display={{ base: 'flex', md: 'none' }}
                    align='stretch'
                    spacing={3}
                  >
                    {pendingInvitations.map(inv => (
                      <Box
                        key={`${inv.id}-card`}
                        border='1px solid'
                        borderColor={border}
                        borderRadius='md'
                        bg={mobileCardBg}
                        p={4}
                      >
                        <VStack align='stretch' spacing={3}>
                          <Box>
                            <Text fontWeight='semibold' wordBreak='break-all'>
                              {inv.email}
                            </Text>
                            <Text fontSize='sm' color={muted}>
                              {inv.role}
                            </Text>
                          </Box>
                          <Box>
                            <Text fontSize='xs' color={muted}>
                              Sent
                            </Text>
                            <Text fontSize='sm'>
                              {inv.created_at
                                ? new Date(inv.created_at).toLocaleString()
                                : ''}
                            </Text>
                          </Box>
                          <Button
                            size='sm'
                            variant='outline'
                            alignSelf='flex-start'
                            isDisabled={!canManage}
                            onClick={() =>
                              openWorkspaceActionConfirm('cancel-invite', {
                                invitation: inv,
                              })
                            }
                          >
                            Cancel invite
                          </Button>
                        </VStack>
                      </Box>
                    ))}
                  </VStack>
                </Box>
              )}
            </DashboardPanel>
          </VStack>
        )}
      </DashboardPageLayout>

      <WorkspaceActionConfirmModal
        isOpen={Boolean(workspaceActionConfirm)}
        action={workspaceActionConfirm}
        isLoading={workspaceActionSubmitting}
        onClose={closeWorkspaceActionConfirm}
        onConfirm={confirmWorkspaceAction}
      />

      {/* Transfer Modal */}
      <AlertDialog
        isOpen={transferOpen}
        leastDestructiveRef={cancelRef}
        onClose={() => setTransferOpen(false)}
        isCentered
        scrollBehavior='inside'
        size='6xl'
      >
        <AlertDialogOverlay {...overlayProps} />
        <AlertDialogContent
          {...contentProps}
          maxW={{ base: 'calc(100vw - 24px)', xl: '1100px' }}
          maxH={{ base: 'calc(100dvh - 24px)', md: 'calc(100dvh - 64px)' }}
          display='flex'
          flexDirection='column'
        >
          <AlertDialogHeader {...headerProps}>
            <DashboardModalTitle color={modalTokens.text}>
              Transfer Tokens
            </DashboardModalTitle>
            <DashboardModalDescription>
              Move selected assets from one workspace to another.
            </DashboardModalDescription>
          </AlertDialogHeader>
          <AlertDialogBody {...bodyProps} flex='1' minH={0} overflow='hidden'>
            <VStack align='stretch' spacing={4} h='100%' minH={0}>
              <HStack
                align='flex-end'
                flexWrap={{ base: 'wrap', md: 'nowrap' }}
                spacing={3}
              >
                <Box flex={{ base: '1 1 100%', md: '1 1 0' }} minW={0}>
                  <Text fontWeight='semibold' mb={1}>
                    From workspace
                  </Text>
                  <Select
                    value={transferState.fromId}
                    onChange={async e => {
                      const fromId = e.target.value;
                      const toId =
                        transferState.toId && transferState.toId !== fromId
                          ? transferState.toId
                          : workspaces.find(w => w.id !== fromId)?.id || '';
                      setTransferState(prev => ({
                        ...prev,
                        fromId,
                        toId,
                        loading: true,
                        tokens: [],
                        selected: new Set(),
                        categories: [],
                        sections: [],
                      }));
                      try {
                        await fetchAllTokensForWorkspace(fromId);
                      } catch (_) {
                        setTransferState(prev => ({ ...prev, loading: false }));
                      }
                    }}
                  >
                    {workspaces.map(w => (
                      <option key={w.id} value={w.id}>
                        {w.name}
                      </option>
                    ))}
                  </Select>
                </Box>
                <Box flex={{ base: '1 1 100%', md: '1 1 0' }} minW={0}>
                  <Text fontWeight='semibold' mb={1}>
                    To workspace
                  </Text>
                  <Select
                    value={transferState.toId}
                    onChange={e =>
                      setTransferState(prev => ({
                        ...prev,
                        toId: e.target.value,
                      }))
                    }
                  >
                    {workspaces
                      .filter(w => w.id !== transferState.fromId)
                      .map(w => (
                        <option key={w.id} value={w.id}>
                          {w.name}
                        </option>
                      ))}
                  </Select>
                </Box>
              </HStack>

              <HStack
                align='flex-end'
                flexWrap={{ base: 'wrap', lg: 'nowrap' }}
                spacing={3}
              >
                <Input
                  placeholder='Search by name'
                  value={transferState.search}
                  onChange={e =>
                    setTransferState(prev => ({
                      ...prev,
                      search: e.target.value,
                    }))
                  }
                  flex={{ base: '1 1 100%', lg: '1.3 1 0' }}
                  minW={{ base: '100%', lg: '260px' }}
                />
                <Select
                  placeholder='Filter by category'
                  onChange={e =>
                    setTransferState(prev => ({
                      ...prev,
                      filterCategory: e.target.value || null,
                    }))
                  }
                  flex={{
                    base: '1 1 100%',
                    md: '1 1 calc(50% - 6px)',
                    lg: '1 1 0',
                  }}
                  minW={{ base: '100%', md: '220px', lg: '180px' }}
                >
                  {transferState.categories.map(c => (
                    <option key={c} value={c}>
                      {c}
                    </option>
                  ))}
                </Select>
                <Select
                  placeholder='Filter by section'
                  onChange={e =>
                    setTransferState(prev => ({
                      ...prev,
                      filterSection: e.target.value || null,
                    }))
                  }
                  flex={{
                    base: '1 1 100%',
                    md: '1 1 calc(50% - 6px)',
                    lg: '1 1 0',
                  }}
                  minW={{ base: '100%', md: '220px', lg: '180px' }}
                >
                  {transferState.sections.map(s => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </Select>
              </HStack>

              <Box
                {...fieldProps}
                borderRadius='0'
                maxH={{ base: '320px', md: '420px' }}
                overflowX='auto'
                overflowY='auto'
              >
                <Table size='sm'>
                  <Thead>
                    <Tr>
                      <Th width='40px'>
                        <Checkbox
                          colorScheme='blue'
                          isChecked={(() => {
                            const filtered = (
                              transferState.tokens || []
                            ).filter(t => {
                              const nameMatch = transferState.search
                                ? (t.name || '')
                                    .toLowerCase()
                                    .includes(
                                      transferState.search.toLowerCase()
                                    )
                                : true;
                              const catMatch = transferState.filterCategory
                                ? t.category === transferState.filterCategory
                                : true;
                              const secMatch = transferState.filterSection
                                ? Array.isArray(t.section)
                                  ? t.section.includes(
                                      transferState.filterSection
                                    )
                                  : false
                                : true;
                              return nameMatch && catMatch && secMatch;
                            });
                            return (
                              filtered.length > 0 &&
                              transferState.selected.size === filtered.length
                            );
                          })()}
                          isIndeterminate={(() => {
                            const filtered = (
                              transferState.tokens || []
                            ).filter(t => {
                              const nameMatch = transferState.search
                                ? (t.name || '')
                                    .toLowerCase()
                                    .includes(
                                      transferState.search.toLowerCase()
                                    )
                                : true;
                              const catMatch = transferState.filterCategory
                                ? t.category === transferState.filterCategory
                                : true;
                              const secMatch = transferState.filterSection
                                ? Array.isArray(t.section)
                                  ? t.section.includes(
                                      transferState.filterSection
                                    )
                                  : false
                                : true;
                              return nameMatch && catMatch && secMatch;
                            });
                            return (
                              transferState.selected.size > 0 &&
                              transferState.selected.size < filtered.length
                            );
                          })()}
                          onChange={e => {
                            const { checked } = e.target;
                            const filtered = (
                              transferState.tokens || []
                            ).filter(t => {
                              const nameMatch = transferState.search
                                ? (t.name || '')
                                    .toLowerCase()
                                    .includes(
                                      transferState.search.toLowerCase()
                                    )
                                : true;
                              const catMatch = transferState.filterCategory
                                ? t.category === transferState.filterCategory
                                : true;
                              const secMatch = transferState.filterSection
                                ? Array.isArray(t.section)
                                  ? t.section.includes(
                                      transferState.filterSection
                                    )
                                  : false
                                : true;
                              return nameMatch && catMatch && secMatch;
                            });
                            setTransferState(prev => ({
                              ...prev,
                              selected: checked
                                ? new Set(filtered.map(t => t.id))
                                : new Set(),
                            }));
                          }}
                        />
                      </Th>
                      <Th>Name</Th>
                      <Th>Category</Th>
                      <Th>Type</Th>
                      <Th>Section</Th>
                    </Tr>
                  </Thead>
                  <Tbody>
                    {(transferState.tokens || [])
                      .filter(t => {
                        const nameMatch = transferState.search
                          ? (t.name || '')
                              .toLowerCase()
                              .includes(transferState.search.toLowerCase())
                          : true;
                        const catMatch = transferState.filterCategory
                          ? t.category === transferState.filterCategory
                          : true;
                        const secMatch = transferState.filterSection
                          ? Array.isArray(t.section)
                            ? t.section.includes(transferState.filterSection)
                            : false
                          : true;
                        return nameMatch && catMatch && secMatch;
                      })
                      .map(t => (
                        <Tr key={t.id}>
                          <Td>
                            <Checkbox
                              colorScheme='blue'
                              isChecked={transferState.selected.has(t.id)}
                              onChange={e => {
                                const { checked } = e.target;
                                setTransferState(prev => {
                                  const next = new Set(prev.selected);
                                  if (checked) next.add(t.id);
                                  else next.delete(t.id);
                                  return { ...prev, selected: next };
                                });
                              }}
                            />
                          </Td>
                          <Td>{t.name}</Td>
                          <Td>{t.category}</Td>
                          <Td>{t.type}</Td>
                          <Td>
                            {Array.isArray(t.section)
                              ? t.section.join(', ')
                              : t.section || ''}
                          </Td>
                        </Tr>
                      ))}
                    {transferState.tokens.length === 0 && (
                      <Tr>
                        <Td colSpan={5}>
                          <Text textAlign='center' py={4}>
                            No tokens found.
                          </Text>
                        </Td>
                      </Tr>
                    )}
                  </Tbody>
                </Table>
              </Box>
            </VStack>
          </AlertDialogBody>
          <AlertDialogFooter {...footerProps}>
            <HStack w='full' justify='flex-end' flexWrap='wrap' spacing={3}>
              <Button
                ref={cancelRef}
                onClick={() => setTransferOpen(false)}
                {...outlineButtonProps}
              >
                Close
              </Button>
              <Button
                {...primaryButtonProps}
                isDisabled={
                  !transferState.fromId ||
                  !transferState.toId ||
                  transferState.fromId === transferState.toId ||
                  transferState.selected.size === 0
                }
                onClick={async () => {
                  try {
                    // Safety: only transfer currently visible selections
                    const visible = (transferState.tokens || []).filter(t => {
                      const nameMatch = transferState.search
                        ? (t.name || '')
                            .toLowerCase()
                            .includes(transferState.search.toLowerCase())
                        : true;
                      const catMatch = transferState.filterCategory
                        ? t.category === transferState.filterCategory
                        : true;
                      const secMatch = transferState.filterSection
                        ? Array.isArray(t.section)
                          ? t.section.includes(transferState.filterSection)
                          : false
                        : true;
                      return nameMatch && catMatch && secMatch;
                    });
                    const visibleIds = new Set(visible.map(t => t.id));
                    const ids = Array.from(
                      transferState.selected.values()
                    ).filter(id => visibleIds.has(id));
                    await workspaceAPI.transferTokens(
                      transferState.toId,
                      transferState.fromId,
                      ids
                    );
                    // Refresh list for fromId
                    await fetchAllTokensForWorkspace(transferState.fromId);
                    setTransferState(prev => ({
                      ...prev,
                      selected: new Set(),
                    }));
                    try {
                      window.dispatchEvent(
                        new CustomEvent('tt:tokens-updated')
                      );
                    } catch (_) {}
                  } catch (_) {}
                }}
              >
                Transfer selected
              </Button>
            </HStack>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      <AlertDialog
        isOpen={confirmOpen}
        leastDestructiveRef={cancelRef}
        onClose={() => {
          setConfirmOpen(false);
          setDeleteConfirmName('');
        }}
        isCentered
        scrollBehavior='inside'
      >
        <AlertDialogOverlay {...overlayProps} />
        <AlertDialogContent
          {...contentProps}
          maxW={{ base: 'calc(100vw - 24px)', md: '560px' }}
        >
          <AlertDialogHeader {...headerProps}>
            <DashboardModalTitle color={modalTokens.text}>
              Delete this workspace?
            </DashboardModalTitle>
            <DashboardModalDescription>
              Confirm the workspace name before deleting it permanently.
            </DashboardModalDescription>
          </AlertDialogHeader>
          <AlertDialogBody {...bodyProps}>
            <VStack align='stretch' spacing={4}>
              <Box {...fieldProps} p={4}>
                <Text color={modalTokens.subtleText} fontSize='sm'>
                  This action is irreversible. It will delete all tokens,
                  alerts, and data associated with this workspace.
                </Text>
              </Box>
              <Box>
                <Text
                  fontSize='sm'
                  fontWeight='semibold'
                  color={modalTokens.muted}
                  mb={2}
                >
                  Type the workspace name to confirm
                </Text>
                <Input
                  value={deleteConfirmName}
                  placeholder={currentWorkspace?.name}
                  onChange={e => setDeleteConfirmName(e.target.value)}
                />
              </Box>
            </VStack>
          </AlertDialogBody>
          <AlertDialogFooter {...footerProps}>
            <HStack w='full' justify='flex-end' flexWrap='wrap' spacing={3}>
              <Button
                ref={cancelRef}
                onClick={() => {
                  setConfirmOpen(false);
                  setDeleteConfirmName('');
                }}
                {...outlineButtonProps}
              >
                Cancel
              </Button>
              <Button
                {...dangerButtonProps}
                isLoading={deleting}
                onClick={async () => {
                  if (!currentWorkspace) return;
                  const typed = deleteConfirmName || '';
                  if (typed.trim() !== (currentWorkspace.name || '').trim()) {
                    showWarning(
                      'Name mismatch',
                      'Please type the exact workspace name to confirm.'
                    );
                    return;
                  }
                  try {
                    setDeleting(true);
                    await workspaceAPI.remove(currentWorkspace.id);
                    const ws = await workspaceAPI.list(50, 0);
                    const items = ws?.items || [];
                    setWorkspaces(items);
                    const next = items[0] || null;
                    setCurrentWorkspace(next);
                    if (next) {
                      selectWorkspace(next.id, { replace: true });
                      const res = await workspaceAPI.listMembers(
                        next.id,
                        100,
                        0
                      );
                      setMembers(res?.items || []);
                      await reloadInvitations(next.id);
                    } else {
                      setMembers([]);
                      setPendingInvitations([]);
                    }
                    try {
                      window.dispatchEvent(
                        new CustomEvent('tt:workspaces-updated', {
                          detail: { deletedId: currentWorkspace.id },
                        })
                      );
                    } catch (_) {}
                    setConfirmOpen(false);
                    setDeleteConfirmName('');
                  } catch (e) {
                    const msg = String(e?.message || '').toUpperCase();
                    if (msg.includes('PERSONAL_DEFAULT')) {
                      showWarning(
                        'Cannot delete personal workspace',
                        'Your default personal workspace cannot be deleted.'
                      );
                    } else {
                      showError(e?.message || 'Failed to delete workspace');
                    }
                  } finally {
                    setDeleting(false);
                  }
                }}
              >
                Delete
              </Button>
            </HStack>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
