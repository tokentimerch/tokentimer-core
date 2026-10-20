import { useCallback, useEffect, useRef, useState } from 'react';
import { FiRefreshCw } from 'react-icons/fi';
import {
  AlertDialog,
  AlertDialogBody,
  AlertDialogContent,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogOverlay,
  Badge,
  Box,
  Flex,
  HStack,
  Spinner,
  Text,
  VStack,
} from '@chakra-ui/react';
import {
  DashboardActionButton,
  DashboardErrorAlert,
} from '../DashboardPrimitives';
import {
  DashboardModalDescription,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import {
  useDashboardTheme,
  useDashboardThemeColors,
} from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';
import GroupEditor from './alertGroupEditor.jsx';
import { describeGroup } from './alertGroups.js';
import {
  describeSetupUse,
  groupReaches,
  planGroupDelete,
  usesDefaultOnly,
} from './alertGroupUsage.js';
import { onboardingActions } from '../../utils/onboardingActions.js';

const CREATE_HELP =
  'Creating a group does not send alerts to it until it is the default or is selected on an asset.';

function makeReaches(settings, contacts) {
  const emailIds = new Set(
    contacts.filter(c => c.details?.email).map(c => String(c.id))
  );
  const webhookNames = new Set(
    (settings.webhook_urls || []).filter(w => w?.name).map(w => w.name)
  );
  return group => groupReaches(group, webhookNames, emailIds);
}

function UsedForSetup({ use }) {
  const { muted } = useDashboardTheme();
  const { dashboard } = useDashboardThemeColors();
  return (
    <Box
      data-testid='used-for-setup'
      borderWidth='1px'
      borderColor={dashboard.accent.interactiveBorder}
      bg={dashboard.accent.interactiveSurface}
      borderRadius='md'
      p={3}
    >
      <Text as='h3' fontSize='sm' fontWeight='bold' mb={1}>
        Used for this setup
      </Text>
      <VStack align='stretch' spacing={1}>
        {use.lines.map(line => (
          <Text key={line} fontSize='sm' color={muted}>
            {line}
          </Text>
        ))}
        {use.warning ? (
          <Text fontSize='sm' color={dashboard.callout.warningText}>
            {use.warning}
          </Text>
        ) : null}
      </VStack>
    </Box>
  );
}

function DeleteDialog({ target, defaultName, busy, onCancel, onConfirm }) {
  const cancelRef = useRef(null);
  const {
    overlayProps,
    contentProps,
    headerProps,
    bodyProps,
    footerProps,
    tokens,
    outlineButtonProps,
    dangerButtonProps,
  } = useDashboardModalProps();
  const name = target?.group.name;
  return (
    <AlertDialog
      isOpen={Boolean(target)}
      leastDestructiveRef={cancelRef}
      onClose={busy ? () => {} : onCancel}
      isCentered
      scrollBehavior='inside'
    >
      <AlertDialogOverlay {...overlayProps} />
      <AlertDialogContent
        {...contentProps}
        maxW={{ base: 'calc(100vw - 24px)', md: '560px' }}
      >
        <AlertDialogHeader {...headerProps}>
          <DashboardModalTitle color={tokens.text}>
            {`Delete the group "${name}"?`}
          </DashboardModalTitle>
          <DashboardModalDescription>
            This removes it from the workspace for good.
          </DashboardModalDescription>
        </AlertDialogHeader>
        <AlertDialogBody {...bodyProps}>
          <VStack align='stretch' spacing={2}>
            <Text color={tokens.subtleText}>
              Assets and websites that use it will use the default group
              {defaultName ? ` "${defaultName}"` : ''} instead.
            </Text>
            <Text color={tokens.subtleText}>This cannot be undone.</Text>
          </VStack>
        </AlertDialogBody>
        <AlertDialogFooter {...footerProps}>
          <Flex
            w='100%'
            gap={3}
            justify={{ base: 'stretch', sm: 'flex-end' }}
            direction={{ base: 'column-reverse', sm: 'row' }}
          >
            <DashboardActionButton
              ref={cancelRef}
              onClick={onCancel}
              isDisabled={busy}
              minW={{ base: '100%', sm: 'auto' }}
              {...outlineButtonProps}
            >
              Cancel
            </DashboardActionButton>
            <DashboardActionButton
              {...dangerButtonProps}
              isLoading={busy}
              minW={{ base: '100%', sm: 'auto' }}
              onClick={onConfirm}
            >
              Delete group
            </DashboardActionButton>
          </Flex>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

export function RecipientsStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const { dashboard } = useDashboardThemeColors();
  const [state, setState] = useState({ loading: true });
  // null = list, 'new' = create, otherwise the group being edited
  const [editing, setEditing] = useState(null);
  const [error, setError] = useState('');
  const [pendingDelete, setPendingDelete] = useState(null);
  const [deleting, setDeleting] = useState(false);
  const load = useCallback(async () => {
    try {
      const [settings, contacts] = await Promise.all([
        onboardingActions.getAlertSettings(ctx.workspaceId),
        onboardingActions.listContacts(ctx.workspaceId),
      ]);
      setState({ loading: false, settings, contacts });
      return { settings, contacts };
    } catch (e) {
      setState({ loading: false, error: e.message });
      return null;
    }
  }, [ctx.workspaceId]);

  useEffect(() => {
    load();
  }, [load]);

  const afterSave = async () => {
    setEditing(null);
    await load();
    await ctx.refresh();
  };

  const makeDefault = async group => {
    setError('');
    try {
      await onboardingActions.putAlertSettings(ctx.workspaceId, {
        default_contact_group_id: group.id,
      });
      await afterSave();
    } catch (e) {
      setError(e.message);
    }
  };

  const confirmDelete = async () => {
    const { id } = pendingDelete.group;
    setDeleting(true);
    setError('');
    try {
      // Decide from the live settings, not the page: another tab may have
      // changed the list since it was drawn.
      const fresh = await onboardingActions.getAlertSettings(ctx.workspaceId);
      const live = (fresh.contact_groups || []).find(
        g => String(g.id) === String(id)
      );
      if (live) {
        const plan = planGroupDelete({
          group: live,
          groups: fresh.contact_groups,
          defaultId: fresh.default_contact_group_id,
        });
        if (!plan.allowed) throw new Error(plan.reason);
        // Only the list changes; the default group is left exactly as it is.
        await onboardingActions.putAlertSettings(ctx.workspaceId, {
          contact_groups: plan.remaining,
        });
        // Read back to confirm the group is really gone.
        const after = await onboardingActions.getAlertSettings(ctx.workspaceId);
        const stillThere = (after.contact_groups || []).some(
          g => String(g.id) === String(id)
        );
        if (stillThere) throw new Error('The group could not be deleted.');
      }
      setPendingDelete(null);
      await afterSave();
    } catch (e) {
      setPendingDelete(null);
      setError(e.message || 'Could not delete the group.');
      await load();
    } finally {
      setDeleting(false);
    }
  };

  const skip = async () => {
    await ctx.skip('recipients');
  };

  const docs = [
    ...ctx.docs('alerts.contactGroups', 'Contact groups'),
    ...ctx.docs('quickstart.recipients', 'Choosing recipients'),
  ];

  if (state.loading) {
    return (
      <StepFrame kind='ui' title='Choose who gets alerted'>
        <Spinner size='sm' />
      </StepFrame>
    );
  }
  if (state.error) {
    return (
      <StepFrame kind='ui' title='Choose who gets alerted' docs={docs}>
        <DashboardErrorAlert>{state.error}</DashboardErrorAlert>
        <DashboardActionButton
          leftIcon={<FiRefreshCw />}
          mt={3}
          variant='outline'
          onClick={load}
        >
          Try again
        </DashboardActionButton>
      </StepFrame>
    );
  }

  const { settings, contacts } = state;
  const groups = Array.isArray(settings.contact_groups)
    ? settings.contact_groups
    : [];
  const defaultId = String(settings.default_contact_group_id || '');
  const reaches = makeReaches(settings, contacts);
  const defaultGroup = groups.find(g => String(g.id) === defaultId);
  const defaultReaches = defaultGroup ? reaches(defaultGroup) : false;
  const goal = ctx.session?.intent?.goal;

  if (editing) {
    const group = editing === 'new' ? null : editing;
    return (
      <StepFrame
        kind='ui'
        title={group ? `Edit ${group.name}` : 'Create a contact group'}
        description={
          group || groups.length === 0
            ? 'Alerts go to the people and webhooks in a group. You can add Slack, Teams, Discord or PagerDuty, set custom alert days, and a weekly digest.'
            : `Alerts go to the people and webhooks in a group. You can add Slack, Teams, Discord or PagerDuty, set custom alert days, and a weekly digest. ${CREATE_HELP}`
        }
        docs={docs}
      >
        <GroupEditor
          autoOpen
          ctx={ctx}
          settings={settings}
          contacts={contacts}
          group={group}
          makeDefault={!defaultReaches || defaultId === String(group?.id)}
          onSaved={afterSave}
          onCancel={() => setEditing(null)}
        />
      </StepFrame>
    );
  }

  if (groups.length === 0) {
    return (
      <StepFrame
        kind='ui'
        title='Choose who gets alerted'
        description='Alerts go to a contact group. Create one with the people and webhooks that should hear about expiring assets.'
        docs={docs}
        actions={
          <DashboardActionButton variant='outline' onClick={skip}>
            Skip for now
          </DashboardActionButton>
        }
      >
        <GroupEditor
          ctx={ctx}
          settings={settings}
          contacts={contacts}
          group={null}
          makeDefault
          onSaved={afterSave}
        />
      </StepFrame>
    );
  }

  // Assets and imports pick their own group in a form this step cannot see,
  // so only the goals that always use the default state a rule.
  const showUse = usesDefaultOnly(goal);
  const use = showUse
    ? describeSetupUse({ goal, groups, defaultId, defaultReaches })
    : null;
  const usedIds = new Set(use ? use.usedIds : []);
  const setupLabel = showUse ? 'Use for this setup' : 'Make default';

  return (
    <StepFrame
      kind='ui'
      title='Choose who gets alerted'
      description={
        showUse
          ? 'Alerts go to contact groups. First see which group this setup uses, then manage the groups in your workspace.'
          : 'Alerts go to contact groups. Manage the groups in your workspace here.'
      }
      docs={docs}
      actions={
        <DashboardActionButton variant='outline' onClick={skip}>
          Skip for now
        </DashboardActionButton>
      }
    >
      <VStack align='stretch' spacing={4}>
        {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
        {use ? <UsedForSetup use={use} /> : null}
        <VStack align='stretch' spacing={3} as='section'>
          <HStack
            justify='space-between'
            align='start'
            flexWrap='wrap'
            spacing={3}
          >
            <VStack align='start' spacing={0} minW={0} flex='1 1 240px'>
              <Text as='h3' fontSize='sm' fontWeight='bold'>
                Groups in this workspace
              </Text>
              <Text fontSize='xs' color={muted}>
                {CREATE_HELP}
              </Text>
            </VStack>
            <PrimaryButton size='sm' onClick={() => setEditing('new')}>
              Create a new group
            </PrimaryButton>
          </HStack>
          {groups.map(g => {
            const isDefault = String(g.id) === defaultId;
            const who = describeGroup(g, contacts);
            const plan = planGroupDelete({ group: g, groups, defaultId });
            const whyId = `delete-why-${g.id}`;
            return (
              <VStack
                key={g.id}
                data-testid={`group-${g.id}`}
                align='stretch'
                spacing={2}
                borderWidth='1px'
                borderColor={dashboard.border.subtle}
                borderRadius='md'
                p={3}
              >
                <HStack
                  justify='space-between'
                  align='start'
                  spacing={3}
                  flexWrap='wrap'
                >
                  <VStack align='start' spacing={0} minW={0}>
                    <HStack flexWrap='wrap'>
                      <Text fontSize='sm' fontWeight='semibold'>
                        {g.name}
                      </Text>
                      {isDefault ? (
                        <Badge colorScheme='blue'>Default</Badge>
                      ) : null}
                      {usedIds.has(String(g.id)) ? (
                        <Badge colorScheme='green'>Used for this setup</Badge>
                      ) : null}
                      {!reaches(g) ? (
                        <Badge colorScheme='orange'>Reaches nobody</Badge>
                      ) : null}
                    </HStack>
                    <Text fontSize='xs' color={muted}>
                      {who.length ? who.join(', ') : 'No recipients'}
                    </Text>
                  </VStack>
                  <HStack spacing={2} flexWrap='wrap'>
                    {!isDefault ? (
                      <DashboardActionButton
                        size='xs'
                        variant='outline'
                        title='Makes this the default group'
                        onClick={() => makeDefault(g)}
                      >
                        {setupLabel}
                      </DashboardActionButton>
                    ) : null}
                    <DashboardActionButton
                      size='xs'
                      variant='outline'
                      onClick={() => setEditing(g)}
                    >
                      Edit
                    </DashboardActionButton>
                    <DashboardActionButton
                      size='xs'
                      variant='outline'
                      colorScheme='red'
                      aria-label={`Delete ${g.name}`}
                      aria-describedby={plan.allowed ? undefined : whyId}
                      isDisabled={!plan.allowed}
                      onClick={() => setPendingDelete({ group: g, plan })}
                    >
                      Delete
                    </DashboardActionButton>
                  </HStack>
                </HStack>
                {!plan.allowed ? (
                  <Text id={whyId} fontSize='xs' color={muted}>
                    {`You cannot delete this group yet. ${plan.reason}`}
                  </Text>
                ) : null}
              </VStack>
            );
          })}
        </VStack>
      </VStack>
      <DeleteDialog
        target={pendingDelete}
        defaultName={defaultGroup?.name}
        busy={deleting}
        onCancel={() => setPendingDelete(null)}
        onConfirm={confirmDelete}
      />
    </StepFrame>
  );
}
