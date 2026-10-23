import { useCallback, useEffect, useRef, useState } from 'react';
import { FiRefreshCw } from 'react-icons/fi';
import {
  AlertDialog,
  AlertDialogBody,
  AlertDialogContent,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogOverlay,
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
import { ContinueHint } from './blocks.jsx';
import GroupEditor from './alertGroupEditor.jsx';
import { GroupRow } from './alertGroupRow.jsx';
import { describeGroup } from './alertGroups.js';
import { groupReaches, planGroupDelete } from './alertGroupUsage.js';
import {
  DEFAULT_ONLY_NOTE,
  canTickGoal,
  canContinueTicks,
  confirmsDefault,
  describeItemsCovered,
  describeNoToken,
  describeTicks,
  isDefaultOnlyGoal,
  recipientsSatisfied,
  summarizeItems,
  tickState,
} from './groupAttachment.js';
import { useSessionGroupTicks } from './useSessionGroupTicks.js';
import { useSummaryPolling } from './useSummaryPolling.js';
import { StatusPanel } from './panels.jsx';
import { onboardingActions } from '../../utils/onboardingActions.js';
import { useContactGroupPluralWrites } from '../../utils/contactGroupPluralWrites.jsx';

const CREATE_HELP =
  'Creating a group does not send alerts to it until it is the default or is selected on an asset.';

/**
 * What the ticks apply to: the first few items by name. One tick below
 * changes every one of them, so the list is only there to show what that is.
 */
function ItemsCovered({ items, goal }) {
  const { muted } = useDashboardTheme();
  const { shown, more } = summarizeItems(items);
  return (
    <VStack align='stretch' spacing={1} data-testid='tick-items'>
      <Text fontSize='sm' fontWeight='semibold'>
        {describeItemsCovered(items, goal)}
      </Text>
      <Text fontSize='xs' color={muted} data-testid='tick-item-names'>
        {shown.join(', ')}
        {more > 0 ? ` and ${more} more` : ''}
      </Text>
      {items.length > 1 ? (
        <Text fontSize='xs' color={muted}>
          A group you tick applies to all {items.length} of them at once.
        </Text>
      ) : null}
      {items.every(i => i.kind === 'asset') &&
      items.some(i => i.groupIds.length > 0) ? (
        <Text fontSize='xs' color={muted} data-testid='chosen-at-creation'>
          Groups you chose when you added an asset are already ticked.
        </Text>
      ) : null}
    </VStack>
  );
}

function makeReaches(settings, contacts) {
  const emailIds = new Set(
    contacts.filter(c => c.details?.email).map(c => String(c.id))
  );
  const webhookNames = new Set(
    (settings.webhook_urls || []).filter(w => w?.name).map(w => w.name)
  );
  return group => groupReaches(group, webhookNames, emailIds);
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

export function RecipientsStep({ ctx, reviewing = false }) {
  const { muted } = useDashboardTheme();
  const { dashboard } = useDashboardThemeColors();
  const [state, setState] = useState({ loading: true });
  // null = list, 'new' = create, otherwise the group being edited
  const [editing, setEditing] = useState(null);
  const [error, setError] = useState('');
  const [pendingDelete, setPendingDelete] = useState(null);
  const [deleting, setDeleting] = useState(false);
  const plural = useContactGroupPluralWrites();
  const ticks = useSessionGroupTicks({ ctx, plural });
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
    ticks.reload();
    await ctx.refresh();
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

  // Goals whose items carry no ticks (imports, alerting, observe) finish this
  // step by an explicit confirmation that belongs to the chosen goal. So do
  // the website and certificate goals while nothing exists yet that could
  // carry a group.
  const sessionGoal = ctx.session?.intent?.goal;
  const ticksGoal = Boolean(sessionGoal) && canTickGoal(sessionGoal);
  const needsConfirm =
    Boolean(sessionGoal) &&
    (!canTickGoal(sessionGoal) || confirmsDefault(sessionGoal, ticks.plan));
  // The step is always shown once and ends with an explicit Continue, even
  // when the items already carry the workspace default group.
  const stepDone = recipientsSatisfied({
    goal: sessionGoal,
    refs: ctx.session?.operationRefs,
    progress: ctx.session?.progress,
    reality: ctx.summary,
  });
  // A website gets its certificate record at its first check, so keep
  // reading while one is missing and the ticks will appear by themselves. The
  // same while the agent has not reported a certificate yet.
  useSummaryPolling(
    ctx.refresh,
    !reviewing &&
      ((sessionGoal === 'monitor_https' && ticks.noToken > 0) ||
        (sessionGoal === 'certops_observe' &&
          ticks.status === 'ready' &&
          ticks.items.length === 0))
  );
  const [confirming, setConfirming] = useState(false);
  // Writes the operator's confirmation for this goal. Idempotent, so a retry
  // or a second tab does no harm.
  const saveConfirmation = async () => {
    await ctx.controller.update(session => ({
      progress: { ...session.progress, recipientsConfirmedFor: sessionGoal },
    }));
    await ctx.refresh();
  };
  const confirm = async () => {
    setConfirming(true);
    setError('');
    try {
      await saveConfirmation();
    } catch (e) {
      setError(e.message || 'Could not save your choice.');
    } finally {
      setConfirming(false);
    }
  };
  // The ticks only say what is attached. Continue is the operator saying the
  // groups are right, so a group the product attached by default never ends
  // the step on its own.
  const canContinue = canContinueTicks({
    goal: sessionGoal,
    refs: ctx.session?.operationRefs,
    reality: ctx.summary,
    progress: ctx.session?.progress,
  });
  const goOn = async () => {
    setConfirming(true);
    setError('');
    try {
      // Release first: saving the confirmation is what finishes the step, and
      // the page must not hold it open as if it had finished by itself.
      ctx.release?.();
      if (!stepDone) await saveConfirmation();
    } catch (e) {
      setError(e.message || 'Could not save your choice.');
    } finally {
      setConfirming(false);
    }
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

  const canTick = ticks.status === 'ready' && ticks.items.length > 0;
  const existingIds = new Set(groups.map(g => String(g.id)));
  const defaultOnly = isDefaultOnlyGoal(goal);
  // The agent found nothing to carry a group yet: say so instead of showing
  // groups that tick nothing. Continuing is allowed, the default group applies.
  const nothingFound =
    goal === 'certops_observe' &&
    ticks.status === 'ready' &&
    ticks.items.length === 0 &&
    !ticks.noToken;
  const sentence =
    ticks.status === 'blocked' || defaultOnly
      ? ''
      : describeTicks({
          goal,
          items: ticks.items,
          defaultName: defaultGroup?.name,
          noToken: ticks.noToken,
          existingIds,
        });

  return (
    <StepFrame
      kind='ui'
      title='Choose who gets alerted'
      description={
        canTick || ticks.status === 'loading'
          ? 'Alerts go to contact groups. Tick the groups that should receive alerts for what you added.'
          : 'Alerts go to contact groups. Manage the groups in your workspace here.'
      }
      docs={docs}
      actions={
        reviewing ? null : (
          <>
            <DashboardActionButton variant='outline' onClick={skip}>
              Skip for now
            </DashboardActionButton>
            {needsConfirm && !(ticksGoal && stepDone) ? (
              <PrimaryButton
                onClick={confirm}
                isLoading={confirming}
                isDisabled={!defaultReaches}
              >
                Use these groups
              </PrimaryButton>
            ) : null}
            {ticksGoal && (!needsConfirm || stepDone) ? (
              <PrimaryButton
                onClick={goOn}
                isLoading={confirming}
                isDisabled={
                  (needsConfirm ? !stepDone : !canContinue) ||
                  Boolean(ticks.saving)
                }
              >
                Continue
              </PrimaryButton>
            ) : null}
          </>
        )
      }
      actionHint={
        !reviewing && needsConfirm && !defaultReaches ? (
          <ContinueHint>set a default group that has a recipient.</ContinueHint>
        ) : !reviewing && ticksGoal && !needsConfirm ? (
          canContinue ? (
            <ContinueHint plain>
              Continue when the groups are right.
            </ContinueHint>
          ) : (
            <ContinueHint>
              tick a group that reaches someone for everything you added.
            </ContinueHint>
          )
        ) : null
      }
    >
      <VStack align='stretch' spacing={4}>
        {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
        {defaultOnly ? (
          <StatusPanel status='info' testId='default-only-note'>
            {DEFAULT_ONLY_NOTE}
          </StatusPanel>
        ) : null}
        {nothingFound ? (
          <StatusPanel
            status='info'
            title='No certificates found yet'
            testId='nothing-found-note'
          >
            {defaultGroup
              ? `Certificates your agent finds later use the workspace default group "${defaultGroup.name}". Continue now, or wait here: this page checks again by itself.`
              : 'No default group is set, so certificates found later have no recipient until one is. Set a default group below.'}
          </StatusPanel>
        ) : null}
        {canTick ? <ItemsCovered items={ticks.items} goal={goal} /> : null}
        <VStack align='stretch' spacing={3} as='section'>
          <HStack
            justify='space-between'
            align='start'
            flexWrap='wrap'
            spacing={3}
          >
            <VStack align='start' spacing={1} minW={0} flex='1 1 240px'>
              <Text as='h3' fontSize='sm' fontWeight='bold'>
                Groups in this workspace
              </Text>
              {ticks.status === 'loading' ? (
                <HStack spacing={2}>
                  <Spinner size='xs' />
                  <Text fontSize='xs' color={muted}>
                    Reading the groups of your items
                  </Text>
                </HStack>
              ) : sentence ? (
                <Text fontSize='xs' color={muted} data-testid='tick-sentence'>
                  {sentence}
                </Text>
              ) : null}
              <Text fontSize='xs' color={muted}>
                {CREATE_HELP}
              </Text>
            </VStack>
            <DashboardActionButton
              size='sm'
              variant='outline'
              onClick={() => setEditing('new')}
            >
              Create a new group
            </DashboardActionButton>
          </HStack>
          {ticks.status === 'blocked' ? (
            <Text
              fontSize='sm'
              color={dashboard.callout.warningText}
              role='status'
            >
              {ticks.blockedMessage}
            </Text>
          ) : null}
          {canTick && ticks.noToken ? (
            <Text fontSize='xs' color={muted} data-testid='no-token-note'>
              {describeNoToken(ticks.noToken, goal, defaultGroup?.name)}
            </Text>
          ) : null}
          {ticks.notice ? (
            <DashboardErrorAlert>{ticks.notice}</DashboardErrorAlert>
          ) : null}
          {groups.map(g => {
            const id = String(g.id);
            return (
              <GroupRow
                key={g.id}
                group={g}
                who={describeGroup(g, contacts)}
                isDefault={id === defaultId}
                reachesAnyone={reaches(g)}
                deletePlan={planGroupDelete({ group: g, groups, defaultId })}
                onEdit={() => setEditing(g)}
                onDelete={() =>
                  setPendingDelete({
                    group: g,
                    plan: planGroupDelete({ group: g, groups, defaultId }),
                  })
                }
                tick={
                  canTick
                    ? {
                        state: tickState(id, ticks.items),
                        busy: ticks.saving === id,
                        disabled: Boolean(ticks.saving),
                        onToggle: add => ticks.toggle(id, add),
                      }
                    : null
                }
              />
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
