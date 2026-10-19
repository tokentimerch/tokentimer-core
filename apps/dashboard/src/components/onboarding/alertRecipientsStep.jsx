import { useCallback, useEffect, useState } from 'react';
import { Badge, HStack, Spinner, Text, VStack } from '@chakra-ui/react';
import {
  DashboardActionButton,
  DashboardErrorAlert,
} from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';
import GroupEditor from './alertGroupEditor.jsx';
import { describeGroup } from './alertGroups.js';
import { onboardingActions } from '../../utils/onboardingActions.js';

function reaches(group, webhookNames, emailIds) {
  return (
    (group.email_contact_ids || []).some(id => emailIds.has(String(id))) ||
    (group.webhook_names || []).some(n => webhookNames.has(n))
  );
}

export function RecipientsStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const [state, setState] = useState({ loading: true });
  // null = list, 'new' = create, otherwise the group being edited
  const [editing, setEditing] = useState(null);
  const [error, setError] = useState('');

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
        <DashboardActionButton mt={3} variant='outline' onClick={load}>
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
  const emailIds = new Set(
    contacts.filter(c => c.details?.email).map(c => String(c.id))
  );
  const webhookNames = new Set(
    (settings.webhook_urls || []).filter(w => w?.name).map(w => w.name)
  );
  const defaultGroup = groups.find(g => String(g.id) === defaultId);
  const defaultReaches = defaultGroup
    ? reaches(defaultGroup, webhookNames, emailIds)
    : false;

  if (editing) {
    const group = editing === 'new' ? null : editing;
    return (
      <StepFrame
        kind='ui'
        title={group ? `Edit ${group.name}` : 'Create a contact group'}
        description='Alerts go to the people and webhooks in a group. You can add Slack, Teams, Discord or PagerDuty, set custom alert days, and a weekly digest.'
        docs={docs}
      >
        <GroupEditor
          ctx={ctx}
          settings={settings}
          contacts={contacts}
          group={group}
          makeDefault={!defaultReaches || defaultId === String(group?.id)}
          onSaved={afterSave}
          onCancel={groups.length > 0 ? () => setEditing(null) : undefined}
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
          <DashboardActionButton variant='ghost' onClick={skip}>
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

  return (
    <StepFrame
      kind='ui'
      title='Choose who gets alerted'
      description='Alerts go to a contact group. The default group is used for new assets.'
      docs={docs}
      actions={
        <>
          <DashboardActionButton variant='ghost' onClick={skip}>
            Skip for now
          </DashboardActionButton>
          <PrimaryButton onClick={() => setEditing('new')}>
            Create another group
          </PrimaryButton>
        </>
      }
    >
      <VStack align='stretch' spacing={3}>
        {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
        {!defaultReaches ? (
          <Text fontSize='sm' color='orange.400'>
            The default group does not reach anyone yet. Add a recipient or a
            webhook to it, or make another group the default.
          </Text>
        ) : null}
        {groups.map(g => {
          const isDefault = String(g.id) === defaultId;
          const who = describeGroup(g, contacts);
          return (
            <HStack
              key={g.id}
              justify='space-between'
              align='start'
              borderWidth='1px'
              borderRadius='md'
              p={3}
              spacing={3}
              flexWrap='wrap'
            >
              <VStack align='start' spacing={0} minW={0}>
                <HStack>
                  <Text fontSize='sm' fontWeight='semibold'>
                    {g.name}
                  </Text>
                  {isDefault ? <Badge colorScheme='blue'>Default</Badge> : null}
                  {!reaches(g, webhookNames, emailIds) ? (
                    <Badge colorScheme='orange'>Reaches nobody</Badge>
                  ) : null}
                </HStack>
                <Text fontSize='xs' color={muted}>
                  {who.length ? who.join(', ') : 'No recipients'}
                </Text>
              </VStack>
              <HStack spacing={2}>
                {!isDefault ? (
                  <DashboardActionButton
                    size='xs'
                    variant='outline'
                    onClick={() => makeDefault(g)}
                  >
                    Make default
                  </DashboardActionButton>
                ) : null}
                <DashboardActionButton
                  size='xs'
                  variant='outline'
                  onClick={() => setEditing(g)}
                >
                  Edit
                </DashboardActionButton>
              </HStack>
            </HStack>
          );
        })}
      </VStack>
    </StepFrame>
  );
}
