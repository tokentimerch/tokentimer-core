import { useCallback, useEffect, useState } from 'react';
import {
  Badge,
  FormControl,
  FormLabel,
  HStack,
  Input,
  Radio,
  RadioGroup,
  Spinner,
  Stack,
  Text,
  VStack,
} from '@chakra-ui/react';
import {
  DashboardActionButton,
  DashboardErrorAlert,
} from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import { runIdempotent } from './operations.js';
import {
  findContactByEmail,
  onboardingGroupId,
  planContactSetup,
  splitName,
} from './contactSetup.js';
import { evaluateVerification, CHECK_STATUS } from './verification.js';
import {
  addRecipientToGroup,
  appendContactGroup,
  onboardingActions,
} from '../../utils/onboardingActions.js';

export function RecipientsStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const [state, setState] = useState({ loading: true });
  const [email, setEmail] = useState(ctx.userEmail || '');
  const [name, setName] = useState(ctx.userName || '');
  const [pick, setPick] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [settings, contacts] = await Promise.all([
        onboardingActions.getAlertSettings(ctx.workspaceId),
        onboardingActions.listContacts(ctx.workspaceId),
      ]);
      const plan = planContactSetup({
        groups: settings.contact_groups,
        contacts,
        defaultGroupId: settings.default_contact_group_id,
      });
      setState({ loading: false, settings, contacts, plan });
      if (plan.kind === 'set_default') setPick(plan.groupId);
    } catch (e) {
      setState({ loading: false, error: e.message });
    }
  }, [ctx.workspaceId]);

  useEffect(() => {
    load();
  }, [load]);

  const finish = async () => {
    await ctx.refresh();
    await load();
  };

  const useExisting = async () => {
    setBusy(true);
    setError('');
    try {
      await onboardingActions.putAlertSettings(ctx.workspaceId, {
        default_contact_group_id: pick,
      });
      await finish();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const createRecipient = async () => {
    const address = email.trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address)) {
      setError('Enter a valid email address.');
      return;
    }
    setBusy(true);
    setError('');
    const { plan } = state;
    const groupId =
      plan.kind === 'add_to_default'
        ? plan.groupId
        : onboardingGroupId(address);
    try {
      await runIdempotent({
        controller: ctx.controller,
        kind: 'contact_group',
        identity: { email: address.toLowerCase(), groupId },
        find: async () => {
          // Verified read: a usable default group means the work is done.
          const [latest, contacts] = await Promise.all([
            onboardingActions.getAlertSettings(ctx.workspaceId),
            onboardingActions.listContacts(ctx.workspaceId),
          ]);
          const done = planContactSetup({
            groups: latest.contact_groups,
            contacts,
            defaultGroupId: latest.default_contact_group_id,
          });
          return done.kind === 'ready' ? { groupId: done.groupId } : null;
        },
        create: async () => {
          let contact = findContactByEmail(state.contacts, address);
          if (!contact) {
            const contacts = await onboardingActions.listContacts(
              ctx.workspaceId
            );
            contact = findContactByEmail(contacts, address);
          }
          if (!contact) {
            contact = await onboardingActions.createContact(ctx.workspaceId, {
              ...splitName(name, address),
              details: { email: address.toLowerCase() },
            });
          }
          const fresh = await onboardingActions.getAlertSettings(
            ctx.workspaceId
          );
          const groups =
            plan.kind === 'add_to_default'
              ? addRecipientToGroup(fresh.contact_groups, groupId, contact.id)
              : appendContactGroup(fresh.contact_groups, {
                  id: groupId,
                  name: 'Alert recipients',
                  emailContactIds: [contact.id],
                });
          await onboardingActions.putAlertSettings(ctx.workspaceId, {
            contact_groups: groups,
            default_contact_group_id: groupId,
          });
          return { groupId };
        },
        record: (_refs, result) => ({ contactGroupId: result.groupId }),
      });
      await finish();
    } catch (e) {
      setError(e.message || 'Could not set up the recipient.');
    } finally {
      setBusy(false);
    }
  };

  const skip = async () => {
    await ctx.controller.update(session => ({
      progress: {
        ...session.progress,
        skipped: Array.from(
          new Set([...(session.progress?.skipped || []), 'recipients'])
        ),
      },
    }));
    await ctx.refresh();
  };

  if (state.loading) {
    return (
      <StepFrame kind='ui' title='Choose who gets alerted'>
        <Spinner size='sm' />
      </StepFrame>
    );
  }

  const { plan } = state;
  const docs = [
    ...ctx.docs('alerts.contactGroups', 'Contact groups'),
    ...ctx.docs('quickstart.recipients', 'Choosing recipients'),
  ];

  return (
    <StepFrame
      kind='ui'
      title='Choose who gets alerted'
      description='Alerts are emailed to a contact group. The default group is used for new assets.'
      docs={docs}
      actions={
        <>
          <DashboardActionButton variant='ghost' onClick={skip}>
            Skip for now
          </DashboardActionButton>
          {plan?.kind === 'set_default' ? (
            <DashboardActionButton
              colorScheme='blue'
              onClick={useExisting}
              isLoading={busy}
              isDisabled={!pick}
            >
              Use this group
            </DashboardActionButton>
          ) : plan?.kind === 'ready' ? null : (
            <DashboardActionButton
              colorScheme='blue'
              onClick={createRecipient}
              isLoading={busy}
            >
              Save recipient
            </DashboardActionButton>
          )}
        </>
      }
    >
      <VStack align='stretch' spacing={3}>
        {state.error ? (
          <DashboardErrorAlert>{state.error}</DashboardErrorAlert>
        ) : null}
        {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
        {plan?.kind === 'ready' ? (
          <Text fontSize='sm'>
            The default contact group already has an email recipient.
          </Text>
        ) : plan?.kind === 'set_default' ? (
          <RadioGroup value={pick} onChange={setPick}>
            <Stack spacing={2}>
              {plan.groups.map(group => (
                <Radio key={group.id} value={String(group.id)}>
                  <Text fontSize='sm'>{group.name}</Text>
                </Radio>
              ))}
            </Stack>
          </RadioGroup>
        ) : (
          <>
            <Text fontSize='xs' color={muted}>
              {plan?.kind === 'add_to_default'
                ? 'Your default group has no email recipient yet. This adds one to it.'
                : 'This creates a contact and a default group for it.'}
            </Text>
            <HStack align='start' spacing={3} flexWrap='wrap'>
              <FormControl flex='1 1 200px'>
                <FormLabel fontSize='sm'>Name</FormLabel>
                <Input
                  size='sm'
                  value={name}
                  onChange={e => setName(e.target.value)}
                  autoComplete='off'
                />
              </FormControl>
              <FormControl flex='1 1 240px' isRequired>
                <FormLabel fontSize='sm'>Email</FormLabel>
                <Input
                  size='sm'
                  type='email'
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  autoComplete='off'
                />
              </FormControl>
            </HStack>
          </>
        )}
      </VStack>
    </StepFrame>
  );
}

const CHECK_BADGE = {
  [CHECK_STATUS.PASS]: { label: 'OK', colorScheme: 'green' },
  [CHECK_STATUS.FAIL]: { label: 'Needs attention', colorScheme: 'red' },
  [CHECK_STATUS.WARN]: { label: 'Follow up', colorScheme: 'orange' },
};

export function VerifyStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const [state, setState] = useState({ loading: true });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const goal = ctx.session.intent?.goal;

  const run = useCallback(async () => {
    setState(s => ({ ...s, loading: true }));
    try {
      await ctx.refresh();
      const summary = await ctx.fetchSummary();
      const refs = ctx.session.operationRefs || {};
      const monitor =
        goal === 'monitor_https'
          ? summary.monitors.items.find(
              m =>
                m.url?.toLowerCase() === String(refs.monitorUrl).toLowerCase()
            ) || null
          : null;
      const tokenId =
        monitor?.tokenId ||
        (summary.references.tokenIds.existing || [])[0] ||
        null;
      const token = tokenId ? await onboardingActions.getToken(tokenId) : null;
      setState({
        loading: false,
        result: evaluateVerification({ goal, monitor, token, summary }),
      });
    } catch (e) {
      setState({ loading: false, error: e.message });
    }
  }, [ctx, goal]);

  useEffect(() => {
    run();
    // Only on mount: the user re-checks explicitly.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const finish = async () => {
    setBusy(true);
    setError('');
    try {
      await ctx.controller.update(session => ({
        progress: { ...session.progress, verified: true },
        status: 'completed',
      }));
      await ctx.refresh();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const { result } = state;
  return (
    <StepFrame
      kind='verify'
      title='Check that it is working'
      description='These checks read the real state of your workspace.'
      docs={[
        ...ctx.docs('quickstart.verifyAlert', 'Verifying an alert'),
        ...ctx.docs('alerts.troubleshooting', 'If alerts do not arrive'),
      ]}
      actions={
        <>
          <DashboardActionButton
            variant='outline'
            onClick={run}
            isLoading={state.loading}
          >
            Check again
          </DashboardActionButton>
          <DashboardActionButton
            colorScheme='blue'
            onClick={finish}
            isLoading={busy}
            isDisabled={!result?.ok}
          >
            Finish setup
          </DashboardActionButton>
        </>
      }
    >
      <VStack align='stretch' spacing={3}>
        {state.error ? (
          <DashboardErrorAlert>{state.error}</DashboardErrorAlert>
        ) : null}
        {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
        {state.loading && !result ? <Spinner size='sm' /> : null}
        {(result?.checks || []).map(check => (
          <HStack key={check.id} align='start' spacing={3}>
            <Badge colorScheme={CHECK_BADGE[check.status].colorScheme}>
              {CHECK_BADGE[check.status].label}
            </Badge>
            <VStack align='start' spacing={0}>
              <Text fontSize='sm' fontWeight='semibold'>
                {check.label}
              </Text>
              {check.detail ? (
                <Text fontSize='xs' color={muted}>
                  {check.detail}
                </Text>
              ) : null}
            </VStack>
          </HStack>
        ))}
      </VStack>
    </StepFrame>
  );
}
