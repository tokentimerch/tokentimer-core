import { useState } from 'react';
import {
  Badge,
  Box,
  FormControl,
  FormHelperText,
  FormLabel,
  HStack,
  Radio,
  RadioGroup,
  Select,
  Stack,
  Text,
  Input,
  VStack,
} from '@chakra-ui/react';
import {
  DashboardActionButton,
  DashboardErrorAlert,
} from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import { availableGoals } from './journeyPlanner.js';
import { GOAL_AREAS } from './modules.js';
import { normalizeMonitorUrl, runIdempotent } from './operations.js';
import { onboardingActions } from '../../utils/onboardingActions.js';

export function GoalStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const goals = availableGoals(ctx.capabilities);
  const current = ctx.session.intent?.goal || '';
  const [choice, setChoice] = useState(current);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  const save = async () => {
    setSaving(true);
    setError('');
    try {
      await ctx.controller.update(session => {
        const changed = (session.intent?.goal || '') !== choice;
        return {
          intent: {
            ...session.intent,
            goal: choice,
            // A provider or objective belongs to the previous goal.
            ...(changed ? { provider: '' } : {}),
          },
          // Keep what was imported or created; only reset flags that were
          // about the old goal's steps.
          progress: changed
            ? {
                imported: session.progress?.imported || [],
                certops: session.progress?.certops || {},
              }
            : { ...session.progress, verified: false },
          plannerVersion: ctx.plannerVersion,
        };
      });
      await ctx.refresh();
    } catch (e) {
      setError(e.message || 'Could not save your choice.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <StepFrame
      kind='ui'
      title='What do you want to do first?'
      description='Pick one. You can come back for the others, and nothing is created until you confirm a step.'
      docs={ctx.docs('quickstart.firstAsset', 'First asset guide')}
      actions={
        <DashboardActionButton
          colorScheme='blue'
          onClick={save}
          isLoading={saving}
          isDisabled={!choice}
        >
          Continue
        </DashboardActionButton>
      }
    >
      <VStack align='stretch' spacing={4}>
        {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
        <RadioGroup value={choice} onChange={setChoice}>
          <VStack align='stretch' spacing={4}>
            {GOAL_AREAS.map(area => {
              const inArea = goals.filter(g => g.area === area.id);
              if (inArea.length === 0) return null;
              return (
                <Box key={area.id} role='group' aria-label={area.label}>
                  <Text fontSize='xs' fontWeight='bold' color={muted} mb={2}>
                    {area.label.toUpperCase()}
                  </Text>
                  <Stack spacing={3}>
                    {inArea.map(goal => (
                      <Box key={goal.id}>
                        <HStack>
                          <Radio
                            value={goal.id}
                            isDisabled={Boolean(goal.blocker)}
                          >
                            <Text fontWeight='semibold' fontSize='sm'>
                              {goal.label}
                            </Text>
                          </Radio>
                          {goal.candidate ? (
                            <Badge colorScheme='orange'>Candidate</Badge>
                          ) : null}
                        </HStack>
                        <Text fontSize='xs' color={muted} ml={6}>
                          {goal.blocker?.remediation || goal.description}
                        </Text>
                      </Box>
                    ))}
                  </Stack>
                </Box>
              );
            })}
          </VStack>
        </RadioGroup>
      </VStack>
    </StepFrame>
  );
}
export function MonitorStep({ ctx }) {
  const [url, setUrl] = useState(ctx.session.operationRefs?.monitorUrl || '');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const normalized = normalizeMonitorUrl(url);

  const submit = async () => {
    if (!normalized) {
      setError('Enter a valid HTTPS address, for example https://example.com');
      return;
    }
    setBusy(true);
    setError('');
    try {
      await runIdempotent({
        controller: ctx.controller,
        kind: 'monitor',
        identity: { url: normalized },
        find: async identity => {
          const monitors = await onboardingActions.listMonitors(
            ctx.workspaceId
          );
          return (
            monitors.find(
              m => String(m.url).toLowerCase() === identity.url.toLowerCase()
            ) || null
          );
        },
        create: identity =>
          onboardingActions.createMonitor(ctx.workspaceId, {
            url: identity.url,
          }),
        record: (refs, created) => ({
          monitorUrl: normalized,
          monitorIds: Array.from(
            new Set([...(refs.monitorIds || []), created.id].filter(Boolean))
          ),
          tokenIds: Array.from(
            new Set(
              [...(refs.tokenIds || []), created.token_id].filter(Boolean)
            )
          ),
        }),
      });
      await ctx.refresh();
    } catch (e) {
      setError(e.message || 'Could not add this website.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <StepFrame
      kind='ui'
      title='Add the website to monitor'
      description='TokenTimer reads the certificate over HTTPS and tracks its expiry.'
      docs={[
        ...ctx.docs('monitoring.endpoint', 'About endpoint monitoring'),
        ...ctx.docs('monitoring.network', 'Network requirements'),
      ]}
      actions={
        <DashboardActionButton
          colorScheme='blue'
          onClick={submit}
          isLoading={busy}
          isDisabled={!url.trim()}
        >
          Add website
        </DashboardActionButton>
      }
    >
      <VStack align='stretch' spacing={3}>
        {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
        <FormControl>
          <FormLabel fontSize='sm'>Website address</FormLabel>
          <Input
            size='sm'
            placeholder='https://example.com'
            value={url}
            onChange={e => setUrl(e.target.value)}
            autoComplete='off'
          />
          <FormHelperText fontSize='xs'>
            The address must be reachable from where TokenTimer runs.
          </FormHelperText>
        </FormControl>
      </VStack>
    </StepFrame>
  );
}

const ASSET_TYPES = [
  { value: 'api_key', category: 'key_secret', label: 'API key' },
  { value: 'secret', category: 'key_secret', label: 'Secret' },
  { value: 'ssh_key', category: 'key_secret', label: 'SSH key' },
  { value: 'software_license', category: 'license', label: 'Software license' },
  {
    value: 'service_subscription',
    category: 'license',
    label: 'Service subscription',
  },
  {
    value: 'domain_registration',
    category: 'license',
    label: 'Domain registration',
  },
  { value: 'other', category: 'general', label: 'Other' },
];

function dayKey(value) {
  const t = new Date(value).getTime();
  return Number.isFinite(t) ? Math.round(t / 86400000) : null;
}

export function AssetStep({ ctx }) {
  const [form, setForm] = useState({
    name: '',
    type: 'api_key',
    expiresAt: '',
    location: '',
  });
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const set = key => e => setForm(f => ({ ...f, [key]: e.target.value }));
  const typeDef = ASSET_TYPES.find(t => t.value === form.type);

  const submit = async () => {
    const name = form.name.trim();
    if (!name || !form.expiresAt) {
      setError('A name and an expiry date are required.');
      return;
    }
    if (new Date(form.expiresAt).getTime() <= Date.now()) {
      setError('The expiry date must be in the future.');
      return;
    }
    setBusy(true);
    setError('');
    const identity = {
      name,
      location: form.location.trim(),
      category: typeDef.category,
      type: typeDef.value,
      expiresAt: form.expiresAt,
    };
    try {
      await runIdempotent({
        controller: ctx.controller,
        kind: 'asset',
        identity,
        // Empty locations never conflict server-side, so reconcile by identity.
        find: async id => {
          const items = await onboardingActions.findTokens(
            ctx.workspaceId,
            id.name
          );
          return (
            items.find(
              t =>
                t.name === id.name &&
                (t.location || '') === id.location &&
                t.category === id.category &&
                t.type === id.type &&
                Math.abs(dayKey(t.expiresAt) - dayKey(id.expiresAt)) <= 1
            ) || null
          );
        },
        create: id =>
          onboardingActions.createToken({
            workspace_id: ctx.workspaceId,
            name: id.name,
            category: id.category,
            type: id.type,
            expiresAt: id.expiresAt,
            ...(id.location ? { location: id.location } : {}),
          }),
        record: (refs, created) => ({
          tokenIds: Array.from(
            new Set([...(refs.tokenIds || []), created.id].filter(Boolean))
          ),
        }),
      });
      await ctx.refresh();
    } catch (e) {
      setError(e.message || 'Could not create this asset.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <StepFrame
      kind='ui'
      title='Add your first asset'
      description='Record only the details, never the secret value itself.'
      docs={[
        ...ctx.docs('tokens.adding', 'Adding assets'),
        ...ctx.docs('tokens.fields', 'Asset fields'),
      ]}
      actions={
        <DashboardActionButton
          colorScheme='blue'
          onClick={submit}
          isLoading={busy}
        >
          Create asset
        </DashboardActionButton>
      }
    >
      <VStack align='stretch' spacing={3}>
        {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
        <FormControl isRequired>
          <FormLabel fontSize='sm'>Name</FormLabel>
          <Input
            size='sm'
            value={form.name}
            onChange={set('name')}
            maxLength={255}
            autoComplete='off'
          />
        </FormControl>
        <HStack align='start' spacing={3} flexWrap='wrap'>
          <FormControl flex='1 1 180px'>
            <FormLabel fontSize='sm'>Type</FormLabel>
            <Select size='sm' value={form.type} onChange={set('type')}>
              {ASSET_TYPES.map(t => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </Select>
          </FormControl>
          <FormControl flex='1 1 180px' isRequired>
            <FormLabel fontSize='sm'>Expires on</FormLabel>
            <Input
              size='sm'
              type='date'
              value={form.expiresAt}
              onChange={set('expiresAt')}
            />
          </FormControl>
        </HStack>
        <FormControl>
          <FormLabel fontSize='sm'>Where it is used (optional)</FormLabel>
          <Input
            size='sm'
            value={form.location}
            onChange={set('location')}
            maxLength={500}
            autoComplete='off'
          />
        </FormControl>
      </VStack>
    </StepFrame>
  );
}
