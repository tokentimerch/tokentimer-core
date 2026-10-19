import { useMemo, useState } from 'react';
import PrimaryButton from './PrimaryButton.jsx';
import {
  Badge,
  Checkbox,
  FormControl,
  FormLabel,
  HStack,
  Input,
  Text,
  VStack,
} from '@chakra-ui/react';
import {
  DashboardActionButton,
  DashboardErrorAlert,
} from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { runIdempotent } from './operations.js';
import { findContactByEmail, splitName } from './contactSetup.js';
import {
  assertGroupPersisted,
  buildGroup,
  uniqueGroupId,
  upsertGroup,
} from './alertGroups.js';
import { onboardingActions } from '../../utils/onboardingActions.js';
import WebhookForm from './alertWebhookForm.jsx';

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const contactLabel = c =>
  [c.first_name, c.last_name].filter(Boolean).join(' ') ||
  c.details?.email ||
  'Contact';

/**
 * Create or edit one contact group with everything the product supports:
 * people, webhooks, optional alert days and the weekly digest.
 */
export default function GroupEditor({
  ctx,
  settings,
  contacts,
  group,
  makeDefault: defaultSuggested,
  onSaved,
  onCancel,
}) {
  const { muted } = useDashboardTheme();
  const editing = Boolean(group);
  const [name, setName] = useState(group?.name || 'Alert recipients');
  const [emailIds, setEmailIds] = useState(
    () => new Set((group?.email_contact_ids || []).map(String))
  );
  const [hooks, setHooks] = useState(() => new Set(group?.webhook_names || []));
  const [newPeople, setNewPeople] = useState([]);
  const [person, setPerson] = useState({
    name: editing ? '' : ctx.userName || '',
    email: editing ? '' : ctx.userEmail || '',
  });
  const [days, setDays] = useState(
    Array.isArray(group?.thresholds) ? group.thresholds.join(', ') : ''
  );
  const [digest, setDigest] = useState(group?.weekly_digest_email === true);
  const [asDefault, setAsDefault] = useState(defaultSuggested);
  const [showWebhook, setShowWebhook] = useState(false);
  const [available, setAvailable] = useState(settings.webhook_urls || []);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const emailContacts = useMemo(
    () => contacts.filter(c => c.details?.email),
    [contacts]
  );
  const toggle = (setter, value) =>
    setter(prev => {
      const next = new Set(prev);
      if (next.has(value)) next.delete(value);
      else next.add(value);
      return next;
    });

  const addPerson = () => {
    const email = person.email.trim().toLowerCase();
    if (!EMAIL.test(email)) {
      setError('Enter a valid email address.');
      return;
    }
    const existing = findContactByEmail(contacts, email);
    if (existing) {
      setEmailIds(prev => new Set(prev).add(String(existing.id)));
    } else if (!newPeople.some(p => p.email === email)) {
      setNewPeople(prev => [...prev, { name: person.name.trim(), email }]);
    }
    setPerson({ name: '', email: '' });
    setError('');
  };

  const save = async () => {
    setError('');
    // A person typed but not yet added still counts: pressing Create group
    // with a filled-in address is the same intent as pressing Add person.
    const pending = person.email.trim().toLowerCase();
    let people = newPeople;
    let ids = emailIds;
    if (pending) {
      if (!EMAIL.test(pending)) {
        setError('Enter a valid email address, or clear the field.');
        return;
      }
      const known = findContactByEmail(contacts, pending);
      if (known) ids = new Set(ids).add(String(known.id));
      else if (!people.some(p => p.email === pending))
        people = [...people, { name: person.name.trim(), email: pending }];
    }
    const groupId =
      group?.id || uniqueGroupId(name, settings.contact_groups, null);
    const preview = buildGroup({
      id: groupId,
      name,
      emailContactIds: [...ids, ...people.map(p => p.email)],
      whatsappContactIds: group?.whatsapp_contact_ids || [],
      webhookNames: [...hooks],
      thresholdsText: days,
      workspaceThresholds: settings.alert_thresholds || [],
      weeklyDigestEmail: digest,
      weeklyDigestWhatsapp: group?.weekly_digest_whatsapp === true,
      weeklyDigestWebhooks: group?.weekly_digest_webhooks === true,
    });
    if (!preview.ok) {
      setError(preview.problems.join(' '));
      return;
    }
    setBusy(true);
    try {
      await runIdempotent({
        controller: ctx.controller,
        kind: 'contact_group',
        // Identity carries only the group id: no emails, no webhook URLs.
        identity: { groupId },
        find: () => Promise.resolve(null),
        create: async () => {
          let current = await onboardingActions.listContacts(ctx.workspaceId);
          const created = [];
          for (const p of people) {
            let contact = findContactByEmail(current, p.email);
            if (!contact) {
              contact = await onboardingActions.createContact(ctx.workspaceId, {
                ...splitName(p.name, p.email),
                details: { email: p.email },
              });
              current = [...current, contact];
            }
            created.push(String(contact.id));
          }
          const fresh = await onboardingActions.getAlertSettings(
            ctx.workspaceId
          );
          const built = buildGroup({
            id: groupId,
            name,
            emailContactIds: [...ids, ...created],
            whatsappContactIds: group?.whatsapp_contact_ids || [],
            webhookNames: [...hooks],
            thresholdsText: days,
            workspaceThresholds: fresh.alert_thresholds || [],
            weeklyDigestEmail: digest,
            weeklyDigestWhatsapp: group?.weekly_digest_whatsapp === true,
            weeklyDigestWebhooks: group?.weekly_digest_webhooks === true,
          });
          if (!built.ok) throw new Error(built.problems.join(' '));
          await onboardingActions.putAlertSettings(ctx.workspaceId, {
            contact_groups: upsertGroup(fresh.contact_groups, built.group),
            ...(asDefault ? { default_contact_group_id: groupId } : {}),
          });
          assertGroupPersisted(
            await onboardingActions.getAlertSettings(ctx.workspaceId),
            built.group,
            { expectDefault: asDefault }
          );
          return { groupId };
        },
        record: (_refs, result) => ({ contactGroupId: result.groupId }),
      });
      await onSaved();
    } catch (e) {
      setError(e?.message || 'Could not save the group.');
    } finally {
      setBusy(false);
    }
  };

  const savedHooks = available.filter(w => w?.name);

  return (
    <VStack align='stretch' spacing={4} data-testid='group-editor'>
      {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}

      <FormControl isRequired>
        <FormLabel fontSize='sm'>Group name</FormLabel>
        <Input
          size='sm'
          value={name}
          onChange={e => setName(e.target.value)}
          maxLength={80}
        />
      </FormControl>

      <VStack align='stretch' spacing={2}>
        <Text fontSize='sm' fontWeight='semibold'>
          People (email)
        </Text>
        {emailContacts.length === 0 && newPeople.length === 0 ? (
          <Text fontSize='xs' color={muted}>
            No contacts yet. Add the first person below.
          </Text>
        ) : null}
        {emailContacts.map(c => (
          <Checkbox
            key={c.id}
            size='sm'
            isChecked={emailIds.has(String(c.id))}
            onChange={() => toggle(setEmailIds, String(c.id))}
          >
            {contactLabel(c)}{' '}
            <Text as='span' fontSize='xs' color={muted}>
              {c.details.email}
            </Text>
          </Checkbox>
        ))}
        {newPeople.map(p => (
          <HStack key={p.email} spacing={2}>
            <Badge colorScheme='green'>New</Badge>
            <Text fontSize='sm'>
              {p.name || p.email} <span>{p.name ? p.email : ''}</span>
            </Text>
            <DashboardActionButton
              size='xs'
              variant='ghost'
              onClick={() =>
                setNewPeople(prev => prev.filter(x => x.email !== p.email))
              }
            >
              Remove
            </DashboardActionButton>
          </HStack>
        ))}
        <HStack align='end' spacing={2} flexWrap='wrap'>
          <FormControl flex='1 1 160px'>
            <FormLabel fontSize='xs'>Name</FormLabel>
            <Input
              size='sm'
              value={person.name}
              onChange={e => setPerson(p => ({ ...p, name: e.target.value }))}
              autoComplete='off'
            />
          </FormControl>
          <FormControl flex='1 1 220px'>
            <FormLabel fontSize='xs'>Email</FormLabel>
            <Input
              size='sm'
              value={person.email}
              onChange={e => setPerson(p => ({ ...p, email: e.target.value }))}
              autoComplete='off'
            />
          </FormControl>
          <DashboardActionButton
            size='sm'
            variant='outline'
            onClick={addPerson}
          >
            Add person
          </DashboardActionButton>
        </HStack>
        {editing && (group.whatsapp_contact_ids || []).length > 0 ? (
          <Text fontSize='xs' color={muted}>
            WhatsApp recipients on this group are kept as they are. Manage them
            in alert preferences.
          </Text>
        ) : null}
      </VStack>

      <VStack align='stretch' spacing={2}>
        <Text fontSize='sm' fontWeight='semibold'>
          Webhooks (Slack, Teams, Discord, PagerDuty, generic)
        </Text>
        {savedHooks.map(w => (
          <Checkbox
            key={w.name}
            size='sm'
            isChecked={hooks.has(w.name)}
            onChange={() => toggle(setHooks, w.name)}
          >
            {w.name}{' '}
            <Text as='span' fontSize='xs' color={muted}>
              {w.kind || 'generic'}
            </Text>
          </Checkbox>
        ))}
        {showWebhook ? (
          <WebhookForm
            workspaceId={ctx.workspaceId}
            existing={savedHooks}
            onCancel={() => setShowWebhook(false)}
            onSaved={async savedName => {
              const fresh = await onboardingActions.getAlertSettings(
                ctx.workspaceId
              );
              setAvailable(fresh.webhook_urls || []);
              setHooks(prev => new Set(prev).add(savedName));
              setShowWebhook(false);
            }}
          />
        ) : (
          <HStack>
            <DashboardActionButton
              size='sm'
              variant='outline'
              onClick={() => setShowWebhook(true)}
            >
              Add a webhook
            </DashboardActionButton>
          </HStack>
        )}
      </VStack>

      <VStack align='stretch' spacing={2}>
        <FormControl>
          <FormLabel fontSize='sm'>
            Alert days for this group (optional)
          </FormLabel>
          <Input
            size='sm'
            value={days}
            onChange={e => setDays(e.target.value)}
            placeholder={(settings.alert_thresholds || []).join(', ')}
          />
          <Text fontSize='xs' color={muted} mt={1}>
            Leave empty to use the workspace days. Days before expiry, 0 is the
            day itself.
          </Text>
        </FormControl>
        <Checkbox
          size='sm'
          isChecked={digest}
          onChange={e => setDigest(e.target.checked)}
        >
          Send a weekly digest by email
        </Checkbox>
        <Checkbox
          size='sm'
          isChecked={asDefault}
          onChange={e => setAsDefault(e.target.checked)}
        >
          Use as the default group for new assets
        </Checkbox>
      </VStack>

      <HStack justify='flex-end'>
        {onCancel ? (
          <DashboardActionButton variant='ghost' onClick={onCancel}>
            Cancel
          </DashboardActionButton>
        ) : null}
        <PrimaryButton onClick={save} isLoading={busy}>
          {editing ? 'Save group' : 'Create group'}
        </PrimaryButton>
      </HStack>
    </VStack>
  );
}
