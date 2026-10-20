import { useState } from 'react';
import PrimaryButton from './PrimaryButton.jsx';
import {
  FormControl,
  FormLabel,
  HStack,
  Input,
  Select,
  Text,
  VStack,
} from '@chakra-ui/react';
import {
  DashboardActionButton,
  DashboardErrorAlert,
} from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { alertAPI } from '../../utils/apiClient';
import { onboardingActions } from '../../utils/onboardingActions.js';
import {
  WEBHOOK_KINDS,
  appendWebhook,
  hasWebhook,
  validateWebhookDraft,
} from './alertGroups.js';

const EMPTY = { kind: 'slack', name: '', url: '', routingKey: '' };

/**
 * Adds one webhook. Like the alert preferences page, a webhook is only saved
 * after a test message went through to its current URL. The URL is a secret:
 * it stays in this component, is sent to the server and is then dropped. It is
 * never written to the setup session or to analytics.
 */
export default function WebhookForm({
  workspaceId,
  existing,
  onSaved,
  onCancel,
}) {
  const { muted } = useDashboardTheme();
  const [draft, setDraft] = useState(EMPTY);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const set = key => e => setDraft(d => ({ ...d, [key]: e.target.value }));
  const kind = WEBHOOK_KINDS[draft.kind] || WEBHOOK_KINDS.generic;

  const testAndSave = async () => {
    const check = validateWebhookDraft(draft, existing);
    if (!check.ok) {
      setError(check.problems.join(' '));
      return;
    }
    setBusy(true);
    setError('');
    try {
      await alertAPI.testWebhook(draft.url.trim(), draft.kind, {
        routingKey: draft.routingKey || undefined,
      });
      // The PUT replaces the whole list, so append to the live one.
      const fresh = await onboardingActions.getAlertSettings(workspaceId);
      await onboardingActions.putAlertSettings(workspaceId, {
        webhook_urls: appendWebhook(fresh.webhook_urls, draft),
      });
      const after = await onboardingActions.getAlertSettings(workspaceId);
      if (!hasWebhook(after, draft.name.trim())) {
        throw new Error(
          'The webhook was not saved. Your plan may not allow more webhooks.'
        );
      }
      const name = draft.name.trim();
      setDraft(EMPTY);
      onSaved(name);
    } catch (e) {
      setError(
        e?.message ||
          'The test message failed. Check the URL and that the receiver is reachable.'
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <VStack align='stretch' spacing={3} data-testid='webhook-form'>
      {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
      <HStack align='start' spacing={3} flexWrap='wrap'>
        <FormControl flex='1 1 150px'>
          <FormLabel fontSize='sm'>Type</FormLabel>
          <Select size='sm' value={draft.kind} onChange={set('kind')}>
            {Object.entries(WEBHOOK_KINDS).map(([id, k]) => (
              <option key={id} value={id}>
                {k.label}
              </option>
            ))}
          </Select>
        </FormControl>
        <FormControl flex='1 1 180px' isRequired>
          <FormLabel fontSize='sm'>Name</FormLabel>
          <Input
            size='sm'
            value={draft.name}
            onChange={set('name')}
            placeholder='Ops channel'
            maxLength={40}
          />
        </FormControl>
      </HStack>
      <FormControl isRequired>
        <FormLabel fontSize='sm'>Webhook URL</FormLabel>
        <Input
          size='sm'
          type='password'
          autoComplete='off'
          value={draft.url}
          onChange={set('url')}
          placeholder='https://'
        />
        <Text fontSize='xs' color={muted} mt={1}>
          {kind.help}. Treated as a secret: it is only sent to the server.
        </Text>
      </FormControl>
      {kind.needsRouting ? (
        <FormControl isRequired>
          <FormLabel fontSize='sm'>Routing key</FormLabel>
          <Input
            size='sm'
            type='password'
            autoComplete='off'
            value={draft.routingKey}
            onChange={set('routingKey')}
          />
        </FormControl>
      ) : null}
      <HStack justify='flex-end'>
        <DashboardActionButton variant='outline' size='sm' onClick={onCancel}>
          Cancel
        </DashboardActionButton>
        <PrimaryButton size='sm' onClick={testAndSave} isLoading={busy}>
          Send test and save
        </PrimaryButton>
      </HStack>
    </VStack>
  );
}
