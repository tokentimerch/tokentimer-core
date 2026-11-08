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
  const [phase, setPhase] = useState('');
  const [testedDraft, setTestedDraft] = useState(null);
  const busy = Boolean(phase);
  const set = key => e => {
    setTestedDraft(null);
    setError('');
    setDraft(d => ({ ...d, [key]: e.target.value }));
  };
  const kind = WEBHOOK_KINDS[draft.kind] || WEBHOOK_KINDS.generic;

  const testAndSave = async () => {
    const check = validateWebhookDraft(draft, existing);
    if (!check.ok) {
      setError(check.problems.join(' '));
      return;
    }
    let testPassed = testedDraft === draft;
    setError('');
    try {
      if (!testPassed) {
        setPhase('testing');
        await alertAPI.testWebhook(draft.url.trim(), draft.kind, {
          routingKey: draft.routingKey || undefined,
        });
        testPassed = true;
        setTestedDraft(draft);
      }
      setPhase('saving');
      // The PUT replaces the whole list, so append to the live one.
      const fresh = await onboardingActions.getAlertSettings(workspaceId);
      const freshCheck = validateWebhookDraft(
        draft,
        Array.isArray(fresh.webhook_urls) ? fresh.webhook_urls : []
      );
      if (!freshCheck.ok) {
        throw new Error(
          `${freshCheck.problems.join(' ')} Check Alert Preferences before retrying.`
        );
      }
      await onboardingActions.putAlertSettings(workspaceId, {
        webhook_urls: appendWebhook(fresh.webhook_urls, draft),
      });
      setPhase('confirming');
      const after = await onboardingActions.getAlertSettings(workspaceId);
      if (!hasWebhook(after, draft.name.trim())) {
        throw new Error(
          'The webhook was not saved. Your plan may not allow more webhooks.'
        );
      }
      const name = draft.name.trim();
      setDraft(EMPTY);
      setTestedDraft(null);
      onSaved(name);
    } catch (e) {
      const detail =
        e?.message ||
        (testPassed
          ? 'Check Alert Preferences before retrying.'
          : 'Check the URL and that the receiver is reachable.');
      setError(
        testPassed
          ? `Test passed, but saving was not confirmed. ${detail}`
          : `Test failed. ${detail}`
      );
    } finally {
      setPhase('');
    }
  };

  return (
    <VStack align='stretch' spacing={3} data-testid='webhook-form'>
      {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
      {phase ? (
        <Text role='status' fontSize='sm'>
          {phase === 'testing'
            ? 'Testing delivery…'
            : phase === 'saving'
              ? 'Saving webhook…'
              : 'Confirming saved webhook…'}
        </Text>
      ) : null}
      <HStack align='start' spacing={3} flexWrap='wrap'>
        <FormControl flex='1 1 150px' isDisabled={busy}>
          <FormLabel fontSize='sm'>Type</FormLabel>
          <Select size='sm' value={draft.kind} onChange={set('kind')}>
            {Object.entries(WEBHOOK_KINDS).map(([id, k]) => (
              <option key={id} value={id}>
                {k.label}
              </option>
            ))}
          </Select>
        </FormControl>
        <FormControl flex='1 1 180px' isRequired isDisabled={busy}>
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
      <FormControl isRequired isDisabled={busy}>
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
        <FormControl isRequired isDisabled={busy}>
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
        <DashboardActionButton
          variant='outline'
          size='sm'
          onClick={onCancel}
          isDisabled={busy}
        >
          Cancel
        </DashboardActionButton>
        <PrimaryButton size='sm' onClick={testAndSave} isLoading={busy}>
          {testedDraft === draft ? 'Retry save' : 'Send test and save'}
        </PrimaryButton>
      </HStack>
    </VStack>
  );
}
