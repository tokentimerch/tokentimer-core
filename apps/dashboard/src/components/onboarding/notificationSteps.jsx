import { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  FormControl,
  FormHelperText,
  FormLabel,
  HStack,
  Input,
  Radio,
  RadioGroup,
  Select,
  Spinner,
  Stack,
  Switch,
  Text,
  VStack,
} from '@chakra-ui/react';
import {
  DashboardActionButton,
  DashboardErrorAlert,
} from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';
import { CopyBlock } from './blocks.jsx';
import { onboardingActions } from '../../utils/onboardingActions.js';
import {
  THRESHOLD_PRESETS,
  describeThresholds,
  matchPreset,
  parseThresholds,
} from './thresholds.js';
import {
  TLS_MODES,
  buildSmtpPayload,
  defaultTlsMode,
  explainSmtpTestError,
  lockedFields,
  smtpIsReady,
  tlsModeFromSaved,
} from './smtpForm.js';

export function NotificationsStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const [state, setState] = useState({ loading: true });
  const [preset, setPreset] = useState('standard');
  const [custom, setCustom] = useState('');
  const [emailOn, setEmailOn] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    onboardingActions
      .getAlertSettings(ctx.workspaceId)
      .then(settings => {
        if (cancelled) return;
        const current = settings.alert_thresholds || [30, 14, 7, 1, 0];
        const match = matchPreset(current);
        setPreset(match);
        if (match === 'custom') setCustom(current.join(', '));
        setEmailOn(settings.email_alerts_enabled !== false);
        setState({ loading: false, settings });
      })
      .catch(e => !cancelled && setState({ loading: false, error: e.message }));
    return () => {
      cancelled = true;
    };
  }, [ctx.workspaceId]);

  const parsed = preset === 'custom' ? parseThresholds(custom) : null;
  const values =
    preset === 'custom' ? parsed.values : THRESHOLD_PRESETS[preset].values;
  const invalid = preset === 'custom' && parsed.problems.length > 0;

  const save = async () => {
    setBusy(true);
    setError('');
    try {
      await onboardingActions.putAlertSettings(ctx.workspaceId, {
        alert_thresholds: values,
        email_alerts_enabled: emailOn,
      });
      // The server normalises thresholds, so confirm what it kept.
      const after = await onboardingActions.getAlertSettings(ctx.workspaceId);
      const kept = JSON.stringify(after.alert_thresholds || []);
      if (kept !== JSON.stringify(values)) {
        throw new Error(
          'The thresholds were adjusted by the server. Review them and save again.'
        );
      }
      await ctx.controller.update(session => ({
        progress: { ...session.progress, notificationsReviewed: true },
      }));
      await ctx.refresh();
    } catch (e) {
      setError(e.message || 'Could not save the notification settings.');
    } finally {
      setBusy(false);
    }
  };

  if (state.loading) {
    return (
      <StepFrame kind='ui' title='Set up notifications'>
        <Spinner size='sm' />
      </StepFrame>
    );
  }

  return (
    <StepFrame
      kind='ui'
      title='Set up notifications'
      description='Choose when alerts fire. These apply to every asset in this workspace unless a group overrides them.'
      docs={[
        ...ctx.docs('alerts.thresholds', 'How thresholds work'),
        ...ctx.docs('alerts.contactGroups', 'Channels and webhooks'),
      ]}
      actions={
        <>
          <DashboardActionButton
            variant='outline'
            onClick={() => ctx.skip('notifications')}
          >
            Keep the defaults
          </DashboardActionButton>
          <PrimaryButton onClick={save} isLoading={busy} isDisabled={invalid}>
            Save
          </PrimaryButton>
        </>
      }
    >
      <VStack align='stretch' spacing={4}>
        {state.error ? (
          <DashboardErrorAlert>{state.error}</DashboardErrorAlert>
        ) : null}
        {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
        <FormControl>
          <FormLabel fontSize='sm'>When to alert</FormLabel>
          <RadioGroup value={preset} onChange={setPreset}>
            <Stack spacing={2}>
              {Object.entries(THRESHOLD_PRESETS).map(([id, p]) => (
                <Radio key={id} value={id}>
                  <Text fontSize='sm' fontWeight='semibold'>
                    {p.label}
                  </Text>
                  <Text fontSize='xs' color={muted}>
                    {p.description}
                  </Text>
                </Radio>
              ))}
              <Radio value='custom'>
                <Text fontSize='sm' fontWeight='semibold'>
                  Custom
                </Text>
              </Radio>
            </Stack>
          </RadioGroup>
          {preset === 'custom' ? (
            <>
              <Input
                mt={2}
                size='sm'
                value={custom}
                onChange={e => setCustom(e.target.value)}
                placeholder='45, 30, 14, 7, 1, 0'
                aria-label='Custom thresholds in days'
              />
              <FormHelperText fontSize='xs'>
                Days before expiry, separated by commas. 0 is the day itself and
                negative numbers fire after expiry.
              </FormHelperText>
              {parsed.problems.map(p => (
                <Text key={p} fontSize='xs' color='red.400'>
                  {p}
                </Text>
              ))}
            </>
          ) : null}
          {!invalid ? (
            <Text fontSize='xs' color={muted} mt={2}>
              Alerts will fire: {describeThresholds(values)}.
            </Text>
          ) : null}
        </FormControl>
        <HStack justify='space-between'>
          <Text fontSize='sm'>Send alerts by email</Text>
          <Switch
            isChecked={emailOn}
            onChange={e => setEmailOn(e.target.checked)}
            aria-label='Email alerts'
          />
        </HStack>
        <Text fontSize='xs' color={muted}>
          Slack, Teams and other webhooks, WhatsApp, delivery windows and weekly
          digests are in workspace preferences when you need them.
        </Text>
      </VStack>
    </StepFrame>
  );
}

export function SmtpStep({ ctx }) {
  const isAdmin = ctx.isSystemAdmin === true;
  const [state, setState] = useState({ loading: true });
  const [form, setForm] = useState({
    host: '',
    port: '587',
    user: '',
    pass: '',
    from_email: '',
    from_name: 'TokenTimer',
    tls: 'starttls',
  });
  const [tlsTouched, setTlsTouched] = useState(false);
  // Once saved the step stays so the test email can be sent. The summary is
  // not refreshed until Continue, because a refreshed summary would move the
  // guide on and drop the form.
  const [saved, setSaved] = useState(false);
  const [testTo, setTestTo] = useState(ctx.userEmail || '');
  const [message, setMessage] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    if (!isAdmin) {
      setState({ loading: false });
      return;
    }
    try {
      const settings = await onboardingActions.getSystemSettings();
      const smtp = settings.smtp || {};
      setForm(f => ({
        ...f,
        host: smtp.host?.value || '',
        port: String(smtp.port?.value || '587'),
        user: smtp.user?.value || '',
        pass: '',
        from_email: smtp.from_email?.value || '',
        from_name: smtp.from_name?.value || 'TokenTimer',
        tls: tlsModeFromSaved(smtp, smtp.port?.value || '587'),
      }));
      setState({ loading: false, smtp });
    } catch (e) {
      setState({ loading: false, error: e.message });
    }
  }, [isAdmin]);

  useEffect(() => {
    load();
  }, [load]);

  const set = key => e => {
    const { value } = e.target;
    setForm(f => ({
      ...f,
      [key]: value,
      ...(key === 'port' && !tlsTouched ? { tls: defaultTlsMode(value) } : {}),
    }));
  };
  const smtp = state.smtp || {};
  const locked = lockedFields(smtp);

  const save = async () => {
    const { payload, problems } = buildSmtpPayload(
      { ...form, ...TLS_MODES[form.tls].fields },
      smtp
    );
    if (problems.length) {
      setError(problems.join(' '));
      return;
    }
    setBusy(true);
    setError('');
    setMessage(null);
    try {
      const data = await onboardingActions.putSmtpSettings(payload);
      setState(s => ({ ...s, smtp: data.smtp || s.smtp }));
      setForm(f => ({ ...f, pass: '' }));
      setSaved(true);
      setMessage(
        'Saved. Send a test email to confirm it works, then continue.'
      );
    } catch (e) {
      setError(e.message || 'Could not save the email settings.');
    } finally {
      setBusy(false);
    }
  };

  const finish = async () => {
    setBusy(true);
    try {
      await ctx.refresh();
    } finally {
      setBusy(false);
    }
  };

  const sendTest = async () => {
    setBusy(true);
    setError('');
    setMessage(null);
    try {
      const res = await onboardingActions.testSmtp(testTo.trim());
      setMessage(
        `${res.message || 'Test email sent.'} This proves the server accepted the message; check the inbox to confirm it arrived.`
      );
    } catch (e) {
      setError(explainSmtpTestError(e.code, e.message));
    } finally {
      setBusy(false);
    }
  };

  // A working setup is never asked about again, except right after saving it
  // here, where the test email still has to be sent.
  if (
    !saved &&
    (smtpIsReady(smtp) || ctx.summary?.alerts?.smtpConfigured === true)
  ) {
    return (
      <StepFrame
        kind='verify'
        title='Email delivery'
        description='Email is already set up on this deployment.'
      >
        <Text fontSize='sm'>Nothing to do here.</Text>
      </StepFrame>
    );
  }

  if (!isAdmin) {
    return (
      <StepFrame
        kind='handoff'
        title='Email delivery needs an administrator'
        description='Alerts are routed, but they cannot be emailed until a system administrator configures SMTP.'
        docs={[
          ...ctx.docs('smtp.setup', 'Setting up email'),
          ...ctx.docs('alerts.troubleshooting', 'If alerts do not arrive'),
        ]}
        actions={
          <DashboardActionButton
            variant='outline'
            onClick={() => ctx.skip('smtp')}
          >
            Continue without it
          </DashboardActionButton>
        }
      >
        <VStack align='stretch' spacing={3}>
          <Text fontSize='sm'>
            Email settings are shared by the whole installation, so they are
            managed by a system administrator. Send them this message:
          </Text>
          <CopyBlock
            label='Message for your administrator'
            text={
              'TokenTimer cannot send alert emails yet because SMTP is not configured.\n' +
              'Please open System Settings > Email (SMTP), enter the mail server details and send a test email.\n' +
              'Until then, alerts are created but not delivered by email.'
            }
          />
          <Text fontSize='xs'>
            Your setup keeps working in the meantime. This step reopens by
            itself once email is configured.
          </Text>
        </VStack>
      </StepFrame>
    );
  }

  if (state.loading) {
    return (
      <StepFrame kind='ui' title='Email delivery'>
        <Spinner size='sm' />
      </StepFrame>
    );
  }

  return (
    <StepFrame
      kind='ui'
      title='Set up email delivery'
      description='Alerts are sent through your mail server. These settings apply to the whole installation.'
      docs={[
        ...ctx.docs('smtp.setup', 'Setting up email'),
        ...ctx.docs('alerts.troubleshooting', 'If alerts do not arrive'),
      ]}
      actions={
        <>
          {saved ? null : (
            <DashboardActionButton
              variant='outline'
              onClick={() => ctx.skip('smtp')}
            >
              Skip for now
            </DashboardActionButton>
          )}
          <DashboardActionButton
            variant='outline'
            onClick={sendTest}
            isLoading={busy}
            isDisabled={!saved || !testTo}
          >
            Send test email
          </DashboardActionButton>
          {saved ? (
            <>
              <DashboardActionButton
                variant='outline'
                onClick={save}
                isDisabled={busy}
              >
                Save again
              </DashboardActionButton>
              <PrimaryButton onClick={finish} isLoading={busy}>
                Continue
              </PrimaryButton>
            </>
          ) : (
            <PrimaryButton onClick={save} isLoading={busy}>
              Save
            </PrimaryButton>
          )}
        </>
      }
    >
      <VStack align='stretch' spacing={3}>
        {state.error ? (
          <DashboardErrorAlert>{state.error}</DashboardErrorAlert>
        ) : null}
        {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
        {message ? (
          <Alert status='success' borderRadius='md' variant='left-accent'>
            <AlertIcon />
            <AlertDescription fontSize='sm'>{message}</AlertDescription>
          </Alert>
        ) : null}
        {locked.length > 0 ? (
          <Alert status='info' borderRadius='md' variant='left-accent'>
            <AlertIcon />
            <AlertDescription fontSize='sm'>
              {locked.join(', ')} {locked.length === 1 ? 'is' : 'are'} set by
              the server environment and cannot be changed here. After changing
              environment variables, recreate the containers so they take
              effect.
            </AlertDescription>
          </Alert>
        ) : null}
        <HStack align='start' spacing={3} flexWrap='wrap'>
          <FormControl
            flex='2 1 220px'
            isRequired
            isDisabled={smtp.host?.locked}
          >
            <FormLabel fontSize='sm'>Server</FormLabel>
            <Input
              size='sm'
              value={form.host}
              onChange={set('host')}
              placeholder='smtp.example.com'
              autoComplete='off'
            />
          </FormControl>
          <FormControl flex='1 1 100px' isDisabled={smtp.port?.locked}>
            <FormLabel fontSize='sm'>Port</FormLabel>
            <Input
              size='sm'
              value={form.port}
              onChange={set('port')}
              inputMode='numeric'
            />
          </FormControl>
        </HStack>
        <FormControl
          isDisabled={smtp.secure?.locked || smtp.require_tls?.locked}
        >
          <FormLabel fontSize='sm'>Connection security</FormLabel>
          <Select
            size='sm'
            value={form.tls}
            onChange={e => {
              setTlsTouched(true);
              setForm(f => ({ ...f, tls: e.target.value }));
            }}
          >
            {Object.entries(TLS_MODES).map(([id, mode]) => (
              <option key={id} value={id}>
                {mode.label}
              </option>
            ))}
          </Select>
          <FormHelperText fontSize='xs'>
            {form.tls === 'none'
              ? 'The login and every message travel in clear text. Use this only for a trusted internal relay or a local test server such as Mailpit.'
              : 'Most providers use STARTTLS on port 587 or SSL/TLS on port 465.'}
          </FormHelperText>
        </FormControl>
        <HStack align='start' spacing={3} flexWrap='wrap'>
          <FormControl flex='1 1 200px' isDisabled={smtp.user?.locked}>
            <FormLabel fontSize='sm'>Username</FormLabel>
            <Input
              size='sm'
              value={form.user}
              onChange={set('user')}
              autoComplete='off'
            />
          </FormControl>
          <FormControl flex='1 1 200px' isDisabled={smtp.pass?.locked}>
            <FormLabel fontSize='sm'>Password</FormLabel>
            <Input
              size='sm'
              type='password'
              value={form.pass}
              onChange={set('pass')}
              autoComplete='new-password'
              placeholder={
                smtp.pass?.value ? 'Leave empty to keep the saved password' : ''
              }
            />
            <FormHelperText fontSize='xs'>
              Stored encrypted. Leave both empty for a relay without login.
            </FormHelperText>
          </FormControl>
        </HStack>
        <HStack align='start' spacing={3} flexWrap='wrap'>
          <FormControl
            flex='1 1 220px'
            isRequired
            isDisabled={smtp.from_email?.locked}
          >
            <FormLabel fontSize='sm'>Sender address</FormLabel>
            <Input
              size='sm'
              type='email'
              value={form.from_email}
              onChange={set('from_email')}
              placeholder='alerts@example.com'
            />
          </FormControl>
          <FormControl flex='1 1 180px' isDisabled={smtp.from_name?.locked}>
            <FormLabel fontSize='sm'>Sender name</FormLabel>
            <Input
              size='sm'
              value={form.from_name}
              onChange={set('from_name')}
            />
          </FormControl>
        </HStack>
        <FormControl>
          <FormLabel fontSize='sm'>Send the test email to</FormLabel>
          <Input
            size='sm'
            type='email'
            value={testTo}
            onChange={e => setTestTo(e.target.value)}
          />
        </FormControl>
        <Text fontSize='xs' color='gray.500'>
          The test checks that the server accepts the message, not that it is
          delivered to the inbox.
        </Text>
      </VStack>
    </StepFrame>
  );
}
