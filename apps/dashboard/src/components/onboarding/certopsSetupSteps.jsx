import { useState } from 'react';
import {
  Box,
  FormControl,
  FormErrorMessage,
  FormLabel,
  HStack,
  Input,
  Radio,
  RadioGroup,
  Select,
  Stack,
  Text,
  Textarea,
  VStack,
} from '@chakra-ui/react';
import { DashboardErrorAlert } from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';
import { CopyBlock } from './blocks.jsx';
import { GOALS } from './modules.js';
import { ADCS_DRY_RUN_NOTE, buildAdcsConfig } from './adcsModel.js';
import { mergeCertops, scopeCertops } from './certopsScope.js';
import { isCandidatePick, pickHint, pickKey } from './guidedSetupStatus.js';
import {
  CANDIDATE_NOTE_ID,
  CandidateBadge,
  CandidateNote,
} from './candidateMarks.jsx';
import { INFRASTRUCTURES, infrastructuresFor } from './certopsMatrix.js';
import {
  DNS_PROVIDERS,
  buildAutomateConfig,
  STAGING_CA,
  RELOAD_SERVICES,
  NGINX_RELOAD_DROPIN,
  buildObserveConfig,
  buildPreseedSteps,
  mergeInstallerFields,
  windowsCredentialAclCommand,
} from './certopsConfig.js';

// acme.sh is a shell script, so Windows needs a shell to run it. Git for
// Windows ships one, which the Windows guide uses.
const DEFAULT_WINDOWS_SHELL = 'C:\\Program Files\\Git\\bin\\bash.exe';

// The agent binds a certificate to an existing TLS listener; it never
// creates the site, and the binding on that port is replaced.
const BINDING_NOTE =
  'Issuing replaces the certificate currently bound to this port. A TLS listener (for example an IIS site) must already exist, because the agent does not create sites.';

function errorLines(messages) {
  return messages.map(m => (
    <Text key={m} as='span' display='block'>
      {m}
    </Text>
  ));
}

export function certopsObjectiveFor(ctx) {
  return GOALS[ctx.session.intent?.goal]?.certopsObjective;
}

export function certopsProgress(ctx) {
  return scopeCertops(ctx.session.progress?.certops, certopsObjectiveFor(ctx));
}

export async function saveCertops(ctx, patch) {
  const objective = certopsObjectiveFor(ctx);
  await ctx.controller.update(session => ({
    progress: {
      ...session.progress,
      // Merge onto this objective's progress only. Another goal's flags are
      // parked, not dropped, so coming back to it restores them.
      certops: mergeCertops(session.progress?.certops, objective, patch),
    },
  }));
  await ctx.refresh();
}

export function ObjectiveStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const goal = GOALS[ctx.session.intent?.goal];
  const objective = goal?.certopsObjective || 'observe';
  const picks = infrastructuresFor(objective).map(o => {
    const key = pickKey(ctx.session.intent?.goal, o.id);
    return {
      ...o,
      candidate: isCandidatePick(key, o.status === 'candidate'),
      hint: pickHint(key),
    };
  });
  const saved = certopsProgress(ctx);
  const [infra, setInfra] = useState(saved.infrastructure || '');
  const [error, setError] = useState('');

  const save = async () => {
    try {
      await saveCertops(ctx, { objective, infrastructure: infra });
    } catch (e) {
      setError(e.message);
    }
  };

  return (
    <StepFrame
      kind='ui'
      title='Where will the certificates live?'
      description='Only combinations that are supported for your goal are listed.'
      docs={ctx.docs('certops.overview', 'About certificate management')}
      actions={
        <PrimaryButton onClick={save} isDisabled={!infra}>
          Continue
        </PrimaryButton>
      }
    >
      <VStack align='stretch' spacing={3}>
        {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
        {picks.some(o => o.candidate) ? <CandidateNote /> : null}
        <RadioGroup value={infra} onChange={setInfra}>
          <Stack spacing={3}>
            {picks.map(o => (
              <Box key={o.id}>
                <HStack align='start'>
                  <Radio
                    value={o.id}
                    aria-describedby={
                      o.candidate
                        ? [
                            `infra-${o.id}-detail`,
                            `infra-${o.id}-badge`,
                            CANDIDATE_NOTE_ID,
                            o.hint ? `infra-${o.id}-hint` : '',
                          ]
                            .filter(Boolean)
                            .join(' ')
                        : undefined
                    }
                  >
                    <Text fontSize='sm' fontWeight='semibold'>
                      {o.label}
                    </Text>
                    <Text
                      id={`infra-${o.id}-detail`}
                      fontSize='xs'
                      color={muted}
                    >
                      {o.detail}
                    </Text>
                  </Radio>
                  {o.candidate ? (
                    <CandidateBadge id={`infra-${o.id}-badge`} />
                  ) : null}
                </HStack>
                {o.candidate && o.hint ? (
                  <Text
                    id={`infra-${o.id}-hint`}
                    fontSize='xs'
                    color={muted}
                    ml={6}
                    mt={1}
                  >
                    {o.hint}
                  </Text>
                ) : null}
              </Box>
            ))}
          </Stack>
        </RadioGroup>
      </VStack>
    </StepFrame>
  );
}

export function ConfigStep({ ctx }) {
  const saved = certopsProgress(ctx);
  const goal = GOALS[ctx.session.intent?.goal];
  const objective = goal?.certopsObjective || saved.objective || 'observe';
  const infra = saved.infrastructure || 'linux';
  const os = INFRASTRUCTURES[infra]?.platform === 'win32' ? 'windows' : 'linux';
  const [form, setForm] = useState({
    names: saved.names || '',
    zone: saved.zone || '',
    dnsProvider: saved.dnsProvider || 'cloudflare',
    certPath: saved.certPath || '/etc/ssl/tokentimer/example.pem',
    caEndpoint: saved.caEndpoint || STAGING_CA,
    reloadService: saved.reloadService || '',
    acmeClientPath: saved.acmeClientPath || '',
    acmeShellPath: saved.acmeShellPath ?? DEFAULT_WINDOWS_SHELL,
    iisSite: saved.iisSite || 'Default Web Site',
    iisPort: saved.iisPort || '443',
    sniHost: saved.sniHost || '',
    caHost: saved.caHost || '',
    caName: saved.caName || '',
    template: saved.template || 'WebServer',
    dnsScopes: saved.dnsScopes || '',
    directories: saved.directories || '/etc/ssl/certs',
  });
  const [error, setError] = useState('');
  // Errors appear only after the operator has typed in, or left, a field.
  const [touched, setTouched] = useState({});
  const markTouched = key =>
    setTouched(t => (t[key] ? t : { ...t, [key]: true }));
  const set = key => e => {
    markTouched(key);
    setForm(f => ({ ...f, [key]: e.target.value }));
  };
  const blur = key => () => markTouched(key);

  if (infra === 'kubernetes') {
    return (
      <StepFrame
        kind='info'
        title='Kubernetes'
        description='The controller needs no agent configuration.'
      >
        <Text fontSize='sm'>The next step shows the Helm values.</Text>
      </StepFrame>
    );
  }

  const names = form.names.split(/[\s,]+/).filter(Boolean);
  let result;
  if (objective === 'observe') {
    const directories = form.directories
      .split(/[\n,]+/)
      .map(s => s.trim())
      .filter(Boolean);
    result = { ok: true, config: buildObserveConfig({ os, directories }) };
  } else if (objective === 'adcs') {
    result = buildAdcsConfig({
      caHost: form.caHost,
      caName: form.caName,
      template: form.template,
      dnsScopes: form.dnsScopes,
      names,
    });
  } else {
    result = buildAutomateConfig({
      os,
      names,
      acmeClientPath: form.acmeClientPath,
      acmeShellPath: form.acmeShellPath,
      zone: form.zone,
      dnsProvider: form.dnsProvider,
      certPath: form.certPath,
      caEndpoint: form.caEndpoint,
      reloadService: form.reloadService,
    });
  }
  const adcsErrors = objective === 'adcs' ? result.fieldErrors || {} : {};
  const shown = key => (touched[key] ? adcsErrors[key] || [] : []);
  const preseed = result.ok
    ? buildPreseedSteps({
        os,
        config: mergeInstallerFields(result.config, {
          apiUrl: ctx.apiUrl,
          workspaceId: ctx.workspaceId,
        }),
      })
    : null;

  const confirm = async () => {
    try {
      await saveCertops(ctx, {
        names: form.names,
        zone: form.zone,
        dnsProvider: form.dnsProvider,
        certPath: form.certPath,
        caEndpoint: form.caEndpoint,
        reloadService: form.reloadService,
        acmeClientPath: form.acmeClientPath,
        acmeShellPath: form.acmeShellPath,
        iisSite: form.iisSite,
        iisPort: form.iisPort,
        sniHost: form.sniHost,
        caHost: form.caHost,
        caName: form.caName,
        template: form.template,
        dnsScopes: form.dnsScopes,
        directories: form.directories,
        configReviewed: true,
      });
    } catch (e) {
      setError(e.message);
    }
  };

  return (
    <StepFrame
      kind='runbook'
      title='Prepare the agent configuration'
      description='Created on the server before the agent registers, because command profiles are reported only at registration.'
      docs={[
        ...ctx.docs('certops.agentConfig', 'Agent configuration'),
        ...(objective === 'adcs' || objective === 'observe'
          ? []
          : ctx.docs('certops.dns', 'DNS providers')),
      ]}
      actions={
        <PrimaryButton onClick={confirm} isDisabled={!result.ok}>
          I saved this file
        </PrimaryButton>
      }
    >
      <VStack align='stretch' spacing={3}>
        {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
        {objective === 'observe' && os === 'windows' ? (
          <Text fontSize='sm'>
            The agent reads the machine certificate store (LocalMachine\My) and
            the site bindings on its own, so there is no folder to choose.
          </Text>
        ) : objective === 'observe' ? (
          <FormControl>
            <FormLabel fontSize='sm'>
              Folders to scan for certificates
            </FormLabel>
            <Textarea
              size='sm'
              rows={2}
              value={form.directories}
              onChange={set('directories')}
            />
          </FormControl>
        ) : objective === 'adcs' ? (
          <>
            <FormControl isRequired isInvalid={shown('names').length > 0}>
              <FormLabel fontSize='sm'>Names (comma separated)</FormLabel>
              <Input
                size='sm'
                value={form.names}
                onChange={set('names')}
                onBlur={blur('names')}
                placeholder='web.corp.example.com'
              />
              <FormErrorMessage fontSize='xs'>
                {errorLines(shown('names'))}
              </FormErrorMessage>
            </FormControl>
            <HStack align='start' spacing={3} flexWrap='wrap'>
              <FormControl
                flex='1 1 240px'
                isRequired
                isInvalid={shown('caHost').length > 0}
              >
                <FormLabel fontSize='sm'>CA server</FormLabel>
                <Input
                  size='sm'
                  value={form.caHost}
                  onChange={set('caHost')}
                  onBlur={blur('caHost')}
                  placeholder='ca01.corp.example.com'
                />
                <FormErrorMessage fontSize='xs'>
                  {errorLines(shown('caHost'))}
                </FormErrorMessage>
              </FormControl>
              <FormControl
                flex='1 1 240px'
                isRequired
                isInvalid={shown('caName').length > 0}
              >
                <FormLabel fontSize='sm'>CA name</FormLabel>
                <Input
                  size='sm'
                  value={form.caName}
                  onChange={set('caName')}
                  onBlur={blur('caName')}
                  placeholder='Corp Issuing CA'
                />
                <FormErrorMessage fontSize='xs'>
                  {errorLines(shown('caName'))}
                </FormErrorMessage>
              </FormControl>
            </HStack>
            <HStack align='start' spacing={3} flexWrap='wrap'>
              <FormControl
                flex='1 1 200px'
                isRequired
                isInvalid={shown('template').length > 0}
              >
                <FormLabel fontSize='sm'>Template (common name)</FormLabel>
                <Input
                  size='sm'
                  value={form.template}
                  onChange={set('template')}
                  onBlur={blur('template')}
                />
                <FormErrorMessage fontSize='xs'>
                  {errorLines(shown('template'))}
                </FormErrorMessage>
              </FormControl>
              <FormControl
                flex='1 1 240px'
                isRequired
                isInvalid={shown('dnsScopes').length > 0}
              >
                <FormLabel fontSize='sm'>Allowed DNS scopes</FormLabel>
                <Input
                  size='sm'
                  value={form.dnsScopes}
                  onChange={set('dnsScopes')}
                  onBlur={blur('dnsScopes')}
                  placeholder='corp.example.com'
                />
                <FormErrorMessage fontSize='xs'>
                  {errorLines(shown('dnsScopes'))}
                </FormErrorMessage>
              </FormControl>
            </HStack>
            <Text fontSize='xs'>
              The rule below lets this one host contact this one CA with this
              one template, for names inside these scopes. TokenTimer never
              stores CA credentials: the agent authenticates as the computer
              account.
            </Text>
            <HStack align='start' spacing={3} flexWrap='wrap'>
              <FormControl flex='1 1 200px'>
                <FormLabel fontSize='sm'>HTTPS binding (IIS site)</FormLabel>
                <Input
                  size='sm'
                  value={form.iisSite}
                  onChange={set('iisSite')}
                />
              </FormControl>
              <FormControl flex='0 1 110px'>
                <FormLabel fontSize='sm'>Port</FormLabel>
                <Input
                  size='sm'
                  type='number'
                  value={form.iisPort}
                  onChange={set('iisPort')}
                />
              </FormControl>
            </HStack>
            <Text fontSize='xs' data-testid='binding-note'>
              {BINDING_NOTE}
            </Text>
          </>
        ) : (
          <>
            <FormControl isRequired>
              <FormLabel fontSize='sm'>Names (comma separated)</FormLabel>
              <Input
                size='sm'
                value={form.names}
                onChange={set('names')}
                placeholder='www.example.com'
              />
            </FormControl>
            <HStack align='start' spacing={3} flexWrap='wrap'>
              <FormControl flex='1 1 200px' isRequired>
                <FormLabel fontSize='sm'>DNS zone</FormLabel>
                <Input
                  size='sm'
                  value={form.zone}
                  onChange={set('zone')}
                  placeholder='example.com'
                />
              </FormControl>
              <FormControl flex='1 1 200px'>
                <FormLabel fontSize='sm'>DNS provider</FormLabel>
                <Select
                  size='sm'
                  value={form.dnsProvider}
                  onChange={set('dnsProvider')}
                >
                  {Object.entries(DNS_PROVIDERS).map(([id, p]) => (
                    <option key={id} value={id}>
                      {p.label}
                    </option>
                  ))}
                </Select>
                <Text fontSize='xs' mt={1} data-testid='dns-provider-note'>
                  {DNS_PROVIDERS[form.dnsProvider]?.note}
                </Text>
              </FormControl>
            </HStack>
            {os === 'windows' ? (
              <>
                <FormControl isRequired>
                  <FormLabel fontSize='sm'>
                    ACME client on the Windows host
                  </FormLabel>
                  <Input
                    size='sm'
                    value={form.acmeClientPath}
                    onChange={set('acmeClientPath')}
                    placeholder='C:\acme\acme.sh.exe'
                  />
                  <Text fontSize='xs' mt={1}>
                    Full path of the ACME client the agent may run. acme.sh is a
                    shell script, so it needs the shell below. Certbot is not
                    supported on Windows. The agent is allowed to run exactly
                    this command.
                  </Text>
                </FormControl>
                <FormControl>
                  <FormLabel fontSize='sm'>
                    Shell that runs the ACME client (optional)
                  </FormLabel>
                  <Input
                    size='sm'
                    value={form.acmeShellPath}
                    onChange={set('acmeShellPath')}
                    placeholder='C:\Program Files\Git\bin\bash.exe'
                  />
                  <Text fontSize='xs' mt={1}>
                    Git for Windows ships bash.exe. Leave it empty only when the
                    ACME client above is a native program.
                  </Text>
                </FormControl>
                <HStack align='start' spacing={3} flexWrap='wrap'>
                  <FormControl flex='1 1 200px'>
                    <FormLabel fontSize='sm'>
                      HTTPS binding (IIS site)
                    </FormLabel>
                    <Input
                      size='sm'
                      value={form.iisSite}
                      onChange={set('iisSite')}
                    />
                  </FormControl>
                  <FormControl flex='0 1 110px'>
                    <FormLabel fontSize='sm'>Port</FormLabel>
                    <Input
                      size='sm'
                      type='number'
                      value={form.iisPort}
                      onChange={set('iisPort')}
                    />
                  </FormControl>
                  <FormControl flex='1 1 200px'>
                    <FormLabel fontSize='sm'>SNI host (optional)</FormLabel>
                    <Input
                      size='sm'
                      value={form.sniHost}
                      onChange={set('sniHost')}
                    />
                  </FormControl>
                </HStack>
                <Text fontSize='xs' data-testid='binding-note'>
                  {BINDING_NOTE}
                </Text>
              </>
            ) : null}
            {os === 'linux' ? (
              <FormControl>
                <FormLabel fontSize='sm'>Certificate file path</FormLabel>
                <Input
                  size='sm'
                  value={form.certPath}
                  onChange={set('certPath')}
                />
              </FormControl>
            ) : null}
            <FormControl>
              <FormLabel fontSize='sm'>ACME directory URL</FormLabel>
              <Input
                size='sm'
                value={form.caEndpoint}
                onChange={set('caEndpoint')}
              />
              <Text fontSize='xs' mt={1}>
                Defaults to the Let&apos;s Encrypt staging CA. Use your own
                private ACME CA address if you have one.
              </Text>
            </FormControl>
            {os === 'linux' ? (
              <FormControl>
                <FormLabel fontSize='sm'>
                  After issuing, reload a web server (optional)
                </FormLabel>
                <Select
                  size='sm'
                  value={form.reloadService}
                  onChange={set('reloadService')}
                >
                  <option value=''>No, only write the certificate</option>
                  {Object.entries(RELOAD_SERVICES).map(([id, s]) => (
                    <option key={id} value={id}>
                      {s.label}
                    </option>
                  ))}
                </Select>
                <Text fontSize='xs' mt={1}>
                  The agent runs a check command, then{' '}
                  <code>systemctl reload</code>, both as its own unprivileged
                  user. The installer command in the next step grants only that
                  reload for the server you choose. It is allowed to run exactly
                  those two commands, nothing else. Your server must already be
                  set up to read the certificate path above.
                </Text>
                {form.reloadService === 'nginx' ? (
                  <VStack align='stretch' spacing={2} mt={1}>
                    <Text fontSize='xs' data-testid='reload-nginx-note'>
                      nginx cannot test its own configuration as an unprivileged
                      user (nginx -t has to write /run/nginx.pid and its error
                      log), so for nginx the agent only checks that the service
                      is running. The stock nginx unit does not test the
                      configuration on reload either, so run this once on the
                      server. It makes every reload test the configuration as
                      root first and fail when the test fails.
                    </Text>
                    <CopyBlock
                      label='One-time nginx setup'
                      text={NGINX_RELOAD_DROPIN}
                    />
                  </VStack>
                ) : null}
                {form.reloadService === 'apache' ? (
                  <Text fontSize='xs' mt={1} data-testid='reload-apache-note'>
                    <code>apachectl configtest</code> runs without privileges
                    while Apache is running. The unit&apos;s own reload (
                    <code>apachectl graceful</code>) tests the configuration
                    again as root and refuses a broken one.
                  </Text>
                ) : null}
                {form.reloadService === 'haproxy' ? (
                  <Text fontSize='xs' mt={1} data-testid='reload-haproxy-note'>
                    <code>haproxy -c</code> reads /etc/haproxy/haproxy.cfg
                    without privileges. The unit&apos;s own reload tests the
                    configuration again as root first.
                  </Text>
                ) : null}
                {form.reloadService ? (
                  <Text fontSize='xs' mt={1} data-testid='reload-failure-note'>
                    When the test or the reload fails, the certificate is still
                    written but the server keeps running with its old one.
                  </Text>
                ) : null}
              </FormControl>
            ) : null}
          </>
        )}
        {!result.ok && objective !== 'adcs'
          ? (result.problems || []).map(p => (
              <Text key={p} fontSize='xs' color='red.400'>
                {p}
              </Text>
            ))
          : null}
        {preseed ? (
          <>
            {preseed.steps.map((s, i) => (
              <Text key={s} fontSize='sm'>
                {i + 1}. {s}
              </Text>
            ))}
            <CopyBlock
              label={preseed.location}
              text={preseed.json}
              language='json'
            />
            {objective === 'adcs' ? (
              <Text fontSize='xs' data-testid='adcs-dry-run-note'>
                {ADCS_DRY_RUN_NOTE}
              </Text>
            ) : objective !== 'observe' ? (
              <Text fontSize='xs' data-testid='dns-credentials-note'>
                The DNS credential stays on the host in a file readable only by
                the agent. It is never entered here. Create it yourself at{' '}
                {result.config.dnsProviders?.[form.dnsProvider]
                  ?.credentialsFile || 'the path in the file above'}{' '}
                {os === 'windows'
                  ? '(then lock it down so only SYSTEM and Administrators can read it, see below)'
                  : '(mode 0600, owned by the agent user)'}{' '}
                with these fields:{' '}
                {(DNS_PROVIDERS[form.dnsProvider]?.fields || []).join(', ')}.
                The DNS providers page shows the exact file format. The CA is
                the Let&apos;s Encrypt staging endpoint until you change it.
              </Text>
            ) : null}
            {objective === 'automate' && os === 'windows' ? (
              <CopyBlock
                label='Lock down the DNS credential file (elevated PowerShell)'
                text={windowsCredentialAclCommand(
                  result.config.dnsProviders?.[form.dnsProvider]
                    ?.credentialsFile || ''
                )}
              />
            ) : null}
          </>
        ) : null}
      </VStack>
    </StepFrame>
  );
}
