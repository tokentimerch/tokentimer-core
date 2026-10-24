import { useState } from 'react';
import {
  Box,
  FormControl,
  FormErrorMessage,
  FormLabel,
  HStack,
  Input,
  ListItem,
  Radio,
  RadioGroup,
  Select,
  Stack,
  Text,
  Textarea,
  UnorderedList,
  VStack,
} from '@chakra-ui/react';
import { DashboardErrorAlert } from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';
import { CopyBlock, ErrorText } from './blocks.jsx';
import { GOALS } from './modules.js';
import { ADCS_DRY_RUN_NOTE, buildAdcsConfig } from './adcsModel.js';
import {
  chooseInfrastructure,
  mergeCertops,
  scopeCertops,
} from './certopsScope.js';
import { isCandidatePick, pickHint, pickKey } from './guidedSetupStatus.js';
import {
  CANDIDATE_NOTE_ID,
  CandidateBadge,
  CandidateNote,
} from './candidateMarks.jsx';
import { INFRASTRUCTURES, infrastructuresFor } from './certopsMatrix.js';
import ExistingAgentPick, { fittingAgents } from './ExistingAgentPick.jsx';
import {
  DNS_PROVIDERS,
  buildAutomateConfig,
  STAGING_CA,
  RELOAD_SERVICES,
  NGINX_RELOAD_DROPIN,
  AGENT_KEYS_DIR,
  buildObserveConfig,
  buildPreseedSteps,
  buildLinuxCredentialPrep,
  dnsCredentialsExample,
  mergeInstallerFields,
  windowsCredentialAclCommand,
} from './certopsConfig.js';

// acme.sh is a shell script, so Windows needs a shell to run it. Git for
// Windows ships one, which the Windows guide uses.
const DEFAULT_WINDOWS_SHELL = 'C:\\Program Files\\Git\\bin\\bash.exe';
// The Vault issuer writes no certificate file; the config builder still
// wants a path, and it is dropped from the allowed paths below.
const VAULT_UNUSED_CERT_PATH = '/etc/ssl/tokentimer/unused.pem';

// The agent binds a certificate to an existing TLS listener; it never
// creates the site, and the binding on that port is replaced.
const BINDING_NOTE =
  'Issuing replaces the certificate currently bound to this port. A TLS listener (for example an IIS site) must already exist, because the agent does not create sites.';

// Field names for the "To continue" line, in the words the form uses.
const FIELD_NAMES = {
  names: 'the names',
  zone: 'the DNS zone',
  dnsProvider: 'the DNS provider',
  caEndpoint: 'the ACME directory URL',
  certPath: 'the certificate file path',
  acmeClientPath: 'the ACME client path',
  acmeShellPath: 'the shell path',
  reloadService: 'the web server to reload',
  caHost: 'the CA server',
  caName: 'the CA name',
  template: 'the template',
  dnsScopes: 'the allowed DNS scopes',
};

const STAGING_WARNING =
  'The first order uses the Let’s Encrypt staging CA, so its test certificate is not trusted by browsers. That is intended for a first run.';
const DNS_PREREQUISITES = [
  'A domain you control, with its DNS zone at a provider that has an API.',
  'An API credential for that DNS provider, limited to that zone. It stays on the server and is never entered here.',
];

// Prerequisites the operator must have before the first step, by objective.
const BEFORE_YOU_START = {
  automate: [
    ...DNS_PREREQUISITES,
    'A web server on the host that will use the certificate (nginx, Apache or HAProxy on Linux, an IIS site on Windows) if you want it reloaded for you.',
    STAGING_WARNING,
  ],
  vault: [
    ...DNS_PREREQUISITES,
    'A HashiCorp Vault server with a KV v2 mount, and two Linux servers: one that issues the certificate and one that installs it.',
    STAGING_WARNING,
  ],
  adcs: [
    'A Windows Server that is joined to your domain and is not a domain controller.',
    'Enroll permission on the certificate template for that server’s computer account.',
    'A network route from that server to your Certification Authority.',
  ],
};

const IIS_SITE_HELPER =
  'The name of an existing IIS site, as shown in IIS Manager. The certificate is bound to its HTTPS binding on the port beside it.';

// Errors use the theme-safe red from ErrorText: the theme pins Text to a dark
// grey in the light theme, which made plain red text read as body text there.
function errorLines(messages) {
  return (
    <div>
      {messages.map(m => (
        <ErrorText key={m} as='span' display='block'>
          {m}
        </ErrorText>
      ))}
    </div>
  );
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
      candidate: isCandidatePick(key),
      hint: pickHint(key),
    };
  });
  const saved = certopsProgress(ctx);
  const [infra, setInfra] = useState(saved.infrastructure || '');
  // Reusing an agent is opt-in: ticked only with a choice already saved, or
  // when the operator ticks it here. Another pick starts unticked.
  const [agentId, setAgentId] = useState(saved.chosenAgentId || '');
  const [ticked, setTicked] = useState(Boolean(saved.chosenAgentId));
  const [error, setError] = useState('');
  const fitting = fittingAgents(ctx, objective, infra);
  const reuse = ticked && fitting.some(a => a.id === agentId);
  const pickInfra = value => {
    if (value === infra) return;
    setInfra(value);
    setTicked(false);
    setAgentId('');
  };

  const save = async () => {
    try {
      // Decided inside the write so a retry after a conflict sees the latest
      // platform, and the previous platform's step marks do not carry over.
      await ctx.controller.update(session => ({
        progress: {
          ...session.progress,
          certops: chooseInfrastructure(
            session.progress?.certops,
            objective,
            infra,
            reuse ? agentId : null
          ),
        },
      }));
      await ctx.refresh();
      // Reviewing this step from the list: go back to the live step, which
      // the new platform may have moved.
      ctx.release?.();
      ctx.onDone?.();
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
        <PrimaryButton
          onClick={save}
          isDisabled={!infra || (ticked && fitting.length > 0 && !reuse)}
        >
          Continue
        </PrimaryButton>
      }
    >
      <VStack align='stretch' spacing={3}>
        {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
        {BEFORE_YOU_START[objective] ? (
          <Box data-testid='before-you-start'>
            <Text fontSize='sm' fontWeight='semibold'>
              Before you start
            </Text>
            <UnorderedList fontSize='sm' spacing={1} ml={5} mt={1}>
              {BEFORE_YOU_START[objective].map(item => (
                <ListItem key={item}>{item}</ListItem>
              ))}
            </UnorderedList>
          </Box>
        ) : null}
        {picks.some(o => o.candidate) ? <CandidateNote /> : null}
        <RadioGroup value={infra} onChange={pickInfra}>
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
        <ExistingAgentPick
          ctx={ctx}
          objective={objective}
          infra={infra}
          ticked={ticked}
          agentId={agentId}
          onTick={on => {
            setTicked(on);
            if (!on) setAgentId('');
          }}
          onAgent={setAgentId}
        />
      </VStack>
    </StepFrame>
  );
}

export function ConfigStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const saved = certopsProgress(ctx);
  const goal = GOALS[ctx.session.intent?.goal];
  const objective = goal?.certopsObjective || saved.objective || 'observe';
  const infra = saved.infrastructure || 'linux';
  const os = INFRASTRUCTURES[infra]?.platform === 'win32' ? 'windows' : 'linux';
  const [form, setForm] = useState({
    names: saved.names || '',
    zone: saved.zone || '',
    dnsProvider: saved.dnsProvider || 'cloudflare',
    // No default on purpose: a pre-filled example path looks real and would
    // be requested as typed. Vault issues no file, so it uses a fixed value.
    certPath: saved.certPath || '',
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
      certPath: objective === 'vault' ? VAULT_UNUSED_CERT_PATH : form.certPath,
      caEndpoint: form.caEndpoint,
      reloadService: objective === 'vault' ? '' : form.reloadService,
    });
    if (result.ok && objective === 'vault') {
      // The issuer publishes to Vault and writes no certificate file, so it
      // is allowed to touch its key folder only.
      result.config.policy.allowedPaths = [AGENT_KEYS_DIR];
    }
  }
  const fieldErrors = result.fieldErrors || {};
  const shown = key => (touched[key] ? fieldErrors[key] || [] : []);
  // Why the main button is off, said once and without red until the person
  // has started typing, so a blank form does not open with errors.
  const missing = Object.keys(fieldErrors).map(k => FIELD_NAMES[k] || k);
  const preseed = result.ok
    ? buildPreseedSteps({
        os,
        config: mergeInstallerFields(result.config, {
          apiUrl: ctx.apiUrl,
          workspaceId: ctx.workspaceId,
        }),
      })
    : null;

  const credentialsFile = result.ok
    ? result.config.dnsProviders?.[form.dnsProvider]?.credentialsFile || ''
    : '';
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
      description='You save a settings file on the server before you install the agent, so the agent starts with it. The installer keeps this file as it is.'
      docs={[
        ...ctx.docs('certops.agentConfig', 'Agent configuration'),
        ...(objective === 'adcs' || objective === 'observe'
          ? []
          : [
              ...ctx.docs('certops.dns', 'DNS providers'),
              ...ctx.docs('certops.dnsPropagation', 'DNS propagation settings'),
            ]),
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
                <Text fontSize='xs' mt={1} data-testid='template-helper'>
                  The template&apos;s common name from the CA console, with no
                  spaces. For example WebServer.
                </Text>
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
                <Text fontSize='xs' mt={1} data-testid='dns-scopes-helper'>
                  The names this host may request certificates for. A scope such
                  as corp.example.com also covers web.corp.example.com.
                </Text>
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
                <Text fontSize='xs' mt={1} data-testid='iis-site-helper'>
                  {IIS_SITE_HELPER}
                </Text>
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
            <FormControl isRequired isInvalid={shown('names').length > 0}>
              <FormLabel fontSize='sm'>Names (comma separated)</FormLabel>
              <Input
                size='sm'
                value={form.names}
                onChange={set('names')}
                onBlur={blur('names')}
                placeholder='www.example.com'
              />
              <FormErrorMessage fontSize='xs'>
                {errorLines(shown('names'))}
              </FormErrorMessage>
            </FormControl>
            <HStack align='start' spacing={3} flexWrap='wrap'>
              <FormControl
                flex='1 1 200px'
                isRequired
                isInvalid={shown('zone').length > 0}
              >
                <FormLabel fontSize='sm'>DNS zone</FormLabel>
                <Input
                  size='sm'
                  value={form.zone}
                  onChange={set('zone')}
                  onBlur={blur('zone')}
                  placeholder='example.com'
                />
                <FormErrorMessage fontSize='xs'>
                  {errorLines(shown('zone'))}
                </FormErrorMessage>
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
                <FormControl
                  isRequired
                  isInvalid={shown('acmeClientPath').length > 0}
                >
                  <FormLabel fontSize='sm'>
                    ACME client on the Windows host
                  </FormLabel>
                  <Input
                    size='sm'
                    value={form.acmeClientPath}
                    onChange={set('acmeClientPath')}
                    onBlur={blur('acmeClientPath')}
                    placeholder='C:\acme\acme.sh.exe'
                  />
                  <FormErrorMessage fontSize='xs'>
                    {errorLines(shown('acmeClientPath'))}
                  </FormErrorMessage>
                  <Text fontSize='xs' mt={1}>
                    Full path of the ACME client the agent may run. acme.sh is a
                    shell script, so it needs the shell below. Certbot is not
                    supported on Windows. The agent is allowed to run exactly
                    this command.
                  </Text>
                </FormControl>
                <FormControl isInvalid={shown('acmeShellPath').length > 0}>
                  <FormLabel fontSize='sm'>
                    Shell that runs the ACME client (optional)
                  </FormLabel>
                  <Input
                    size='sm'
                    value={form.acmeShellPath}
                    onChange={set('acmeShellPath')}
                    onBlur={blur('acmeShellPath')}
                    placeholder='C:\Program Files\Git\bin\bash.exe'
                  />
                  <FormErrorMessage fontSize='xs'>
                    {errorLines(shown('acmeShellPath'))}
                  </FormErrorMessage>
                  <Text fontSize='xs' mt={1} data-testid='git-for-windows-note'>
                    Install Git for Windows on this server first: it provides
                    bash.exe, which runs acme.sh. Leave this empty only when the
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
                    <Text fontSize='xs' mt={1} data-testid='iis-site-helper'>
                      {IIS_SITE_HELPER}
                    </Text>
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
                    <Text fontSize='xs' mt={1} data-testid='sni-helper'>
                      The hostname clients ask for when several sites share this
                      IP address and port. Leave it empty if unsure.
                    </Text>
                  </FormControl>
                </HStack>
                <Text fontSize='xs' data-testid='binding-note'>
                  {BINDING_NOTE}
                </Text>
              </>
            ) : null}
            {os === 'linux' && objective !== 'vault' ? (
              <FormControl isRequired isInvalid={shown('certPath').length > 0}>
                <FormLabel fontSize='sm'>Certificate file path</FormLabel>
                <Input
                  size='sm'
                  value={form.certPath}
                  onChange={set('certPath')}
                  onBlur={blur('certPath')}
                  placeholder='/etc/ssl/tokentimer/www.example.com.pem'
                />
                <FormErrorMessage fontSize='xs'>
                  {errorLines(shown('certPath'))}
                </FormErrorMessage>
                <Text fontSize='xs' mt={1} data-testid='cert-path-helper'>
                  Where the agent writes the certificate. Choose a new file name
                  in a folder your web server can read. The key goes next to it
                  with .key added.
                </Text>
              </FormControl>
            ) : null}
            <FormControl isInvalid={shown('caEndpoint').length > 0}>
              <FormLabel fontSize='sm'>ACME directory URL</FormLabel>
              <Input
                size='sm'
                value={form.caEndpoint}
                onChange={set('caEndpoint')}
                onBlur={blur('caEndpoint')}
              />
              <FormErrorMessage fontSize='xs'>
                {errorLines(shown('caEndpoint'))}
              </FormErrorMessage>
              <Text fontSize='xs' mt={1}>
                Defaults to the Let&apos;s Encrypt staging CA. Use your own
                private ACME CA address if you have one.
              </Text>
            </FormControl>
            {os === 'linux' && objective !== 'vault' ? (
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
                  set up to read the certificate path above and the key the
                  agent writes next to it (the same path with .key added). The
                  request step shows the exact lines for your server.
                </Text>
                {form.reloadService === 'nginx' ? (
                  <Box as='details' mt={1} data-testid='reload-nginx-panel'>
                    <Box
                      as='summary'
                      fontSize='xs'
                      cursor='pointer'
                      fontWeight='semibold'
                    >
                      One-time nginx setup, so a reload tests the configuration
                    </Box>
                    <VStack align='stretch' spacing={2} mt={2}>
                      <Text fontSize='xs' data-testid='reload-nginx-note'>
                        nginx cannot test its own configuration as an
                        unprivileged user (nginx -t has to write /run/nginx.pid
                        and its error log), so for nginx the agent only checks
                        that the service is running. The stock nginx unit does
                        not test the configuration on reload either, so run this
                        once on the server. It makes every reload test the
                        configuration as root first and fail when the test
                        fails.
                      </Text>
                      <CopyBlock
                        label='One-time nginx setup'
                        text={NGINX_RELOAD_DROPIN}
                      />
                    </VStack>
                  </Box>
                ) : null}
                {form.reloadService === 'apache' ? (
                  <Text fontSize='xs' mt={1} data-testid='reload-apache-note'>
                    The agent only checks that Apache is running. The
                    unit&apos;s own reload (<code>apachectl graceful</code>)
                    tests the configuration as root, so a broken one is refused
                    and Apache keeps its old certificate. A test run by the
                    agent itself would fail whenever any site loads a key only
                    root can read, such as the default-ssl site.
                  </Text>
                ) : null}
                {form.reloadService === 'haproxy' ? (
                  <Text fontSize='xs' mt={1} data-testid='reload-haproxy-note'>
                    The agent only checks that HAProxy is running. The
                    unit&apos;s own reload (<code>haproxy -c -q</code>) tests
                    the configuration as root, so a broken one is refused and
                    HAProxy keeps its old certificate. A test run by the agent
                    itself would fail whenever the configuration loads a PEM
                    only root can read.
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
        {!result.ok ? (
          <Text fontSize='xs' color={muted} data-testid='config-missing'>
            The button below stays disabled until these are filled in correctly:{' '}
            {missing.join(', ')}.
          </Text>
        ) : null}
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
                {credentialsFile || 'the path in the file above'}{' '}
                {os === 'windows'
                  ? '(then lock it down so only SYSTEM and Administrators can read it, see below)'
                  : '(mode 0600, owned by the agent user once the installer has created it, see below)'}{' '}
                with these fields:{' '}
                {(DNS_PROVIDERS[form.dnsProvider]?.fields || []).join(', ')}.
                The DNS providers page shows the exact file format. The CA is
                the Let&apos;s Encrypt staging endpoint until you change it.
              </Text>
            ) : null}
            {objective !== 'observe' &&
            objective !== 'adcs' &&
            os === 'linux' ? (
              <CopyBlock
                label='Create the folder now, set the owner after the installer has run'
                text={buildLinuxCredentialPrep(credentialsFile)}
              />
            ) : null}
            {objective === 'automate' &&
            dnsCredentialsExample(form.dnsProvider) ? (
              <CopyBlock
                label='Credential file shape (replace the placeholders)'
                text={dnsCredentialsExample(form.dnsProvider)}
                language='json'
              />
            ) : null}
            {objective === 'automate' ? (
              <Text fontSize='xs' data-testid='dns-propagation-note'>
                After publishing the challenge record, the agent waits until it
                can see it. Some DNS setups, such as split-horizon or private
                zones, need the DNS propagation settings (which resolvers to
                ask, how long to wait, whether to check the authoritative
                servers); see the DNS propagation page.
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
