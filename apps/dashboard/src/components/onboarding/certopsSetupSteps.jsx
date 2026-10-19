import { useState } from 'react';
import {
  Badge,
  FormControl,
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
import { buildAdcsConfig } from './adcsModel.js';
import { scopeCertops } from './certopsScope.js';
import { INFRASTRUCTURES, infrastructuresFor } from './certopsMatrix.js';
import {
  DNS_PROVIDERS,
  buildAutomateConfig,
  STAGING_CA,
  RELOAD_SERVICES,
  buildObserveConfig,
  buildPreseedSteps,
  mergeInstallerFields,
} from './certopsConfig.js';

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
      // Merge onto this objective's progress only, so flags left by another
      // goal are dropped the first time this one writes.
      certops: {
        ...scopeCertops(session.progress?.certops, objective),
        ...patch,
      },
    },
  }));
  await ctx.refresh();
}

export function ObjectiveStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const goal = GOALS[ctx.session.intent?.goal];
  const objective = goal?.certopsObjective || 'observe';
  const options = infrastructuresFor(objective);
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
        <RadioGroup value={infra} onChange={setInfra}>
          <Stack spacing={3}>
            {options.map(o => (
              <HStack key={o.id} align='start'>
                <Radio value={o.id}>
                  <Text fontSize='sm' fontWeight='semibold'>
                    {o.label}
                  </Text>
                  <Text fontSize='xs' color={muted}>
                    {o.detail}
                  </Text>
                </Radio>
                {o.status === 'candidate' ? (
                  <Badge colorScheme='orange'>Candidate</Badge>
                ) : null}
              </HStack>
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
  const set = key => e => setForm(f => ({ ...f, [key]: e.target.value }));

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
      zone: form.zone,
      dnsProvider: form.dnsProvider,
      certPath: form.certPath,
      caEndpoint: form.caEndpoint,
      reloadService: form.reloadService,
    });
  }
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
        ...ctx.docs('certops.dns', 'DNS providers'),
      ]}
      actions={
        <PrimaryButton onClick={confirm} isDisabled={!result.ok}>
          I saved this file
        </PrimaryButton>
      }
    >
      <VStack align='stretch' spacing={3}>
        {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
        {objective === 'observe' ? (
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
            <FormControl isRequired>
              <FormLabel fontSize='sm'>Names (comma separated)</FormLabel>
              <Input
                size='sm'
                value={form.names}
                onChange={set('names')}
                placeholder='web.corp.example.com'
              />
            </FormControl>
            <HStack align='start' spacing={3} flexWrap='wrap'>
              <FormControl flex='1 1 240px' isRequired>
                <FormLabel fontSize='sm'>CA server</FormLabel>
                <Input
                  size='sm'
                  value={form.caHost}
                  onChange={set('caHost')}
                  placeholder='ca01.corp.example.com'
                />
              </FormControl>
              <FormControl flex='1 1 240px' isRequired>
                <FormLabel fontSize='sm'>CA name</FormLabel>
                <Input
                  size='sm'
                  value={form.caName}
                  onChange={set('caName')}
                  placeholder='Corp Issuing CA'
                />
              </FormControl>
            </HStack>
            <HStack align='start' spacing={3} flexWrap='wrap'>
              <FormControl flex='1 1 200px' isRequired>
                <FormLabel fontSize='sm'>Template</FormLabel>
                <Input
                  size='sm'
                  value={form.template}
                  onChange={set('template')}
                />
              </FormControl>
              <FormControl flex='1 1 240px' isRequired>
                <FormLabel fontSize='sm'>Allowed DNS scopes</FormLabel>
                <Input
                  size='sm'
                  value={form.dnsScopes}
                  onChange={set('dnsScopes')}
                  placeholder='corp.example.com'
                />
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
                <FormLabel fontSize='sm'>IIS site</FormLabel>
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
                    Full path of the ACME client the agent may run (acme.sh or a
                    compatible tool). Certbot is not supported on Windows. The
                    agent is allowed to run exactly this file.
                  </Text>
                </FormControl>
                <HStack align='start' spacing={3} flexWrap='wrap'>
                  <FormControl flex='1 1 200px'>
                    <FormLabel fontSize='sm'>IIS site</FormLabel>
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
                  The agent first tests the server&apos;s own configuration and
                  only reloads if the test passes. It is allowed to run exactly
                  those two commands, nothing else. Your server must already be
                  set up to read the certificate path above.
                </Text>
              </FormControl>
            ) : null}
          </>
        )}
        {!result.ok
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
            {objective !== 'observe' ? (
              <Text fontSize='xs'>
                The DNS credential stays on the host in a file readable only by
                the agent. It is never entered here. The CA is the Let&apos;s
                Encrypt staging endpoint until you change it.
              </Text>
            ) : null}
          </>
        ) : null}
      </VStack>
    </StepFrame>
  );
}
