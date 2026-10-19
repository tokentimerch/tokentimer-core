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
import {
  DashboardActionButton,
  DashboardErrorAlert,
} from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import { CopyBlock } from './blocks.jsx';
import { GOALS } from './modules.js';
import { INFRASTRUCTURES, infrastructuresFor } from './certopsMatrix.js';
import {
  DNS_PROVIDERS,
  buildAutomateConfig,
  STAGING_CA,
  buildObserveConfig,
  buildPreseedSteps,
  mergeInstallerFields,
} from './certopsConfig.js';

export function certopsProgress(ctx) {
  return ctx.session.progress?.certops || {};
}

export async function saveCertops(ctx, patch) {
  await ctx.controller.update(session => ({
    progress: {
      ...session.progress,
      certops: { ...(session.progress?.certops || {}), ...patch },
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
        <DashboardActionButton
          colorScheme='blue'
          onClick={save}
          isDisabled={!infra}
        >
          Continue
        </DashboardActionButton>
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
  } else {
    result = buildAutomateConfig({
      os,
      names,
      zone: form.zone,
      dnsProvider: form.dnsProvider,
      certPath: form.certPath,
      caEndpoint: form.caEndpoint,
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
        <DashboardActionButton
          colorScheme='blue'
          onClick={confirm}
          isDisabled={!result.ok}
        >
          I saved this file
        </DashboardActionButton>
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
