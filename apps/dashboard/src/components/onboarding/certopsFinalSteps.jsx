import { useState } from 'react';
import { FiRefreshCw } from 'react-icons/fi';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
  FormControl,
  FormLabel,
  HStack,
  Input,
  Text,
  VStack,
} from '@chakra-ui/react';
import { DashboardActionButton } from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import { CopyBlock } from './blocks.jsx';
import { capabilityGap, requiredCapabilities } from './certopsMatrix.js';
import { buildVaultConfigs, buildVaultPolicies } from './certopsConfig.js';
import { certopsProgress, saveCertops } from './certopsSetupSteps.jsx';
import IssueStep from './certopsIssueStep.jsx';

export function FirstCertificateStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const saved = certopsProgress(ctx);
  const automating = saved.objective === 'automate';
  if (automating) {
    return <IssueStep ctx={ctx} />;
  }
  const certs = ctx.summary?.certops?.certificates;
  const total = certs?.observed ?? certs?.total ?? 0;
  return (
    <StepFrame
      kind='verify'
      title='See your first certificate'
      description='This confirms the agent is reporting real certificates into your inventory.'
      docs={[
        ...ctx.docs('certops.inventory', 'Certificate inventory'),
        ...ctx.docs('certops.discovery', 'How discovery works'),
      ]}
      actions={
        <DashboardActionButton
          leftIcon={<FiRefreshCw />}
          variant='outline'
          onClick={() => ctx.refresh()}
        >
          Check again
        </DashboardActionButton>
      }
    >
      <VStack align='stretch' spacing={2}>
        <HStack>
          <Badge colorScheme={total > 0 ? 'green' : 'gray'}>
            {total > 0 ? 'Found' : 'Waiting'}
          </Badge>
          <Text fontSize='sm'>
            {total > 0
              ? `${total} certificate${total === 1 ? '' : 's'} in the inventory.`
              : 'No certificates have been reported yet.'}
          </Text>
        </HStack>
        {total === 0 ? (
          <Text fontSize='xs' color={muted}>
            {saved.infrastructure === 'windows'
              ? 'Discovery on Windows runs about every 30 minutes by default and reads the machine certificate store. Check that the agent service is running and that certificates exist in LocalMachine\\My. Private keys are never read.'
              : 'Discovery runs about once an hour by default. Make sure the folders you listed contain a PEM certificate and that the agent user can read them. Private keys are never read.'}
          </Text>
        ) : (
          <Text fontSize='sm'>
            Open Certificate Management, Certificates to inspect each one:
            identity, validity, observed locations and monitoring status.
          </Text>
        )}
      </VStack>
    </StepFrame>
  );
}

/**
 * Two honest outcomes. Generated files only ever reach "Configuration
 * prepared". "Distribution verified" requires a rollout that the control plane
 * recorded as verified, which in turn requires qualified agents.
 */
export function vaultOutcome({ declaredByAgents, distribution }) {
  const required = requiredCapabilities('vault', 'linux');
  const missing = required.filter(c => !declaredByAgents.includes(c));
  if (distribution?.verified) return { level: 'verified', missing: [] };
  if (missing.length === 0 && distribution?.groups > 0) {
    return { level: 'ready_to_roll_out', missing: [] };
  }
  return { level: 'prepared', missing };
}

export function VaultStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const saved = certopsProgress(ctx);
  const [form, setForm] = useState({
    vaultAddress: saved.vaultAddress || '',
    mount: saved.vaultMount || 'secret',
    groupId: saved.groupId || '',
    caFile: saved.vaultCaFile || '',
  });
  const set = key => e => setForm(f => ({ ...f, [key]: e.target.value }));
  const names = (saved.names || '').split(/[\s,]+/).filter(Boolean);
  const out = buildVaultConfigs({
    vaultAddress: form.vaultAddress,
    mount: form.mount,
    workspaceId: ctx.workspaceId,
    groupId: form.groupId,
    names,
    zone: saved.zone,
    dnsProvider: saved.dnsProvider || 'cloudflare',
    caEndpoint: saved.caEndpoint || undefined,
    caFile: form.caFile.trim(),
  });
  let policies = null;
  try {
    policies = buildVaultPolicies({
      mount: form.mount,
      workspaceId: ctx.workspaceId,
      groupId: form.groupId,
    });
  } catch (_) {
    policies = null;
  }
  const declared = (ctx.summary?.certops?.agents?.items || []).flatMap(
    a => a.declaredCapabilities || []
  );
  const outcome = vaultOutcome({
    declaredByAgents: declared,
    distribution: ctx.summary?.certops?.distribution,
  });
  const gap = capabilityGap('vault', 'linux', declared);

  return (
    <StepFrame
      kind='runbook'
      title='Share a certificate through Vault'
      description='The issuing agent publishes the certificate to your Vault and other agents pull and install it. TokenTimer never connects to Vault.'
      docs={[
        ...ctx.docs('certops.vault', 'Shared certificate runbook'),
        ...ctx.docs('certops.vaultAuth', 'Vault Agent authentication'),
      ]}
    >
      <VStack align='stretch' spacing={3}>
        <Alert status='warning' borderRadius='md' variant='left-accent'>
          <AlertIcon />
          <AlertDescription fontSize='sm'>
            Generating files below only prepares the configuration. It does not
            mean distribution works: a verified rollout does.
          </AlertDescription>
        </Alert>
        <HStack>
          <Badge
            colorScheme={outcome.level === 'verified' ? 'green' : 'orange'}
          >
            {outcome.level === 'verified'
              ? 'Distribution verified'
              : outcome.level === 'ready_to_roll_out'
                ? 'Ready to roll out'
                : 'Configuration prepared'}
          </Badge>
          {gap.length ? (
            <Text fontSize='xs' color={muted}>
              Agents do not yet declare: {gap.join(', ')}.
            </Text>
          ) : null}
        </HStack>
        <Text fontSize='sm'>
          First create an issue job that publishes to your Vault store. The
          group id appears on that job as publication.groupId; paste it here. Do
          not invent one.
        </Text>
        <HStack align='start' spacing={3} flexWrap='wrap'>
          <FormControl flex='2 1 240px'>
            <FormLabel fontSize='sm'>Vault address</FormLabel>
            <Input
              size='sm'
              value={form.vaultAddress}
              onChange={set('vaultAddress')}
              placeholder='https://vault.example.com:8200'
            />
          </FormControl>
          <FormControl flex='1 1 120px'>
            <FormLabel fontSize='sm'>KV v2 mount</FormLabel>
            <Input size='sm' value={form.mount} onChange={set('mount')} />
          </FormControl>
        </HStack>
        <FormControl>
          <FormLabel fontSize='sm'>Group id</FormLabel>
          <Input
            size='sm'
            value={form.groupId}
            onChange={set('groupId')}
            placeholder='from publication.groupId'
          />
        </FormControl>
        <FormControl>
          <FormLabel fontSize='sm'>Vault CA file (optional)</FormLabel>
          <Input
            size='sm'
            value={form.caFile}
            onChange={set('caFile')}
            placeholder='/etc/tokentimer-agent/vault-ca.pem'
          />
          <Text fontSize='xs' mt={1} color={muted}>
            Needed when Vault uses a private CA. The file stays on each host.
          </Text>
        </FormControl>
        {!out.ok
          ? (out.problems || []).map(p => (
              <Text key={p} fontSize='xs' color='red.400'>
                {p}
              </Text>
            ))
          : null}
        {policies ? (
          <>
            <CopyBlock
              label='Vault policy: issuer (separate policy)'
              text={policies.issuer}
            />
            <CopyBlock
              label='Vault policy: consumer (separate policy)'
              text={policies.consumer}
            />
            <CopyBlock
              label='Vault policy: scanner (mandatory deny)'
              text={policies.scanner}
            />
          </>
        ) : null}
        {out.ok ? (
          <>
            <CopyBlock
              label='Issuer agent config.json'
              text={JSON.stringify(out.issuer, null, 2)}
              language='json'
            />
            <CopyBlock
              label='Consumer agent config.json'
              text={JSON.stringify(out.consumer, null, 2)}
              language='json'
            />
            <Text fontSize='xs' color={muted}>
              Replace the REPLACE_WITH values with each agent&apos;s own wire id
              from its config. Each agent reads a Vault token file refreshed by
              Vault Agent. No Vault token is ever entered here.
            </Text>
          </>
        ) : null}
        <DashboardActionButton
          alignSelf='flex-start'
          variant='outline'
          onClick={() =>
            saveCertops(ctx, {
              vaultAddress: form.vaultAddress,
              vaultMount: form.mount,
              vaultCaFile: form.caFile.trim(),
              groupId: form.groupId,
              configReviewed: true,
            })
          }
          isDisabled={!out.ok}
        >
          Save these settings
        </DashboardActionButton>
      </VStack>
    </StepFrame>
  );
}
