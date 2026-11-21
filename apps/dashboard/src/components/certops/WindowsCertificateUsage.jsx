import {
  Box,
  Button,
  Checkbox,
  HStack,
  Text,
  Select,
  Link,
  VStack,
} from '@chakra-ui/react';
import { useState } from 'react';

// The observation's server-generated source reference is scoped to the agent
// and host. A matching fingerprint alone is not enough to join two servers.
export function windowsUsageGroups(sources, identityId) {
  const groups = new Map();
  for (const source of sources || []) {
    if (
      source.source !== 'agent_windows' ||
      source.endedAt ||
      source.periodEndedAt ||
      source.currentIdentityId !== identityId ||
      typeof source.sourceRef !== 'string'
    )
      continue;
    const match = source.sourceRef.match(
      /^([^/]+)\/([^/]+)\/(windows_store|iis_binding)\/(.+)$/
    );
    if (!match) continue;
    const [, agent, host, kind, reference] = match;
    const key = `${agent}/${host}`;
    const group = groups.get(key) || { key, host, stores: [], bindings: [] };
    if (kind === 'windows_store') {
      const store = reference.match(/^LocalMachine\/([^/]+)(?:\/|$)/i);
      if (store)
        group.stores.push({ ...source, store: `LocalMachine\\${store[1]}` });
    } else {
      group.bindings.push({ ...source, binding: reference });
    }
    groups.set(key, group);
  }
  return [...groups.values()].filter(
    group => group.stores.length && group.bindings.length
  );
}

export default function WindowsCertificateUsage({
  groups = [],
  certificateName,
  onSelect,
  onToggle,
  canManage,
  busy,
  profiles = [],
  onProfile,
  workspaceId,
}) {
  const [editing, setEditing] = useState('');
  const [profileId, setProfileId] = useState('');
  if (!groups.length) return null;
  return (
    <VStack align='stretch' spacing={3} mb={4}>
      {groups.map(group => (
        <Box
          key={group.periodId}
          borderWidth='1px'
          borderColor='dashboard.modal.border'
          borderRadius='lg'
          p={4}
        >
          <HStack justify='space-between' align='start'>
            <Box>
              <Text fontWeight='semibold'>
                {certificateName || 'Windows certificate'}
              </Text>
              <Text fontSize='sm' color='dashboard.modal.muted'>
                {group.host} › {group.store}
              </Text>
            </Box>
            <Button
              size='xs'
              variant='outline'
              onClick={() => {
                onSelect?.(group.managedCertificateId);
                setProfileId(group.profileId || '');
                setEditing(editing === group.periodId ? '' : group.periodId);
              }}
            >
              Renewal settings
            </Button>
          </HStack>
          {editing === group.periodId ? (
            <VStack align='stretch' spacing={2} mt={3}>
              <Select
                size='sm'
                aria-label='Windows Store renewal profile'
                value={profileId}
                onChange={event => setProfileId(event.target.value)}
              >
                <option value=''>Choose a Store renewal profile</option>
                {profiles
                  .filter(
                    profile =>
                      profile.renewalProfile?.target?.type ===
                        'windows-cert-store' &&
                      profile.renewalProfile.target.store === 'My'
                  )
                  .map(profile => (
                    <option key={profile.id} value={profile.id}>
                      {profile.name}
                    </option>
                  ))}
              </Select>
              <Text fontSize='xs' color='dashboard.modal.muted'>
                Choose a Windows Store profile from{' '}
                <Link
                  href={`/certops/renewals?workspace=${encodeURIComponent(workspaceId || '')}`}
                  textDecoration='underline'
                >
                  Renewal profiles
                </Link>
                . Replacing management starts a new period; enable IIS updates
                again after saving.
              </Text>
              <Button
                size='xs'
                alignSelf='start'
                isDisabled={
                  !canManage ||
                  busy ||
                  !profileId ||
                  profileId === group.profileId
                }
                onClick={async () => {
                  if (await onProfile?.(group, profileId)) setEditing('');
                }}
              >
                Save renewal settings
              </Button>
            </VStack>
          ) : null}
          <Text fontSize='sm' mt={3}>
            Renewal:{' '}
            <Box as='span' fontWeight='semibold'>
              {group.profileName || 'Not configured'}
            </Box>
          </Text>
          <Box mt={4}>
            <Text fontSize='sm' fontWeight='semibold'>
              IIS bindings
            </Text>
            <Text fontSize='xs' color='dashboard.modal.muted' mt={1}>
              Choose which bindings receive the renewed certificate.
            </Text>
            <VStack align='stretch' spacing={3} mt={3}>
              {group.bindings.map(binding => (
                <Box
                  key={binding.targetId}
                  borderTopWidth='1px'
                  borderColor='dashboard.modal.border'
                  pt={3}
                >
                  <HStack justify='space-between' align='start'>
                    <Box>
                      <Text fontSize='sm' fontWeight='medium'>
                        {binding.site}:{binding.port}
                        {binding.sniHost ? ` · ${binding.sniHost}` : ''}
                      </Text>
                    </Box>
                    <Checkbox
                      size='sm'
                      isChecked={binding.automaticUpdate}
                      isDisabled={
                        !canManage ||
                        busy ||
                        (!binding.automaticUpdate && !binding.canEnable)
                      }
                      onChange={event =>
                        onToggle?.(group, binding, event.target.checked)
                      }
                      aria-label={`Automatically update ${binding.site}:${binding.port}${binding.sniHost ? ` ${binding.sniHost}` : ''}`}
                    >
                      Update after renewal
                    </Checkbox>
                  </HStack>
                  <Text
                    fontSize='xs'
                    color={
                      binding.deployment === 'conflict' ||
                      binding.lastResult?.updated === false
                        ? 'orange.400'
                        : 'dashboard.modal.muted'
                    }
                    mt={1}
                  >
                    {binding.deployment === 'conflict'
                      ? 'Existing IIS renewal profile: stop that registration’s renewal before enabling Store updates.'
                      : binding.relationship === 'absent'
                        ? 'Binding removed. It will not be recreated; Store renewal continues.'
                        : binding.relationship === 'changed'
                          ? 'Binding uses a different certificate. No automatic update will be made.'
                          : binding.relationship === 'unknown'
                            ? 'Presence unconfirmed. Check the agent and discovery status.'
                            : binding.lastResult?.updated === false
                              ? `Last update needs attention (${binding.lastResult.code}). See job evidence.`
                              : binding.automaticUpdate
                                ? 'Included in future Store renewals.'
                                : 'Not included in automatic updates.'}
                  </Text>
                </Box>
              ))}
            </VStack>
            {group.readinessReason ? (
              <Text fontSize='xs' color='orange.400' mt={3}>
                {group.readinessReason}
              </Text>
            ) : null}
          </Box>
        </Box>
      ))}
    </VStack>
  );
}
