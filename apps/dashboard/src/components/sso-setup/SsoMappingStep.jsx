import { useEffect, useRef } from 'react';
import { Text, VStack } from '@chakra-ui/react';
import StepFrame from '../onboarding/StepFrame.jsx';
import { Callout } from '../onboarding/panels.jsx';
import { DashboardActionButton } from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import {
  SsoGroupMappingModal,
  SsoGroupMappingsSection,
  useSsoGroupMappings,
} from '../SsoGroupMappings.jsx';
import { SSO_STEP_MAPPING, mappingPresent, ssoFacts } from './ssoSetupRules.js';
import { ssoDocs } from './ssoDocs.js';

export default function SsoMappingStep({ ctx, reviewing = false }) {
  const { muted } = useDashboardTheme();
  const mappingsState = useSsoGroupMappings();
  const { mappings, mappingsLoading, mappingProviders } = mappingsState;
  const done = mappingPresent(ctx.summary);
  const facts = ssoFacts(ctx.summary);

  // The guide judges this step from the summary, so tell it when the list
  // changed (added, edited or removed here). A reload supplies a new array;
  // editing a mapping's provider can change readiness without changing its count.
  const refreshRef = useRef(ctx.refresh);
  refreshRef.current = ctx.refresh;
  const seen = useRef(null);
  useEffect(() => {
    if (mappingsLoading) return;
    if (seen.current !== null && seen.current !== mappings) {
      refreshRef.current?.();
    }
    seen.current = mappings;
  }, [mappingsLoading, mappings]);

  const ready = (facts?.providers.items || []).filter(
    p => p.enabled && p.signInReady
  );
  const names = ready.map(p => p.displayName || p.slug).join(', ');
  const hint = names
    ? `${names} can sign users in. Add at least one group mapping so SSO users receive workspace roles automatically.`
    : null;

  return (
    <StepFrame
      kind='ui'
      title='Map groups to roles'
      description='Bind identity provider groups to TokenTimer roles. Roles are reconciled on every SSO sign-in.'
      docs={ssoDocs(ctx)}
      actions={
        reviewing || done ? null : (
          <DashboardActionButton
            variant='outline'
            onClick={() => ctx.skip(SSO_STEP_MAPPING)}
          >
            Skip for now
          </DashboardActionButton>
        )
      }
    >
      <VStack align='stretch' spacing={3}>
        <Callout kind='check'>
          <VStack align='stretch' spacing={1} fontSize='sm' color={muted}>
            <Text>
              Match the group value exactly as your identity provider sends it.
            </Text>
            <Text>Microsoft Entra ID SAML often sends a group object ID.</Text>
            <Text>
              <Text as='span' fontWeight='semibold'>
                When it applies:{' '}
              </Text>
              At the user&apos;s next sign-in.
            </Text>
          </VStack>
        </Callout>
        <SsoGroupMappingsSection state={mappingsState} hint={hint} />
        <SsoGroupMappingModal state={mappingsState} />
        {mappingProviders.length === 0 && !mappingsLoading ? (
          <Text fontSize='sm' color={muted}>
            No SSO providers are configured yet.
          </Text>
        ) : null}
      </VStack>
    </StepFrame>
  );
}
