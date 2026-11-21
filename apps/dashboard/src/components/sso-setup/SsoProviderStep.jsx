import { useEffect, useRef, useState } from 'react';
import { Link as RouterLink } from 'react-router';
import { Text, VStack } from '@chakra-ui/react';
import StepFrame from '../onboarding/StepFrame.jsx';
import { Callout, FactsList } from '../onboarding/panels.jsx';
import { DashboardActionButton } from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import SsoProviderWizard from '../../pages/SsoProviderWizard.jsx';
import { ssoFacts, providerReady } from './ssoSetupRules.js';
import { ssoDocs } from './ssoDocs.js';

// A multi-replica deployment applies a new provider to each process a few
// seconds after the save, so the summary is re-read for a while.
const POLL_MS = 3000;
const POLL_TRIES = 10;

export default function SsoProviderStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const [enabledSlug, setEnabledSlug] = useState(null);
  const refreshRef = useRef(ctx.refresh);
  refreshRef.current = ctx.refresh;
  const facts = ssoFacts(ctx.summary);
  const ready = providerReady(ctx.summary);

  useEffect(() => {
    if (!enabledSlug || ready) return undefined;
    let tries = 0;
    const timer = setInterval(() => {
      tries += 1;
      refreshRef.current?.();
      if (tries >= POLL_TRIES) clearInterval(timer);
    }, POLL_MS);
    return () => clearInterval(timer);
  }, [enabledSlug, ready]);

  const onEnabled = async slug => {
    setEnabledSlug(slug);
    await ctx.refresh();
  };

  if (ready) {
    const live = facts.providers.items.filter(p => p.enabled && p.signInReady);
    return (
      <StepFrame
        kind='ui'
        title='Connect your identity provider'
        description='Sign-in through your identity provider is enabled.'
        docs={ssoDocs(ctx)}
        actions={
          <DashboardActionButton
            as={RouterLink}
            to='/sso-providers'
            variant='outline'
          >
            Manage SSO providers
          </DashboardActionButton>
        }
      >
        <FactsList
          items={live.map(p => ({
            label: p.displayName || p.slug,
            value: `${String(p.type).toUpperCase()}, sign-in ready`,
          }))}
        />
      </StepFrame>
    );
  }

  if (!facts || facts.providers.enabled > 0 || enabledSlug) {
    return (
      <StepFrame
        kind='ui'
        title='Connect your identity provider'
        docs={ssoDocs(ctx)}
        actions={
          <>
            <DashboardActionButton
              variant='outline'
              onClick={() => ctx.refresh()}
            >
              Check status
            </DashboardActionButton>
            <DashboardActionButton
              as={RouterLink}
              to='/sso-providers'
              variant='outline'
            >
              Manage SSO providers
            </DashboardActionButton>
          </>
        }
      >
        <Text color={muted} role='status'>
          {facts
            ? 'Waiting for the provider to become ready to sign users in.'
            : 'Could not read SSO status. Check status to try again.'}
        </Text>
      </StepFrame>
    );
  }

  return (
    <StepFrame
      kind='ui'
      title='Connect your identity provider'
      description='Register TokenTimer in your identity provider, test the connection, then enable sign-in.'
      docs={ssoDocs(ctx)}
    >
      <VStack align='stretch' spacing={3}>
        <Callout kind='before'>
          <VStack align='stretch' spacing={1} fontSize='sm' color={muted}>
            <Text>
              <Text as='span' fontWeight='semibold'>
                OIDC:{' '}
              </Text>
              Have the issuer and client ID ready.
            </Text>
            <Text>
              <Text as='span' fontWeight='semibold'>
                SAML:{' '}
              </Text>
              Have the metadata URL ready.
            </Text>
            <Text>
              The wizard provides the callback or ACS values to register with
              your identity provider. Keep a working local administrator session
              and test a new SSO sign-in in a private browser window.
            </Text>
          </VStack>
        </Callout>
        <SsoProviderWizard embedded onEnabled={onEnabled} />
      </VStack>
    </StepFrame>
  );
}
