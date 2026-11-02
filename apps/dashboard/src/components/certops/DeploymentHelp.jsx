import { useState } from 'react';
import { Button, IconButton, Tooltip } from '@chakra-ui/react';
import { Info } from 'lucide-react';

export const refreshStatusHelp =
  'Reload the latest deployment status and evidence recorded by TokenTimer.';
export const providerRevisionHelp =
  'The immutable storage version: a numeric KV v2 revision or an opaque Azure Key Vault secret version. Consumers always fetch this exact version.';
const materialHelp =
  'The immutable TokenTimer ID for one certificate material record.';
const generationHelp = 'A sequence number for an approved deployment decision.';
export const deploymentFieldHelp = {
  'Expected version':
    'The certificate version this destination is expected and authorized to use, shown as the material store version.',
  'Last confirmed version':
    'The most recent certificate version confirmed by accepted deployment evidence. The service may have changed since this observation. The shown value is the material store version.',
  'Vault provider revision': providerRevisionHelp,
  'Provider version': providerRevisionHelp,
  'Last verification':
    'When TokenTimer last accepted verification evidence from this destination.',
  'Verification freshness':
    'How long the last verification remains current under the configured policy.',
  'Deployment status':
    'The current deployment state based on accepted, fresh evidence for the expected certificate and deployment decision.',
  'Verification policy':
    'The checks required before this destination counts as verified: serving and fingerprint checks, or those checks plus TLS trust validation.',
  'Verification policy code':
    'The configured verification policy. Served requires serving and fingerprint checks. Trust also requires TLS trust validation.',
  'Required destination':
    'When this destination is required, a failed or uncertain deployment pauses the rollout. Optional failures can leave the rollout degraded.',
  'Material version ID': materialHelp,
  'Expected material version ID': materialHelp,
  'Last confirmed material version ID': materialHelp,
  'Rollout generation': generationHelp,
  'Desired rollout generation': generationHelp,
  'Accepted rollout generation': generationHelp,
  'Freshness policy':
    'How long an accepted observation can remain current. Copy this duration to get its value in seconds.',
};

/** Chakra tooltip with an explicit tap toggle, as well as hover/focus and Escape dismissal. */
export default function DeploymentHelp({
  label,
  text,
  icon: Icon = Info,
  onAction,
  busy = false,
}) {
  const [pinned, setPinned] = useState(false);
  const [active, setActive] = useState(false);
  const open = pinned || active;
  const close = () => {
    setPinned(false);
    setActive(false);
  };
  const Trigger = onAction ? Button : IconButton;
  return (
    <Tooltip
      label={text}
      isOpen={open}
      onOpen={() => setActive(true)}
      onClose={() => setActive(false)}
      hasArrow
      placement='top'
      maxW='min(320px, calc(100vw - 32px))'
      closeOnClick={false}
      closeOnPointerDown={false}
    >
      <Trigger
        aria-label={onAction ? label : `About ${label}`}
        aria-expanded={onAction ? undefined : open}
        aria-busy={onAction ? busy : undefined}
        type='button'
        size='xs'
        variant='ghost'
        color='dashboard.modal.muted'
        minW={onAction ? undefined : '24px'}
        h={onAction ? '28px' : '24px'}
        flexShrink={0}
        {...(onAction
          ? { loadingText: label }
          : { icon: <Icon size={12} aria-hidden='true' /> })}
        isLoading={busy}
        onBlur={close}
        onKeyDown={event => {
          if (event.key === 'Escape' && open) {
            event.stopPropagation();
            close();
          }
        }}
        onClick={() => {
          if (onAction) {
            onAction();
            setPinned(true);
          } else setPinned(value => !value);
          setActive(false);
        }}
      >
        {onAction ? label : undefined}
      </Trigger>
    </Tooltip>
  );
}
