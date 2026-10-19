import { useState } from 'react';
import { IconButton, Tooltip } from '@chakra-ui/react';
import { Info } from 'lucide-react';

export const refreshStatusHelp =
  'Reload the latest deployment status and evidence recorded by TokenTimer. This does not trigger deployment or verification.';
export const providerRevisionHelp =
  'A revision assigned by Vault when it stores certificate material. It is separate from TokenTimer material IDs and rollout generations.';
const materialHelp =
  'The immutable TokenTimer ID for one certificate material record. It is not a Vault provider revision or a rollout generation.';
const generationHelp =
  'A sequence number for an approved deployment decision. It is not a certificate version.';
export const deploymentFieldHelp = {
  'Expected version':
    "The certificate version this destination is expected and authorized to use. The shown number is the Vault provider's storage revision, not a TokenTimer material ID or rollout generation.",
  'Last confirmed version':
    "The most recent certificate version confirmed by accepted deployment evidence. The service may have changed since this observation. The shown number is the Vault provider's storage revision.",
  'Vault provider revision': providerRevisionHelp,
  'Last verification':
    'When the last accepted observation was made at this destination. A successful job alone does not prove the certificate is still served now.',
  'Verification freshness':
    "How long the last verification remains current under the configured policy. This is not the certificate's expiration date.",
  'Deployment status':
    'Whether TokenTimer currently has accepted, fresh evidence for the expected certificate and deployment decision. Publication to Vault alone does not confirm deployment.',
  'Verification policy':
    'The checks required before this destination counts as verified: serving and fingerprint checks, or those checks plus TLS trust validation.',
  'Verification policy code':
    'The configured verification policy. Served requires serving and fingerprint checks; trust also requires TLS trust validation.',
  'Required destination':
    'When this destination is required, a failed or uncertain deployment pauses the rollout. Optional failures can leave the rollout degraded.',
  'Material version ID': materialHelp,
  'Expected material version ID': materialHelp,
  'Last confirmed material version ID': materialHelp,
  'Rollout generation': generationHelp,
  'Desired rollout generation': generationHelp,
  'Accepted rollout generation': generationHelp,
  'Freshness policy':
    'How long an accepted observation can remain current. The displayed duration is human-readable; copying it copies the raw number of seconds.',
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
      <IconButton
        aria-label={onAction ? label : `About ${label}`}
        aria-expanded={onAction ? undefined : open}
        aria-busy={onAction ? busy : undefined}
        type='button'
        size='xs'
        variant='ghost'
        color='dashboard.modal.muted'
        minW={onAction ? '28px' : '24px'}
        h={onAction ? '28px' : '24px'}
        flexShrink={0}
        icon={<Icon size={onAction ? 14 : 12} aria-hidden='true' />}
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
      />
    </Tooltip>
  );
}
