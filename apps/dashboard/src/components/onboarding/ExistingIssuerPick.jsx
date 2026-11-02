import { Box, Checkbox, Select, Text, VStack } from '@chakra-ui/react';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { issuerExistedBefore } from './adcsModel.js';

/** Issuers the operator may reuse: already in the workspace, pinned and safe. */
export function reusableIssuers(adcs) {
  return (adcs?.issuers || []).filter(
    i => issuerExistedBefore(i) && i.confirmed && i.safe
  );
}

function label(issuer) {
  const pair =
    issuer.caConfig && issuer.template
      ? `, ${issuer.caConfig}, template ${issuer.template}`
      : '';
  return `${issuer.name}${pair}`;
}

/**
 * "My Microsoft CA issuer is already set up": the explicit opt-in to reuse an
 * issuer of this workspace. Without it the guide creates a new issuer, so an
 * issuer that was there before the session never marks the step done.
 */
export default function ExistingIssuerPick({
  issuers,
  ticked,
  issuerId,
  onTick,
  onIssuer,
}) {
  const { muted } = useDashboardTheme();
  if (!issuers.length) return null;
  return (
    <VStack align='stretch' spacing={2} data-testid='existing-issuer-pick'>
      <Checkbox isChecked={ticked} onChange={e => onTick(e.target.checked)}>
        <Text fontSize='sm' fontWeight='semibold'>
          My Microsoft CA issuer is already set up
        </Text>
      </Checkbox>
      {ticked ? (
        <Box pl={6}>
          <Select
            size='sm'
            aria-label='Choose your issuer'
            placeholder='Choose an issuer'
            value={issuerId || ''}
            onChange={e => onIssuer(e.target.value)}
          >
            {issuers.map(i => (
              <option key={i.id} value={i.id}>
                {label(i)}
              </option>
            ))}
          </Select>
          <Text fontSize='xs' color={muted} mt={1}>
            Only issuers that passed their CA check and have a pinned CA
            certificate are listed.
          </Text>
        </Box>
      ) : null}
    </VStack>
  );
}
