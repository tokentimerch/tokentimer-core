import { Box, Checkbox, Select, Text, VStack } from '@chakra-ui/react';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { distributionExistedBefore } from './distributionModel.js';

/** Verified distributions the operator may reuse: already in the workspace. */
export function reusableDistributions(distribution) {
  return (distribution?.items || []).filter(
    i => distributionExistedBefore(i) && i.verified
  );
}

function label(item) {
  const store = item.materialStoreRef ? String(item.materialStoreRef) : 'group';
  const short = String(item.id || '').slice(0, 8);
  return short ? `${store} (${short}…)` : store;
}

/**
 * "My Vault distribution is already set up": the explicit opt-in to reuse a
 * verified distribution of this workspace. Without it the guide expects a new
 * publish and rollout, so a distribution that was there before the session
 * never marks the step done.
 */
export default function ExistingDistributionPick({
  items,
  ticked,
  distributionId,
  onTick,
  onDistribution,
}) {
  const { muted } = useDashboardTheme();
  if (!items.length) return null;
  return (
    <VStack
      align='stretch'
      spacing={2}
      data-testid='existing-distribution-pick'
    >
      <Checkbox isChecked={ticked} onChange={e => onTick(e.target.checked)}>
        <Text fontSize='sm' fontWeight='semibold'>
          My Vault distribution is already set up
        </Text>
      </Checkbox>
      {ticked ? (
        <Box pl={6}>
          <Select
            size='sm'
            aria-label='Choose your distribution'
            placeholder='Choose a distribution'
            value={distributionId || ''}
            onChange={e => onDistribution(e.target.value)}
          >
            {items.map(i => (
              <option key={i.id} value={i.id}>
                {label(i)}
              </option>
            ))}
          </Select>
          <Text fontSize='xs' color={muted} mt={1}>
            Only distribution groups with a verified rollout are listed.
          </Text>
        </Box>
      ) : null}
    </VStack>
  );
}
