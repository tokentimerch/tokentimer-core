import { Box, Button, FormHelperText } from '@chakra-ui/react';

/** The names a selection of contact group ids resolves to, in list order. */
export function selectedGroupNames(selectedIds, groups) {
  const chosen = new Set((selectedIds || []).map(String));
  return (groups || []).filter(g => chosen.has(String(g.id))).map(g => g.name);
}

/**
 * One line under the "Who gets alerted" picker saying where alerts will go,
 * with a way back to the picker. Hidden when nothing is selected, because the
 * picker's own hint already covers falling back to the default group.
 */
export function AlertsGoTo({ selectedIds, groups, defaultId, pickerRef }) {
  const names = selectedGroupNames(selectedIds, groups);
  if (names.length === 0) return null;
  const onlyDefault =
    defaultId &&
    selectedIds.length === 1 &&
    String(selectedIds[0]) === String(defaultId);
  const change = () => {
    pickerRef?.current?.querySelector('button')?.focus();
  };
  return (
    <FormHelperText fontSize='xs' data-testid='alerts-go-to'>
      <Box as='span'>
        Alerts will go to: {names.join(', ')}
        {onlyDefault ? ' (workspace default group)' : ''}{' '}
      </Box>
      <Button
        variant='link'
        size='xs'
        fontWeight='normal'
        onClick={change}
        aria-label='Change who gets alerted'
      >
        (change)
      </Button>
    </FormHelperText>
  );
}
