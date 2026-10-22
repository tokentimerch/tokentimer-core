import { useState } from 'react';
import { Box, Button, HStack, Text } from '@chakra-ui/react';
import ContactGroupCheckboxGroup from '../ContactGroupCheckboxGroup.jsx';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { SYNC_GROUP_EXPLANATION, describeSyncGroups } from './syncGroupLine.js';

/**
 * "Alerts for synced items go to: <group>" with a Change link. The group
 * picked at import time is the starting value, so the operator is asked once.
 */
export default function AutoSyncGroupLine({
  groupIds,
  onChange,
  contactGroups,
  defaultGroupId,
}) {
  const { muted } = useDashboardTheme();
  const [changing, setChanging] = useState(false);
  return (
    <Box data-testid='sync-group-line'>
      <HStack spacing={2} align='baseline' flexWrap='wrap'>
        <Text fontSize='sm'>
          Alerts for synced items go to:{' '}
          <Text as='span' fontWeight='semibold'>
            {describeSyncGroups(groupIds, contactGroups, defaultGroupId)}
          </Text>
        </Text>
        <Button
          variant='link'
          size='sm'
          colorScheme='blue'
          onClick={() => setChanging(v => !v)}
        >
          {changing ? 'Done' : 'Change'}
        </Button>
      </HStack>
      <Text fontSize='xs' color={muted} mt={1}>
        {SYNC_GROUP_EXPLANATION}
      </Text>
      {changing ? (
        <Box mt={2}>
          <ContactGroupCheckboxGroup
            contactGroups={contactGroups}
            value={groupIds}
            onChange={onChange}
            defaultContactGroupId={defaultGroupId}
            helperText='Leave empty to use the workspace default.'
            maxH='140px'
          />
        </Box>
      ) : null}
    </Box>
  );
}
