import {
  Box,
  Checkbox,
  CheckboxGroup,
  Text,
  VStack,
  useColorModeValue,
} from '@chakra-ui/react';
import { useContactGroupPluralWrites } from '../utils/contactGroupPluralWrites.jsx';

/**
 * Stacked contact-group checkboxes. Empty selection means workspace default.
 * When plural writes are off, checking a second group replaces the first.
 */
export default function ContactGroupCheckboxGroup({
  contactGroups = [],
  value = [],
  onChange,
  isDisabled = false,
  emptyText = 'No contact groups in this workspace.',
  helperText = 'Leave all unchecked to use the workspace default.',
  defaultContactGroupId = '',
  size = 'sm',
  maxH = { base: 'min(32vh, 240px)', md: '160px' },
  allowMultiple,
}) {
  const helperColor = useColorModeValue('gray.600', 'gray.400');
  const pluralWritesEnabled = useContactGroupPluralWrites();
  const canSelectMultiple =
    allowMultiple === undefined ? pluralWritesEnabled : allowMultiple === true;
  const selected = Array.isArray(value) ? value.map(String) : [];
  const groups = Array.isArray(contactGroups) ? contactGroups : [];
  const shownHelper = canSelectMultiple
    ? helperText
    : 'Select one contact group. Leave unchecked to use the workspace default.';

  if (groups.length === 0) {
    return (
      <Text fontSize='xs' color={helperColor}>
        {emptyText}
      </Text>
    );
  }

  return (
    <>
      <Box
        maxH={maxH}
        overflowY='auto'
        sx={{ WebkitOverflowScrolling: 'touch' }}
      >
        <CheckboxGroup
          colorScheme='blue'
          value={selected}
          onChange={vals => {
            const next = Array.isArray(vals) ? vals.map(String) : [];
            if (!canSelectMultiple && next.length > 1) {
              const added = next.find(id => !selected.includes(id));
              onChange?.(added ? [added] : next.slice(-1));
              return;
            }
            onChange?.(next);
          }}
          isDisabled={isDisabled}
        >
          <VStack align='stretch' spacing={2}>
            {groups.map(group => {
              const id = String(group.id);
              const isDefault =
                defaultContactGroupId && id === String(defaultContactGroupId);
              return (
                <Checkbox
                  key={id}
                  value={id}
                  size={size}
                  w='100%'
                  minH={{ base: '44px', md: 'auto' }}
                  py={{ base: 1, md: 0 }}
                >
                  {group.name}
                  {isDefault ? ' (default)' : ''}
                </Checkbox>
              );
            })}
          </VStack>
        </CheckboxGroup>
      </Box>
      {shownHelper ? (
        <Text fontSize='xs' mt={1} color={helperColor}>
          {shownHelper}
        </Text>
      ) : null}
    </>
  );
}
