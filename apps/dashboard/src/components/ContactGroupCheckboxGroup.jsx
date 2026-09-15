import {
  Box,
  Checkbox,
  CheckboxGroup,
  Text,
  VStack,
  useColorModeValue,
} from '@chakra-ui/react';

/**
 * Stacked contact-group checkboxes. Empty selection means workspace default.
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
}) {
  const helperColor = useColorModeValue('gray.600', 'gray.400');
  const selected = Array.isArray(value) ? value.map(String) : [];
  const groups = Array.isArray(contactGroups) ? contactGroups : [];

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
          onChange={vals =>
            onChange?.(Array.isArray(vals) ? vals.map(String) : [])
          }
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
      {helperText ? (
        <Text fontSize='xs' mt={1} color={helperColor}>
          {helperText}
        </Text>
      ) : null}
    </>
  );
}
