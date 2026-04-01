import {
  Box,
  VStack,
  HStack,
  Text,
  Input,
  Select,
  useColorModeValue,
} from '@chakra-ui/react';

/**
 * Reusable component for bulk assignment of section and contact group
 * to selected integration items before import
 */
export default function BulkIntegrationAssignment({
  selectedCount = 0,
  section = '',
  onSectionChange,
  contactGroupId = '',
  onContactGroupChange,
  contactGroups = [],
  borderColor,
}) {
  const panelBg = useColorModeValue('blue.50', 'blue.900');
  const inputBg = useColorModeValue('white', 'gray.800');
  const helperTextColor = useColorModeValue('gray.600', 'gray.400');
  if (selectedCount === 0) return null;

  return (
    <Box
      border='1px solid'
      borderColor={borderColor}
      borderRadius='md'
      p={3}
      bg={panelBg}
    >
      <VStack align='stretch' spacing={3}>
        <Text fontSize='sm' fontWeight='semibold'>
          Assign to {selectedCount} selected item
          {selectedCount !== 1 ? 's' : ''}:
        </Text>

        <HStack spacing={3} flexWrap='wrap'>
          <Box minW='200px'>
            <Text fontSize='xs' mb={1} fontWeight='medium'>
              Section (optional)
            </Text>
            <Input
              placeholder='e.g., production, AWS, team-api'
              value={section}
              onChange={e => onSectionChange(e.target.value)}
              size='sm'
              bg={inputBg}
              maxLength={120}
              isInvalid={section.length > 120}
            />
            <Text
              fontSize='2xs'
              color={section.length > 108 ? 'orange.500' : 'gray.500'}
              mt={1}
              whiteSpace='pre-wrap'
            >
              {section.length > 108
                ? `${section.length}/120 characters`
                : 'Group tokens for better organization\nDefaults to the source of import, e.g; gitlab-pat'}
            </Text>
          </Box>

          <Box minW='200px'>
            <Text fontSize='xs' mb={1} fontWeight='medium'>
              Contact Group (optional)
            </Text>
            <Select
              value={contactGroupId}
              onChange={e => onContactGroupChange(e.target.value)}
              size='sm'
              bg={inputBg}
            >
              <option value=''>Use workspace default</option>
              {contactGroups.map(g => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </Select>
            <Text fontSize='2xs' color={helperTextColor} mt={1}>
              Override alert recipients
            </Text>
          </Box>
        </HStack>
      </VStack>
    </Box>
  );
}
