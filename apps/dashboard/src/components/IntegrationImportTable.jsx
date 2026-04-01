import React from 'react';
import {
  Box,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Checkbox,
  Badge,
  HStack,
  VStack,
  Text,
  Tooltip,
  Button,
  useColorModeValue,
  Input,
  Select,
  IconButton,
  Alert,
  AlertIcon,
} from '@chakra-ui/react';
import { FiEdit2, FiCheck, FiAlertTriangle } from 'react-icons/fi';
import TruncatedText from './TruncatedText';
import { formatExpirationDate, isNeverExpires } from '../utils/dateUtils';

/**
 * Reusable component for displaying integration import tables
 * Used by all integrations (Vault, GitLab, GitHub, AWS, Azure, Azure AD, GCP)
 */
export default function IntegrationImportTable({
  items = [],
  selectedRows = new Set(),
  onToggleRow,
  onToggleAll,
  borderColor,
  getDetailsForItem,
  showCategory = false, // Optional: show category column (for Vault)
  onUpdateItem, // Callback to update item fields
  categoryOptions = ['cert', 'key_secret', 'license', 'general'], // Available categories
  editableFields: _editableFields = ['name', 'category', 'type'], // Which fields are editable (reserved for callers)
  duplicateIndices = new Set(), // Set of indices that are duplicates
}) {
  const [editingRow, setEditingRow] = React.useState(null);
  const [editValues, setEditValues] = React.useState({});
  const editingRowBg = useColorModeValue('yellow.50', 'yellow.900');
  const labelMutedColor = useColorModeValue('gray.600', 'gray.400');

  if (!items || items.length === 0) return null;

  const startEditing = index => {
    const item = items[index];
    setEditingRow(index);
    setEditValues({
      name: item.name || '',
      category: item.category || 'general',
      type: item.type || '',
      // Include all editable detail fields
      location: item.location || '',
      description: item.description || '',
      used_by: item.used_by || '',
      issuer: item.issuer || '',
      subject: item.subject || '',
      project: item.project || '',
      repository: item.repository || '',
      scope: item.scope || '',
    });
  };

  const saveEditing = index => {
    // Validate before saving
    const name = editValues.name?.trim() || '';
    if (name.length < 3 || name.length > 100) {
      return; // Don't save if invalid
    }

    if (onUpdateItem) {
      onUpdateItem(index, editValues);
    }
    setEditingRow(null);
    setEditValues({});
  };

  const isEditValid = () => {
    if (!editValues.name) return false;
    const name = editValues.name.trim();
    if (name.length < 3 || name.length > 100) return false;

    // Check field lengths
    const maxLengths = {
      location: 500,
      used_by: 500,
      issuer: 255,
      serial_number: 255,
      subject: 1000,
      algorithm: 100,
      license_type: 100,
      vendor: 255,
      renewal_url: 500,
      contacts: 500,
      section: 120,
      description: 10000,
    };

    for (const [field, maxLen] of Object.entries(maxLengths)) {
      if (editValues[field] && String(editValues[field]).length > maxLen) {
        return false;
      }
    }

    return true;
  };

  const cancelEditing = () => {
    setEditingRow(null);
    setEditValues({});
  };

  // Get allowed types for a given category
  const getTypesForCategory = category => {
    const typeMap = {
      cert: ['ssl_cert', 'tls_cert', 'code_signing', 'client_cert'],
      key_secret: [
        'api_key',
        'secret',
        'password',
        'encryption_key',
        'ssh_key',
      ],
      license: [
        'software_license',
        'service_subscription',
        'domain_registration',
      ],
      general: ['other', 'document', 'membership'],
    };
    return typeMap[category] || ['other'];
  };

  // Calculate how many selected items are duplicates
  const selectedDuplicateCount = Array.from(selectedRows).filter(i =>
    duplicateIndices.has(i)
  ).length;

  return (
    <Box>
      <HStack justify='space-between' mb={2}>
        <Text fontSize='sm'>
          Detected {items.length} item{items.length !== 1 ? 's' : ''}
        </Text>
        <Button size='xs' variant='outline' onClick={onToggleAll}>
          {selectedRows.size === items.length ? 'Deselect All' : 'Select All'}
        </Button>
      </HStack>
      {/* Warning banner for duplicates */}
      {duplicateIndices.size > 0 && selectedDuplicateCount > 0 && (
        <Alert status='warning' borderRadius='md' mb={2} py={2}>
          <AlertIcon />
          <Text fontSize='sm'>
            {selectedDuplicateCount} token
            {selectedDuplicateCount > 1 ? 's' : ''} already exist
            {selectedDuplicateCount === 1 ? 's' : ''} in this workspace.
            Importing will update the existing token
            {selectedDuplicateCount > 1 ? 's' : ''} with the new data.
          </Text>
        </Alert>
      )}
      <Box
        maxH='300px'
        overflowY='auto'
        border='1px solid'
        borderColor={borderColor}
        borderRadius='md'
      >
        <Table size='sm'>
          <Thead>
            <Tr>
              <Th w='36px'></Th>
              <Th>Name</Th>
              {showCategory && <Th>Category</Th>}
              <Th>Type</Th>
              <Th>Details</Th>
              <Th>Expires</Th>
              <Th w='60px'></Th>
            </Tr>
          </Thead>
          <Tbody>
            {items.map((item, index) => {
              const details = getDetailsForItem ? getDetailsForItem(item) : [];
              const isEditing = editingRow === index;

              return (
                <Tr key={index} bg={isEditing ? editingRowBg : 'transparent'}>
                  <Td>
                    <HStack spacing={1}>
                      <Checkbox
                        isChecked={selectedRows.has(index)}
                        onChange={() => onToggleRow(index)}
                        isDisabled={isEditing}
                      />
                      {duplicateIndices.has(index) && (
                        <Tooltip
                          label='This token already exists in this workspace. Importing will update the existing token with the new data.'
                          hasArrow
                          placement='top'
                        >
                          <Box as='span' color='orange.500' cursor='help'>
                            <FiAlertTriangle size={14} />
                          </Box>
                        </Tooltip>
                      )}
                    </HStack>
                  </Td>
                  <Td>
                    {isEditing ? (
                      <Input
                        value={editValues.name}
                        onChange={e =>
                          setEditValues({ ...editValues, name: e.target.value })
                        }
                        size='xs'
                        fontSize='sm'
                        maxLength={100}
                        isInvalid={
                          editValues.name.trim().length < 3 ||
                          editValues.name.length > 100
                        }
                      />
                    ) : (
                      <TruncatedText
                        text={item.name}
                        maxLines={3}
                        maxWidth='150px'
                        fontSize='sm'
                      />
                    )}
                  </Td>
                  {showCategory && (
                    <Td>
                      {isEditing ? (
                        <Select
                          value={editValues.category}
                          onChange={e => {
                            const newCategory = e.target.value;
                            const allowedTypes =
                              getTypesForCategory(newCategory);
                            // If current type is not valid for new category, pick first valid type
                            const newType = allowedTypes.includes(
                              editValues.type
                            )
                              ? editValues.type
                              : allowedTypes[0];
                            setEditValues({
                              ...editValues,
                              category: newCategory,
                              type: newType,
                            });
                          }}
                          size='xs'
                          fontSize='xs'
                        >
                          {categoryOptions.map(cat => (
                            <option key={cat} value={cat}>
                              {cat}
                            </option>
                          ))}
                        </Select>
                      ) : (
                        <Badge fontSize='xs'>
                          {String(item.category || 'general')}
                        </Badge>
                      )}
                    </Td>
                  )}
                  <Td>
                    {isEditing ? (
                      <Select
                        value={editValues.type}
                        onChange={e =>
                          setEditValues({ ...editValues, type: e.target.value })
                        }
                        size='xs'
                        fontSize='xs'
                      >
                        {getTypesForCategory(editValues.category).map(type => (
                          <option key={type} value={type}>
                            {type}
                          </option>
                        ))}
                      </Select>
                    ) : (
                      <Badge fontSize='xs'>{item.type}</Badge>
                    )}
                  </Td>
                  <Td>
                    {isEditing ? (
                      <VStack align='stretch' spacing={2}>
                        {[
                          'location',
                          'description',
                          'used_by',
                          'issuer',
                          'subject',
                          'project',
                          'repository',
                          'scope',
                        ].map(field => {
                          const fieldLabel = field
                            .split('_')
                            .map(w => w.charAt(0).toUpperCase() + w.slice(1))
                            .join(' ');
                          if (
                            editValues[field] !== undefined &&
                            editValues[field] !== null &&
                            String(editValues[field]).trim()
                          ) {
                            // Define max lengths per field
                            const maxLengths = {
                              location: 500,
                              used_by: 500,
                              issuer: 255,
                              serial_number: 255,
                              subject: 1000,
                              algorithm: 100,
                              license_type: 100,
                              vendor: 255,
                              renewal_url: 500,
                              contacts: 500,
                              description: 10000,
                              project: 500,
                              repository: 500,
                              scope: 500,
                            };
                            const maxLen = maxLengths[field] || 500;
                            const fieldValue = String(editValues[field] || '');

                            return (
                              <Box key={field}>
                                <Text
                                  fontSize='2xs'
                                  color={labelMutedColor}
                                  fontWeight='semibold'
                                  mb={1}
                                >
                                  {fieldLabel}:
                                </Text>
                                <Input
                                  value={editValues[field]}
                                  onChange={e =>
                                    setEditValues({
                                      ...editValues,
                                      [field]: e.target.value,
                                    })
                                  }
                                  size='xs'
                                  fontSize='xs'
                                  placeholder={fieldLabel}
                                  maxLength={maxLen}
                                  isInvalid={fieldValue.length > maxLen}
                                />
                                {fieldValue.length > maxLen * 0.9 && (
                                  <Text
                                    fontSize='2xs'
                                    color={
                                      fieldValue.length > maxLen
                                        ? 'red.500'
                                        : 'orange.500'
                                    }
                                  >
                                    {fieldValue.length}/{maxLen}
                                  </Text>
                                )}
                              </Box>
                            );
                          }
                          return null;
                        })}
                      </VStack>
                    ) : (
                      <VStack align='start' spacing={1}>
                        {details.map((detail, idx) => (
                          <Box key={idx}>
                            <Text
                              fontSize='2xs'
                              color={labelMutedColor}
                              fontWeight='semibold'
                            >
                              {detail.label}:
                            </Text>
                            {detail.badge ? (
                              <Badge
                                colorScheme={detail.badgeColor || 'purple'}
                                fontSize='2xs'
                              >
                                {detail.value}
                              </Badge>
                            ) : (
                              <TruncatedText
                                text={detail.value}
                                maxLines={detail.maxLines || 1}
                                maxWidth='200px'
                                fontSize='xs'
                              />
                            )}
                          </Box>
                        ))}
                      </VStack>
                    )}
                  </Td>
                  <Td>
                    <HStack spacing={1}>
                      <Text fontSize='sm'>
                        {formatExpirationDate(item.expiration, {
                          shortFormat: true,
                        })}
                      </Text>
                      {(isNeverExpires(item.expiration) ||
                        !item.expiration) && (
                        <Tooltip
                          label='This token type does not have an expiration date'
                          fontSize='xs'
                        >
                          <Badge colorScheme='blue' fontSize='2xs'>
                            ∞
                          </Badge>
                        </Tooltip>
                      )}
                    </HStack>
                  </Td>
                  <Td>
                    {isEditing ? (
                      <HStack spacing={1}>
                        <Tooltip
                          label={
                            !isEditValid()
                              ? 'Fix validation errors to save'
                              : 'Save changes'
                          }
                          fontSize='xs'
                        >
                          <IconButton
                            icon={<FiCheck />}
                            size='xs'
                            colorScheme='green'
                            onClick={() => saveEditing(index)}
                            aria-label='Save'
                            isDisabled={!isEditValid()}
                          />
                        </Tooltip>
                        <IconButton
                          icon={<Text fontSize='lg'>×</Text>}
                          size='xs'
                          variant='ghost'
                          onClick={cancelEditing}
                          aria-label='Cancel'
                        />
                      </HStack>
                    ) : (
                      <IconButton
                        icon={<FiEdit2 />}
                        size='xs'
                        variant='ghost'
                        onClick={() => startEditing(index)}
                        aria-label='Edit'
                      />
                    )}
                  </Td>
                </Tr>
              );
            })}
          </Tbody>
        </Table>
      </Box>
    </Box>
  );
}
