import { useState, useEffect, useMemo, useCallback, memo } from 'react';
import {
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  Box,
  Heading,
  Text,
  Button,
  Grid,
  GridItem,
  Badge,
  HStack,
  VStack,
  Divider,
  Input,
  Textarea,
  Select,
  Tooltip,
  useColorModeValue,
} from '@chakra-ui/react';
import { getColorFromString } from '../styles/colors.js';
import { formatDate, tokenAPI } from '../utils/apiClient';

/**
 * Token Detail Modal Component
 * Displays detailed information about a token with inline editing capability
 */
function TokenDetailModal({
  token,
  isOpen,
  onClose,
  TOKEN_CATEGORIES,
  onTokenUpdated,
  isViewer,
  contactGroups,
  workspaceContacts = [],
}) {
  const bgColor = useColorModeValue('gray.100', 'gray.800');
  const textColor = useColorModeValue('gray.800', 'white');
  const labelColor = useColorModeValue('gray.600', 'gray.400');
  const inputBg = useColorModeValue('rgba(255, 255, 255, 0.95)', 'gray.700');
  const inputBorder = useColorModeValue('gray.400', 'gray.600');
  const [_saving, setSaving] = useState(false);
  const [_saveError, setSaveError] = useState('');
  const [isEditing, setIsEditing] = useState(false);
  const [editData, setEditData] = useState({
    name: token?.name || '',
    section: Array.isArray(token?.section)
      ? token.section.join(', ')
      : token?.section || '',
    expiresAt: token?.expiresAt || '',
    domains: Array.isArray(token?.domains)
      ? token.domains.join(', ')
      : token?.domains || '',
    location: token?.location || '',
    used_by: token?.used_by || '',
    issuer: token?.issuer || '',
    serial_number: token?.serial_number || '',
    subject: token?.subject || '',
    key_size: token?.key_size || '',
    algorithm: token?.algorithm || '',
    license_type: token?.license_type || '',
    vendor: token?.vendor || '',
    cost: token?.cost || '',
    renewal_url: token?.renewal_url || '',
    renewal_date: token?.renewal_date || '',
    contacts: token?.contacts || '',
    description: token?.description || '',
    notes: token?.notes || '',
    contact_group_id: token?.contact_group_id || '',
  });

  // Memoize category/type lookups to avoid recomputing on every render
  const category = useMemo(
    () => TOKEN_CATEGORIES.find(cat => cat.value === token?.category),
    [TOKEN_CATEGORIES, token?.category]
  );
  const type = useMemo(
    () => category?.types.find(t => t.value === token?.type),
    [category, token?.type]
  );

  useEffect(() => {
    if (token) {
      setSaveError('');
      setEditData({
        name: token?.name || '',
        section: Array.isArray(token?.section)
          ? token.section.join(', ')
          : token?.section || '',
        expiresAt: token?.expiresAt || '',
        domains: Array.isArray(token?.domains)
          ? token.domains.join(', ')
          : token?.domains || '',
        location: token?.location || '',
        used_by: token?.used_by || '',
        issuer: token?.issuer || '',
        serial_number: token?.serial_number || '',
        subject: token?.subject || '',
        key_size: token?.key_size || '',
        algorithm: token?.algorithm || '',
        license_type: token?.license_type || '',
        vendor: token?.vendor || '',
        cost: token?.cost || '',
        renewal_url: token?.renewal_url || '',
        renewal_date: token?.renewal_date || '',
        contacts: token?.contacts || '',
        description: token?.description || '',
        notes: token?.notes || '',
        contact_group_id: token?.contact_group_id || '',
      });
    }
  }, [token]);

  const renderRenewalInfo = useCallback(() => {
    const renewalInfo = [];
    if (token?.renewal_url) renewalInfo.push(`URL: ${token.renewal_url}`);
    if (token?.renewal_date)
      renewalInfo.push(`Date: ${formatDate(token.renewal_date)}`);
    if (token?.contacts) renewalInfo.push(`Contact: ${token.contacts}`);

    if (renewalInfo.length === 0) return null;

    return (
      <GridItem colSpan={2}>
        <Box>
          <Text fontSize='sm' fontWeight='medium' color={labelColor} mb={1}>
            Renewal Information
          </Text>
          <VStack align='start' spacing={1}>
            {renewalInfo.map((info, index) => (
              <Text key={index} fontSize='md' color={textColor}>
                {info}
              </Text>
            ))}
          </VStack>
        </Box>
      </GridItem>
    );
  }, [
    token?.renewal_url,
    token?.renewal_date,
    token?.contacts,
    labelColor,
    textColor,
  ]);

  const handleSave = useCallback(async () => {
    try {
      setSaving(true);
      setSaveError('');
      const payload = { ...editData };
      if (typeof payload.section === 'string' && payload.section.trim()) {
        payload.section = payload.section
          .split(',')
          .map(s => s.trim())
          .filter(Boolean);
      } else if (payload.section === '') {
        payload.section = null;
      }
      if (typeof payload.domains === 'string' && payload.domains.trim()) {
        payload.domains = payload.domains
          .split(',')
          .map(d => d.trim())
          .filter(Boolean);
      } else if (payload.domains === '') {
        payload.domains = null;
      }
      if (
        payload.expiresAt &&
        typeof payload.expiresAt === 'string' &&
        !payload.expiresAt.includes('T')
      ) {
      }
      if (
        payload.key_size !== undefined &&
        String(payload.key_size).trim() !== ''
      ) {
        const ks = parseInt(payload.key_size, 10);
        payload.key_size = Number.isFinite(ks) ? ks : null;
      } else {
        payload.key_size = null;
      }
      if (payload.cost !== undefined && String(payload.cost).trim() !== '') {
        const c = parseFloat(payload.cost);
        payload.cost = Number.isFinite(c) ? c : null;
      } else {
        payload.cost = null;
      }
      [
        'section',
        'location',
        'used_by',
        'issuer',
        'serial_number',
        'subject',
        'algorithm',
        'license_type',
        'vendor',
        'renewal_url',
        'renewal_date',
        'contacts',
        'description',
        'notes',
      ].forEach(k => {
        if (payload[k] !== undefined && String(payload[k]).trim() === '')
          payload[k] = null;
      });
      const updated = await tokenAPI.updateToken(token?.id, payload);
      onTokenUpdated && onTokenUpdated(updated);
      setIsEditing(false);
    } catch (err) {
      setSaveError(
        err?.response?.data?.error || err?.message || 'Failed to update token'
      );
    } finally {
      setSaving(false);
    }
  }, [editData, token?.id, onTokenUpdated]);

  const contactGroupOptions = useMemo(
    () => (
      <>
        <option value=''>Use workspace default</option>
        {Array.isArray(contactGroups) &&
          contactGroups.map(g => (
            <option key={g.id} value={g.id}>
              {g.name}
            </option>
          ))}
      </>
    ),
    [contactGroups]
  );

  const workspaceContactOptions = useMemo(
    () =>
      (Array.isArray(workspaceContacts) ? workspaceContacts : []).map(c => {
        const name = [c.first_name, c.last_name]
          .filter(Boolean)
          .join(' ')
          .trim();
        const phone = (c.phone_e164 || '').trim();
        const parts = [name, phone].filter(Boolean);
        const label = parts.join(' - ');
        return <option key={c.id} value={label} />;
      }),
    [workspaceContacts]
  );

  if (!token) return null;

  const renderField = (label, value, isMultiline = false) => {
    if (!value) return null;

    return (
      <GridItem colSpan={{ base: 1, md: 1 }}>
        <Box>
          <Text fontSize='sm' fontWeight='medium' color={labelColor} mb={1}>
            {label}
          </Text>
          {isMultiline ? (
            <Text fontSize='md' color={textColor} whiteSpace='pre-wrap'>
              {value}
            </Text>
          ) : (
            <Text fontSize='md' color={textColor}>
              {value}
            </Text>
          )}
        </Box>
      </GridItem>
    );
  };

  const renderDateField = (label, value) => {
    if (!value) return null;

    return (
      <GridItem colSpan={{ base: 1, md: 1 }}>
        <Box>
          <Text fontSize='sm' fontWeight='medium' color={labelColor} mb={1}>
            {label}
          </Text>
          <Text fontSize='md' color={textColor}>
            {formatDate(value)}
          </Text>
        </Box>
      </GridItem>
    );
  };

  // Inline editable field renderers
  const renderEditable = (
    label,
    key,
    displayValue,
    { multiline = false, type = 'text', inputProps = {} } = {}
  ) => {
    return (
      <GridItem colSpan={{ base: 1, md: multiline ? 2 : 1 }}>
        <Box>
          <Text fontSize='sm' fontWeight='medium' color={labelColor} mb={1}>
            {label}
          </Text>
          {isEditing ? (
            multiline ? (
              <Textarea
                value={editData[key] ?? ''}
                onChange={e =>
                  setEditData(d => ({ ...d, [key]: e.target.value }))
                }
                bg={inputBg}
                borderColor={inputBorder}
                {...inputProps}
              />
            ) : (
              <Input
                type={type}
                value={editData[key] ?? ''}
                onChange={e =>
                  setEditData(d => ({ ...d, [key]: e.target.value }))
                }
                bg={inputBg}
                borderColor={inputBorder}
                {...inputProps}
              />
            )
          ) : (
            <Text
              fontSize='md'
              color={textColor}
              whiteSpace={multiline ? 'pre-wrap' : 'normal'}
            >
              {displayValue || '-'}
            </Text>
          )}
        </Box>
      </GridItem>
    );
  };

  const renderEditableSelect = (label, key, options) => {
    return (
      <GridItem colSpan={2}>
        <Box>
          <Text fontSize='sm' fontWeight='medium' color={labelColor} mb={1}>
            {label}
          </Text>
          {isEditing ? (
            <Select
              value={editData[key] || ''}
              onChange={e =>
                setEditData(d => ({ ...d, [key]: e.target.value }))
              }
            >
              {options}
            </Select>
          ) : (
            <Text fontSize='md' color={textColor}>
              {(() => {
                const id = editData[key] || '';
                if (!id) return 'Use workspace default';
                const g = Array.isArray(contactGroups)
                  ? contactGroups.find(x => String(x.id) === String(id))
                  : null;
                return g ? g.name : 'Use workspace default';
              })()}
            </Text>
          )}
        </Box>
      </GridItem>
    );
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} size='xl' scrollBehavior='inside'>
      <ModalOverlay />
      <ModalContent bg={bgColor} maxW='800px'>
        <ModalHeader>
          <Box
            display='flex'
            alignItems='center'
            justifyContent='space-between'
          >
            <Box>
              <Heading size='md' color={textColor}>
                {token.name}
              </Heading>
              <Text fontSize='sm' color={labelColor} mt={1}>
                {category?.label} • {type?.label || token.type}
              </Text>
            </Box>
            <Badge
              colorScheme={category?.color || 'gray'}
              variant='subtle'
              fontSize='sm'
              px={3}
              py={1}
            >
              {category?.label}
            </Badge>
          </Box>
        </ModalHeader>
        <ModalCloseButton />

        <ModalBody pb={6}>
          <Grid templateColumns={{ base: '1fr', md: 'repeat(2, 1fr)' }} gap={6}>
            {/* Basic Information */}
            <GridItem colSpan={2}>
              <Text
                fontSize='lg'
                fontWeight='semibold'
                color={textColor}
                mb={4}
              >
                Basic Information
              </Text>
            </GridItem>

            {/* Token ID - non-editable identifier */}
            {renderField('Token ID', token.id)}

            {isEditing ? (
              <Tooltip label='Cannot edit type' hasArrow placement='top'>
                <Box cursor='not-allowed' opacity={0.8}>
                  {renderField('Type', type?.label || token.type)}
                </Box>
              </Tooltip>
            ) : (
              renderField('Type', type?.label || token.type)
            )}
            {isEditing ? (
              <Tooltip label='Cannot edit category' hasArrow placement='top'>
                <Box cursor='not-allowed' opacity={0.8}>
                  {renderField('Category', category?.label)}
                </Box>
              </Tooltip>
            ) : (
              renderField('Category', category?.label)
            )}
            {renderEditable('Name', 'name', token.name, {
              inputProps: { maxLength: 100 },
            })}
            {isEditing ? (
              renderEditable(
                'Section (labels, comma-separated)',
                'section',
                Array.isArray(token.section)
                  ? token.section.join(', ')
                  : token.section,
                {
                  inputProps: {
                    maxLength: 255,
                    placeholder: 'e.g., prod, AWS, security team',
                  },
                }
              )
            ) : (
              <GridItem colSpan={1}>
                <Box>
                  <Text
                    fontSize='sm'
                    fontWeight='medium'
                    color={labelColor}
                    mb={1}
                  >
                    Section
                  </Text>
                  <HStack spacing={2} flexWrap='wrap'>
                    {(() => {
                      const sections = Array.isArray(token.section)
                        ? token.section.flatMap(s =>
                            typeof s === 'string' ? s.split(',') : [s]
                          )
                        : typeof token.section === 'string' && token.section
                          ? token.section.split(',')
                          : [];

                      const cleanSections = sections
                        .map(s => String(s || '').trim())
                        .filter(Boolean);

                      if (cleanSections.length > 0) {
                        return cleanSections.map((s, i) => (
                          <Badge
                            key={i}
                            colorScheme={getColorFromString(s)}
                            variant='subtle'
                          >
                            {s}
                          </Badge>
                        ));
                      }
                      return (
                        <Text fontSize='md' color={textColor}>
                          -
                        </Text>
                      );
                    })()}
                  </HStack>
                </Box>
              </GridItem>
            )}
            {renderEditableSelect(
              'Contact group (alerts)',
              'contact_group_id',
              contactGroupOptions
            )}

            {isEditing
              ? renderEditable(
                  'Expiration Date',
                  'expiresAt',
                  token.expiresAt,
                  { type: 'date' }
                )
              : renderDateField('Expiration Date', token.expiresAt)}
            {renderDateField('Created', token.created_at)}
            {renderDateField('Imported At', token.imported_at)}
            {renderDateField('Last Used', token.last_used)}
            {renderDateField('Last Updated', token.updated_at)}
            {renderField('Privileges/Scopes', token.privileges)}

            {/* Category-specific fields */}
            {token.category === 'cert' && (
              <>
                <GridItem colSpan={2}>
                  <Divider my={4} />
                  <Text
                    fontSize='lg'
                    fontWeight='semibold'
                    color={textColor}
                    mb={4}
                  >
                    Certificate Details
                  </Text>
                </GridItem>

                {(isEditing ||
                  (Array.isArray(token.domains) && token.domains.length)) &&
                  renderEditable(
                    'Domains',
                    'domains',
                    Array.isArray(token.domains)
                      ? token.domains.join(', ')
                      : token.domains,
                    {
                      inputProps: {
                        maxLength: 500,
                        placeholder: 'example.com, www.example.com',
                      },
                    }
                  )}
                {(isEditing || token.issuer) &&
                  renderEditable('Issuer', 'issuer', token.issuer, {
                    inputProps: {
                      maxLength: 100,
                      placeholder: "Let's Encrypt, DigiCert",
                    },
                  })}
                {(isEditing || token.serial_number) &&
                  renderEditable(
                    'Serial Number',
                    'serial_number',
                    token.serial_number,
                    { inputProps: { maxLength: 50, placeholder: 'Optional' } }
                  )}
                {(isEditing || token.subject) &&
                  renderEditable('Subject', 'subject', token.subject, {
                    multiline: true,
                    inputProps: {
                      maxLength: 300,
                      placeholder: 'CN=example.com, O=Example Corp, C=US',
                    },
                  })}
                {isEditing
                  ? renderEditable(
                      'Renewal URL',
                      'renewal_url',
                      token.renewal_url,
                      {
                        type: 'url',
                        inputProps: {
                          maxLength: 500,
                          placeholder: 'https://provider.com/renew',
                        },
                      }
                    )
                  : token.renewal_url &&
                    renderEditable(
                      'Renewal URL',
                      'renewal_url',
                      token.renewal_url,
                      {
                        type: 'url',
                        inputProps: { maxLength: 500 },
                      }
                    )}
                {(isEditing || token.contacts) &&
                  (isEditing ? (
                    <GridItem colSpan={{ base: 1, md: 1 }}>
                      <Box>
                        <Text
                          fontSize='sm'
                          fontWeight='medium'
                          color={labelColor}
                          mb={1}
                        >
                          Contacts (Key custodian)
                        </Text>
                        <Input
                          type='text'
                          value={editData.contacts || ''}
                          onChange={e =>
                            setEditData(d => ({
                              ...d,
                              contacts: e.target.value,
                            }))
                          }
                          bg={inputBg}
                          borderColor={inputBorder}
                          list='workspace-contacts-suggestions'
                          placeholder='Who manages this certificate?'
                          maxLength={200}
                        />
                      </Box>
                    </GridItem>
                  ) : (
                    renderEditable(
                      'Contacts (Key custodian)',
                      'contacts',
                      token.contacts,
                      {
                        inputProps: {
                          maxLength: 200,
                          placeholder: 'Who manages this certificate?',
                        },
                      }
                    )
                  ))}
              </>
            )}

            {token.category === 'key_secret' && (
              <>
                <GridItem colSpan={2}>
                  <Divider my={4} />
                  <Text
                    fontSize='lg'
                    fontWeight='semibold'
                    color={textColor}
                    mb={4}
                  >
                    Key/Secret Details
                  </Text>
                </GridItem>

                {(isEditing || token.location) &&
                  renderEditable('Locations', 'location', token.location, {
                    multiline: true,
                    inputProps: {
                      maxLength: 1000,
                      placeholder: 'One location per line',
                      rows: 3,
                    },
                  })}
                {(isEditing || token.used_by) &&
                  renderEditable('Used By', 'used_by', token.used_by, {
                    inputProps: {
                      maxLength: 200,
                      placeholder: 'Application, service',
                    },
                  })}
                {(isEditing || token.description) &&
                  renderEditable(
                    'Description',
                    'description',
                    token.description,
                    {
                      multiline: true,
                      inputProps: {
                        maxLength: 300,
                        placeholder: 'Use case or context for this key/secret',
                      },
                    }
                  )}
                {(() => {
                  const allowAlgo = ['encryption_key', 'ssh_key'].includes(
                    token.type
                  );
                  return (
                    (isEditing ? allowAlgo : !!token.algorithm) &&
                    renderEditable('Algorithm', 'algorithm', token.algorithm, {
                      inputProps: {
                        maxLength: 50,
                        placeholder: 'AES-256, RSA',
                      },
                    })
                  );
                })()}
                {(() => {
                  const allowSize = ['encryption_key', 'ssh_key'].includes(
                    token.type
                  );
                  return (
                    (isEditing ? allowSize : !!token.key_size) &&
                    renderEditable('Key Size', 'key_size', token.key_size, {
                      type: 'number',
                      inputProps: { min: 1, step: 1, placeholder: '256, 2048' },
                    })
                  );
                })()}
                {isEditing
                  ? renderEditable(
                      'Renewal URL',
                      'renewal_url',
                      token.renewal_url,
                      {
                        type: 'url',
                        inputProps: {
                          maxLength: 500,
                          placeholder: 'https://provider.com/renew',
                        },
                      }
                    )
                  : token.renewal_url &&
                    renderEditable(
                      'Renewal URL',
                      'renewal_url',
                      token.renewal_url,
                      {
                        type: 'url',
                        inputProps: { maxLength: 500 },
                      }
                    )}
                {(isEditing || token.contacts) &&
                  (isEditing ? (
                    <GridItem colSpan={{ base: 1, md: 1 }}>
                      <Box>
                        <Text
                          fontSize='sm'
                          fontWeight='medium'
                          color={labelColor}
                          mb={1}
                        >
                          Contacts (Key custodian)
                        </Text>
                        <Input
                          type='text'
                          value={editData.contacts || ''}
                          onChange={e =>
                            setEditData(d => ({
                              ...d,
                              contacts: e.target.value,
                            }))
                          }
                          bg={inputBg}
                          borderColor={inputBorder}
                          list='workspace-contacts-suggestions'
                          placeholder='Who manages this key/secret?'
                          maxLength={200}
                        />
                      </Box>
                    </GridItem>
                  ) : (
                    renderEditable(
                      'Contacts (Key custodian)',
                      'contacts',
                      token.contacts,
                      {
                        inputProps: {
                          maxLength: 200,
                          placeholder: 'Who manages this key/secret?',
                        },
                      }
                    )
                  ))}
              </>
            )}

            {token.category === 'license' && (
              <>
                <GridItem colSpan={2}>
                  <Divider my={4} />
                  <Text
                    fontSize='lg'
                    fontWeight='semibold'
                    color={textColor}
                    mb={4}
                  >
                    License Details
                  </Text>
                </GridItem>

                {(isEditing || token.vendor) &&
                  renderEditable('Vendor', 'vendor', token.vendor, {
                    inputProps: {
                      maxLength: 100,
                      placeholder: 'Microsoft, Adobe',
                    },
                  })}
                {(isEditing || token.license_type) &&
                  renderEditable(
                    'License Type',
                    'license_type',
                    token.license_type,
                    {
                      inputProps: {
                        maxLength: 50,
                        placeholder: 'Perpetual, Subscription',
                      },
                    }
                  )}
                {(isEditing || token.cost) &&
                  renderEditable('Cost', 'cost', token.cost, {
                    type: 'number',
                    inputProps: {
                      min: 0,
                      max: 999999999999.99,
                      step: 0.01,
                      placeholder: '0.00',
                    },
                  })}
                {(isEditing || token.contacts) &&
                  (isEditing ? (
                    <GridItem colSpan={{ base: 1, md: 1 }}>
                      <Box>
                        <Text
                          fontSize='sm'
                          fontWeight='medium'
                          color={labelColor}
                          mb={1}
                        >
                          Contacts
                        </Text>
                        <Input
                          type='text'
                          value={editData.contacts || ''}
                          onChange={e =>
                            setEditData(d => ({
                              ...d,
                              contacts: e.target.value,
                            }))
                          }
                          bg={inputBg}
                          borderColor={inputBorder}
                          list='workspace-contacts-suggestions'
                          placeholder='Who owns this renewal?'
                          maxLength={200}
                        />
                      </Box>
                    </GridItem>
                  ) : (
                    renderEditable('Contacts', 'contacts', token.contacts, {
                      inputProps: {
                        maxLength: 200,
                        placeholder: 'Who owns this renewal?',
                      },
                    })
                  ))}
                {isEditing ? (
                  <>
                    {renderEditable(
                      'Renewal URL',
                      'renewal_url',
                      token.renewal_url,
                      {
                        type: 'url',
                        inputProps: {
                          maxLength: 500,
                          placeholder: 'https://vendor.com/renew',
                        },
                      }
                    )}
                    {renderEditable(
                      'Renewal Date',
                      'renewal_date',
                      token.renewal_date,
                      { type: 'date' }
                    )}
                  </>
                ) : (
                  renderRenewalInfo()
                )}
              </>
            )}

            {token.category === 'general' && (
              <>
                <GridItem colSpan={2}>
                  <Divider my={4} />
                  <Text
                    fontSize='lg'
                    fontWeight='semibold'
                    color={textColor}
                    mb={4}
                  >
                    General Details
                  </Text>
                </GridItem>

                {(isEditing || token.location) &&
                  renderEditable('Locations', 'location', token.location, {
                    multiline: true,
                    inputProps: {
                      maxLength: 1000,
                      placeholder: 'One location per line',
                      rows: 3,
                    },
                  })}
                {(isEditing || token.used_by) &&
                  renderEditable('Used By', 'used_by', token.used_by, {
                    inputProps: {
                      maxLength: 200,
                      placeholder: 'Application, service',
                    },
                  })}
                {isEditing
                  ? renderEditable(
                      'Renewal URL',
                      'renewal_url',
                      token.renewal_url,
                      {
                        type: 'url',
                        inputProps: {
                          maxLength: 500,
                          placeholder: 'https://provider.com/renew',
                        },
                      }
                    )
                  : token.renewal_url &&
                    renderEditable(
                      'Renewal URL',
                      'renewal_url',
                      token.renewal_url,
                      {
                        type: 'url',
                        inputProps: { maxLength: 500 },
                      }
                    )}
                {(isEditing || token.contacts) &&
                  (isEditing ? (
                    <GridItem colSpan={{ base: 1, md: 1 }}>
                      <Box>
                        <Text
                          fontSize='sm'
                          fontWeight='medium'
                          color={labelColor}
                          mb={1}
                        >
                          Contacts
                        </Text>
                        <Input
                          type='text'
                          value={editData.contacts || ''}
                          onChange={e =>
                            setEditData(d => ({
                              ...d,
                              contacts: e.target.value,
                            }))
                          }
                          bg={inputBg}
                          borderColor={inputBorder}
                          list='workspace-contacts-suggestions'
                          placeholder='Who manages this item?'
                          maxLength={200}
                        />
                      </Box>
                    </GridItem>
                  ) : (
                    renderEditable('Contacts', 'contacts', token.contacts, {
                      inputProps: {
                        maxLength: 200,
                        placeholder: 'Who manages this item?',
                      },
                    })
                  ))}
              </>
            )}

            {/* Notes */}
            {(isEditing || token.notes) && (
              <>
                <GridItem colSpan={2}>
                  <Divider my={4} />
                  <Text
                    fontSize='lg'
                    fontWeight='semibold'
                    color={textColor}
                    mb={4}
                  >
                    Notes
                  </Text>
                </GridItem>

                {renderEditable('Notes', 'notes', token.notes, {
                  multiline: true,
                  inputProps: {
                    maxLength: 500,
                    placeholder: 'Additional information',
                  },
                })}
              </>
            )}
          </Grid>
          {/* Datalist for workspace contacts suggestions */}
          <datalist id='workspace-contacts-suggestions'>
            {workspaceContactOptions}
          </datalist>
        </ModalBody>

        <ModalFooter>
          {!isViewer && (
            <Button
              mr={3}
              variant='outline'
              onClick={() => setIsEditing(e => !e)}
            >
              {isEditing ? 'Cancel edit' : 'Edit'}
            </Button>
          )}
          <Button onClick={onClose} colorScheme='blue'>
            Close
          </Button>
          {!isViewer && isEditing && (
            <Button ml={3} colorScheme='green' onClick={handleSave}>
              Save
            </Button>
          )}
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
}

export default memo(TokenDetailModal);
