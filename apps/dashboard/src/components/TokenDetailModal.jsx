import { useState, useEffect, useMemo, useCallback, memo } from 'react';
import {
  Modal,
  ModalOverlay,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  Box,
  Heading,
  Text,
  Button,
  Flex,
  Grid,
  GridItem,
  Badge,
  HStack,
  VStack,
  Input,
  Textarea,
  Select,
  Tooltip,
  useColorModeValue,
} from '@chakra-ui/react';
import { getColorFromString } from '../styles/colors.js';
import { formatDate, tokenAPI } from '../utils/apiClient';
import {
  DASHBOARD_MODAL_HEADING_FONT,
  DashboardModalFrame,
  useDashboardModalProps,
} from './DashboardModalFrame.jsx';
import TokenCertOpsPanel from './certops/TokenCertOpsPanel.jsx';

function createTokenEditData(token) {
  return {
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
    privileges: token?.privileges || '',
    contact_group_id: token?.contact_group_id || '',
  };
}

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
  const {
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    outlineButtonProps,
    primaryButtonProps,
    tokens: modalTokens,
  } = useDashboardModalProps();
  const fieldBg = modalTokens.fieldBg;
  const borderColor = modalTokens.border;
  const textColor = modalTokens.text;
  const labelColor = modalTokens.muted;
  const subtleTextColor = modalTokens.subtleText;
  const inputBg = modalTokens.inputBg;
  const inputBorder = modalTokens.inputBorder;
  const focusBorderColor = modalTokens.focusBorder;
  const sectionAccent = modalTokens.sectionAccent;
  const dangerBg = useColorModeValue('#fef2f2', 'rgba(127, 29, 29, 0.28)');
  const dangerBorder = useColorModeValue('#fecaca', 'rgba(248, 113, 113, 0.3)');
  const dangerText = useColorModeValue('#b91c1c', '#fecaca');
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState('');
  const [isEditing, setIsEditing] = useState(false);
  const [editData, setEditData] = useState(() => createTokenEditData(token));

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
    setSaveError('');
    setSaving(false);
    setIsEditing(false);
    setEditData(createTokenEditData(token));
  }, [token]);

  const renderRenewalInfo = useCallback(() => {
    const renewalInfo = [];
    if (token?.renewal_url) renewalInfo.push(`URL: ${token.renewal_url}`);
    if (token?.renewal_date)
      renewalInfo.push(`Date: ${formatDate(token.renewal_date)}`);
    if (token?.contacts) renewalInfo.push(`Contact: ${token.contacts}`);

    if (renewalInfo.length === 0) return null;

    return (
      <GridItem colSpan={{ base: 1, md: 2 }}>
        <Box
          bg={fieldBg}
          border='1px solid'
          borderColor={borderColor}
          borderRadius='12px'
          p={{ base: 3.5, md: 4 }}
        >
          <Text fontSize='sm' fontWeight='semibold' color={labelColor} mb={2}>
            Renewal Information
          </Text>
          <VStack align='start' spacing={1}>
            {renewalInfo.map((info, index) => (
              <Text
                key={index}
                fontSize={{ base: 'sm', md: 'md' }}
                color={textColor}
                wordBreak='break-word'
              >
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
    fieldBg,
    borderColor,
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
      const originalExpiresAt = token?.expiresAt ? String(token.expiresAt) : '';
      const nextExpiresAt =
        payload.expiresAt == null ? '' : String(payload.expiresAt).trim();
      if (nextExpiresAt === originalExpiresAt) {
        delete payload.expiresAt;
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
        'privileges',
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
  }, [editData, token?.expiresAt, token?.id, onTokenUpdated]);

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

  const commonInputProps = {
    bg: inputBg,
    borderColor: inputBorder,
    borderRadius: '10px',
    color: textColor,
    minH: '40px',
    _placeholder: { color: labelColor },
    _hover: { borderColor: focusBorderColor },
    _focusVisible: {
      borderColor: focusBorderColor,
      boxShadow: `0 0 0 1px ${focusBorderColor}`,
    },
  };

  const renderFieldShell = (
    label,
    children,
    colSpan = { base: 1, md: 1 },
    tooltipLabel = null
  ) => {
    const shell = (
      <Box
        bg={fieldBg}
        border='1px solid'
        borderColor={borderColor}
        borderRadius='12px'
        p={{ base: 3.5, md: 4 }}
        minH='88px'
      >
        <Text fontSize='sm' fontWeight='semibold' color={labelColor} mb={2}>
          {label}
        </Text>
        {children}
      </Box>
    );

    return (
      <GridItem colSpan={colSpan}>
        {tooltipLabel ? (
          <Tooltip label={tooltipLabel} hasArrow placement='top'>
            <Box w='full'>{shell}</Box>
          </Tooltip>
        ) : (
          shell
        )}
      </GridItem>
    );
  };

  const renderValueText = (value, isMultiline = false) => (
    <Text
      fontSize={{ base: 'sm', md: 'md' }}
      fontWeight='semibold'
      color={textColor}
      lineHeight='1.45'
      whiteSpace={isMultiline ? 'pre-wrap' : 'normal'}
      wordBreak='break-word'
    >
      {value || '-'}
    </Text>
  );

  const renderSectionTitle = (label, withDivider = true) => (
    <GridItem colSpan={{ base: 1, md: 2 }}>
      <Box
        borderTop={withDivider ? '1px solid' : '0'}
        borderColor={borderColor}
        pt={withDivider ? { base: 4, md: 5 } : 0}
        mt={withDivider ? { base: 1, md: 2 } : 0}
      >
        <HStack spacing={3}>
          <Box
            w='3px'
            h='18px'
            borderRadius='full'
            bg={sectionAccent}
            flexShrink={0}
          />
          <Text
            fontSize={{ base: 'md', md: 'lg' }}
            fontWeight='bold'
            fontFamily={DASHBOARD_MODAL_HEADING_FONT}
            color={textColor}
          >
            {label}
          </Text>
        </HStack>
      </Box>
    </GridItem>
  );

  const renderField = (
    label,
    value,
    isMultiline = false,
    tooltipLabel = null
  ) => {
    if (!value) return null;

    return renderFieldShell(
      label,
      renderValueText(value, isMultiline),
      { base: 1, md: 1 },
      tooltipLabel
    );
  };

  const renderDateField = (label, value) => {
    if (!value) return null;

    return renderFieldShell(label, renderValueText(formatDate(value)));
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
        <Box
          bg={fieldBg}
          border='1px solid'
          borderColor={borderColor}
          borderRadius='12px'
          p={{ base: 3.5, md: 4 }}
          minH={multiline ? 'auto' : '88px'}
        >
          <Text fontSize='sm' fontWeight='semibold' color={labelColor} mb={2}>
            {label}
          </Text>
          {isEditing ? (
            multiline ? (
              <Textarea
                value={editData[key] ?? ''}
                onChange={e =>
                  setEditData(d => ({ ...d, [key]: e.target.value }))
                }
                {...commonInputProps}
                {...inputProps}
              />
            ) : (
              <Input
                type={type}
                value={editData[key] ?? ''}
                onChange={e =>
                  setEditData(d => ({ ...d, [key]: e.target.value }))
                }
                {...commonInputProps}
                {...inputProps}
              />
            )
          ) : (
            renderValueText(displayValue, multiline)
          )}
        </Box>
      </GridItem>
    );
  };

  const renderEditableSelect = (label, key, options) => {
    return (
      <GridItem colSpan={{ base: 1, md: 1 }}>
        <Box
          bg={fieldBg}
          border='1px solid'
          borderColor={borderColor}
          borderRadius='12px'
          p={{ base: 3.5, md: 4 }}
          minH='88px'
        >
          <Text fontSize='sm' fontWeight='semibold' color={labelColor} mb={2}>
            {label}
          </Text>
          {isEditing ? (
            <Select
              value={editData[key] || ''}
              onChange={e =>
                setEditData(d => ({ ...d, [key]: e.target.value }))
              }
              {...commonInputProps}
            >
              {options}
            </Select>
          ) : (
            <Text
              fontSize={{ base: 'sm', md: 'md' }}
              fontWeight='semibold'
              color={textColor}
              wordBreak='break-word'
            >
              {(() => {
                const id = (isEditing ? editData[key] : token?.[key]) || '';
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

  const categoryLabel = category?.label || token.category || 'Asset';
  const typeLabel = type?.label || token.type || 'Unknown type';

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      size='xl'
      scrollBehavior='inside'
      isCentered
      motionPreset='none'
    >
      <ModalOverlay />
      <DashboardModalFrame maxW={{ base: 'calc(100vw - 24px)', md: '760px' }}>
        <ModalHeader {...headerProps}>
          <Flex
            align={{ base: 'flex-start', md: 'center' }}
            justify='space-between'
            gap={4}
            direction={{ base: 'column', sm: 'row' }}
          >
            <Box minW={0}>
              <Heading
                size={{ base: 'md', md: 'lg' }}
                color={textColor}
                fontFamily={DASHBOARD_MODAL_HEADING_FONT}
                noOfLines={2}
              >
                {token.name}
              </Heading>
              <Text
                fontSize={{ base: 'sm', md: 'md' }}
                color={subtleTextColor}
                mt={2}
                noOfLines={2}
              >
                {categoryLabel} - {typeLabel}
              </Text>
            </Box>
            <Badge
              colorScheme={category?.color || 'gray'}
              variant='subtle'
              fontSize='xs'
              borderRadius='8px'
              px={3}
              py={1.5}
              flexShrink={0}
            >
              {categoryLabel}
            </Badge>
          </Flex>
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} />

        <ModalBody {...bodyProps}>
          <Grid
            templateColumns={{ base: 'minmax(0, 1fr)', md: 'repeat(2, 1fr)' }}
            gap={{ base: 3, md: 4 }}
          >
            {renderSectionTitle('Basic Information', false)}

            {/* Token ID - non-editable identifier */}
            {renderField('Token ID', token.id)}

            {renderField(
              'Type',
              type?.label || token.type,
              false,
              isEditing ? 'Cannot edit type' : null
            )}
            {renderField(
              'Category',
              category?.label,
              false,
              isEditing ? 'Cannot edit category' : null
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
                <Box
                  bg={fieldBg}
                  border='1px solid'
                  borderColor={borderColor}
                  borderRadius='12px'
                  p={{ base: 3.5, md: 4 }}
                  minH='88px'
                >
                  <Text
                    fontSize='sm'
                    fontWeight='semibold'
                    color={labelColor}
                    mb={2}
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
                        <Text
                          fontSize={{ base: 'sm', md: 'md' }}
                          fontWeight='semibold'
                          color={textColor}
                        >
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

            {/* Category-specific fields */}
            {token.category === 'cert' && (
              <>
                {renderSectionTitle('Certificate Details')}

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
                      <Box
                        bg={fieldBg}
                        border='1px solid'
                        borderColor={borderColor}
                        borderRadius='12px'
                        p={{ base: 3.5, md: 4 }}
                        minH='88px'
                      >
                        <Text
                          fontSize='sm'
                          fontWeight='semibold'
                          color={labelColor}
                          mb={2}
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
                          {...commonInputProps}
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
                <TokenCertOpsPanel tokenId={token.id} />
              </>
            )}

            {token.category === 'key_secret' && (
              <>
                {renderSectionTitle('Key/Secret Details')}

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
                {(isEditing || token.privileges) &&
                  renderEditable('Privileges', 'privileges', token.privileges, {
                    multiline: true,
                    inputProps: {
                      maxLength: 5000,
                      placeholder:
                        'e.g. read:api, write:registry, secrets:read',
                      rows: 3,
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
                      <Box
                        bg={fieldBg}
                        border='1px solid'
                        borderColor={borderColor}
                        borderRadius='12px'
                        p={{ base: 3.5, md: 4 }}
                        minH='88px'
                      >
                        <Text
                          fontSize='sm'
                          fontWeight='semibold'
                          color={labelColor}
                          mb={2}
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
                          {...commonInputProps}
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
                {renderSectionTitle('License Details')}

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
                      <Box
                        bg={fieldBg}
                        border='1px solid'
                        borderColor={borderColor}
                        borderRadius='12px'
                        p={{ base: 3.5, md: 4 }}
                        minH='88px'
                      >
                        <Text
                          fontSize='sm'
                          fontWeight='semibold'
                          color={labelColor}
                          mb={2}
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
                          {...commonInputProps}
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
                {renderSectionTitle('General Details')}

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
                      <Box
                        bg={fieldBg}
                        border='1px solid'
                        borderColor={borderColor}
                        borderRadius='12px'
                        p={{ base: 3.5, md: 4 }}
                        minH='88px'
                      >
                        <Text
                          fontSize='sm'
                          fontWeight='semibold'
                          color={labelColor}
                          mb={2}
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
                          {...commonInputProps}
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
                {renderSectionTitle('Notes')}

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

        <ModalFooter {...footerProps}>
          <Flex
            w='100%'
            align={{ base: 'stretch', md: 'center' }}
            justify='space-between'
            gap={3}
            direction={{ base: 'column', md: 'row' }}
          >
            {saveError ? (
              <Box
                bg={dangerBg}
                border='1px solid'
                borderColor={dangerBorder}
                borderRadius='10px'
                color={dangerText}
                fontSize='sm'
                fontWeight='semibold'
                px={3}
                py={2}
                flex='1'
              >
                {saveError}
              </Box>
            ) : (
              <Text fontSize='sm' color={labelColor}>
                {isViewer
                  ? 'You have read-only access to this asset.'
                  : isEditing
                    ? 'Review your changes before saving.'
                    : 'Asset details are read-only until edit mode is enabled.'}
              </Text>
            )}

            <Flex
              gap={3}
              justify={{ base: 'stretch', md: 'flex-end' }}
              direction={{ base: 'column-reverse', sm: 'row' }}
              flexShrink={0}
            >
              {!isViewer && (
                <Button
                  onClick={() => setIsEditing(e => !e)}
                  minW={{ base: '100%', sm: '104px' }}
                  {...outlineButtonProps}
                >
                  {isEditing ? 'Cancel edit' : 'Edit'}
                </Button>
              )}
              <Button
                onClick={onClose}
                minW={{ base: '100%', sm: '104px' }}
                {...primaryButtonProps}
              >
                Close
              </Button>
              {!isViewer && isEditing && (
                <Button
                  {...primaryButtonProps}
                  colorScheme='green'
                  onClick={handleSave}
                  isLoading={saving}
                  minW={{ base: '100%', sm: '104px' }}
                >
                  Save
                </Button>
              )}
            </Flex>
          </Flex>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}

export default memo(TokenDetailModal);
