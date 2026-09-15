import { useState, useEffect, useMemo, useCallback, memo } from 'react';
import {
  Modal,
  ModalOverlay,
  ModalHeader,
  ModalBody,
  ModalCloseButton,
  Text,
  Grid,
  GridItem,
  VStack,
  Input,
  Textarea,
  Select,
} from '@chakra-ui/react';
import { BadgeCheck, FileText, Info, KeyRound, List } from 'lucide-react';
import { getExpiryStatus } from '../styles/colors.js';
import { formatDate, tokenAPI } from '../utils/apiClient';
import {
  DashboardDetailsModalFrame,
  useDashboardModalProps,
} from './DashboardModalFrame.jsx';
import {
  DashboardDetailsModalFooter,
  DashboardDetailsModalHeader,
  DashboardDetailsSummary,
  DashboardModalDataSection,
  DashboardModalDetailRow,
  DashboardModalDetailsGrid,
  DashboardModalSectionHeading,
} from './DashboardModalDetails.jsx';
import TokenCertOpsPanel from './certops/TokenCertOpsPanel.jsx';
import {
  createTokenEditData,
  createTokenUpdatePayload,
} from './tokenDetailForm.js';

function hasDisplayValue(value) {
  if (Array.isArray(value)) return value.some(hasDisplayValue);
  if (typeof value === 'string') return value.trim().length > 0;
  return value !== null && value !== undefined;
}

function hasAnyDisplayValue(...values) {
  return values.some(hasDisplayValue);
}

function displayList(value) {
  const values = Array.isArray(value) ? value : [value];
  return values
    .flatMap(item => (typeof item === 'string' ? item.split(',') : [item]))
    .map(item => String(item || '').trim())
    .filter(Boolean)
    .join(', ');
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
  const {
    text: textColor,
    muted: labelColor,
    inputBg,
    inputBorder,
    focusBorder: focusBorderColor,
  } = modalTokens;
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

  const beginEditing = useCallback(() => {
    setEditData(createTokenEditData(token));
    setSaveError('');
    setIsEditing(true);
  }, [token]);

  const cancelEditing = useCallback(() => {
    setEditData(createTokenEditData(token));
    setSaveError('');
    setIsEditing(false);
  }, [token]);

  const handleSave = useCallback(async () => {
    try {
      setSaving(true);
      setSaveError('');
      const payload = createTokenUpdatePayload(editData, token);
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
  }, [editData, token, onTokenUpdated]);

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
    borderRadius: '8px',
    color: textColor,
    size: 'sm',
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
    _colSpan = { base: 1, md: 1 },
    tooltipLabel = null
  ) => {
    return (
      <DashboardModalDetailRow
        label={label}
        tokens={modalTokens}
        tooltip={tooltipLabel}
      >
        {children}
      </DashboardModalDetailRow>
    );
  };

  const renderValueText = (value, isMultiline = false) => (
    <Text
      fontSize='sm'
      color={textColor}
      lineHeight='1.45'
      whiteSpace={isMultiline ? 'pre-wrap' : 'normal'}
      wordBreak='break-word'
    >
      {hasDisplayValue(value) ? value : '-'}
    </Text>
  );

  const renderSectionTitle = (label, withDivider = true) => (
    <DashboardModalSectionHeading
      tokens={modalTokens}
      withDivider={withDivider}
    >
      {label}
    </DashboardModalSectionHeading>
  );

  const renderField = (
    label,
    value,
    isMultiline = false,
    tooltipLabel = null
  ) => {
    if (!hasDisplayValue(value)) return null;

    return renderFieldShell(
      label,
      renderValueText(value, isMultiline),
      { base: 1, md: 1 },
      tooltipLabel
    );
  };

  const renderDateField = (label, value) => {
    if (!hasDisplayValue(value)) return null;

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
      <DashboardModalDetailRow label={label} tokens={modalTokens}>
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
      </DashboardModalDetailRow>
    );
  };

  const renderEditableSelect = (label, key, options) => {
    return (
      <DashboardModalDetailRow label={label} tokens={modalTokens}>
        {isEditing ? (
          <Select
            value={editData[key] || ''}
            onChange={e => setEditData(d => ({ ...d, [key]: e.target.value }))}
            {...commonInputProps}
          >
            {options}
          </Select>
        ) : (
          <Text fontSize='sm' color={textColor} wordBreak='break-word'>
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
      </DashboardModalDetailRow>
    );
  };

  const renderContactsField = (label, placeholder) => {
    if (!isEditing && !token.contacts) return null;

    return renderFieldShell(
      label,
      isEditing ? (
        <Input
          type='text'
          value={editData.contacts || ''}
          onChange={event =>
            setEditData(current => ({
              ...current,
              contacts: event.target.value,
            }))
          }
          {...commonInputProps}
          list='workspace-contacts-suggestions'
          placeholder={placeholder}
          maxLength={200}
        />
      ) : (
        renderValueText(token.contacts)
      )
    );
  };

  const renderRenewalInfo = () => {
    const renewalInfo = [];
    if (token.renewal_url) renewalInfo.push(`URL: ${token.renewal_url}`);
    if (token.renewal_date)
      renewalInfo.push(`Date: ${formatDate(token.renewal_date)}`);
    if (token.contacts) renewalInfo.push(`Contact: ${token.contacts}`);

    if (renewalInfo.length === 0) return null;

    return renderFieldShell(
      'Renewal information',
      <VStack align='start' spacing={1}>
        {renewalInfo.map(info => (
          <Text
            key={info}
            fontSize='sm'
            color={textColor}
            wordBreak='break-word'
          >
            {info}
          </Text>
        ))}
      </VStack>
    );
  };

  const categoryLabel = category?.label || token.category || 'Asset';
  const typeLabel = type?.label || token.type || 'Unknown type';
  const hasBasicInformation =
    isEditing ||
    hasAnyDisplayValue(
      token.id,
      token.type,
      token.category,
      token.name,
      token.section,
      token.contact_group_id,
      token.expiresAt,
      token.created_at,
      token.imported_at,
      token.last_used,
      token.updated_at
    );
  const hasCertificateDetails =
    isEditing ||
    hasAnyDisplayValue(
      token.domains,
      token.issuer,
      token.serial_number,
      token.subject,
      token.renewal_url,
      token.contacts
    );
  const hasKeySecretDetails =
    isEditing ||
    hasAnyDisplayValue(
      token.location,
      token.used_by,
      token.privileges,
      token.description,
      token.algorithm,
      token.key_size,
      token.renewal_url,
      token.contacts
    );
  const hasLicenseDetails =
    isEditing ||
    hasAnyDisplayValue(
      token.vendor,
      token.license_type,
      token.cost,
      token.renewal_url,
      token.renewal_date,
      token.contacts
    );
  const hasGeneralDetails =
    isEditing ||
    hasAnyDisplayValue(
      token.location,
      token.used_by,
      token.renewal_url,
      token.contacts
    );
  const expiryStatus = hasDisplayValue(token.expiresAt)
    ? getExpiryStatus(token.expiresAt)
    : null;
  const summaryItems = expiryStatus
    ? [
        {
          label: 'Expires',
          value: formatDate(token.expiresAt),
          help: expiryStatus.label,
          accent: expiryStatus.color,
        },
      ]
    : [];

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      scrollBehavior='inside'
      isCentered
      motionPreset='none'
    >
      <ModalOverlay />
      <DashboardDetailsModalFrame>
        <ModalHeader {...headerProps} py={{ base: 4, md: 4 }}>
          <DashboardDetailsModalHeader
            title={token.name}
            subtitle={`${categoryLabel} · ${typeLabel}`}
            badgeLabel={categoryLabel}
            badgeColorScheme={category?.color || 'gray'}
          />
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} top={{ base: 3, md: 3 }} />

        <ModalBody {...bodyProps} py={{ base: 4, md: 4 }}>
          <DashboardDetailsSummary items={summaryItems} />
          <DashboardModalDetailsGrid>
            {hasBasicInformation ? (
              <DashboardModalDataSection
                title='Basic information'
                tokens={modalTokens}
                icon={Info}
              >
                {/* Token ID - non-editable identifier */}
                {renderField('Token ID', token.id)}

                {hasDisplayValue(token.type)
                  ? renderField(
                      'Type',
                      type?.label || token.type,
                      false,
                      isEditing ? 'Cannot edit type' : null
                    )
                  : null}
                {hasDisplayValue(token.category)
                  ? renderField(
                      'Category',
                      category?.label || token.category,
                      false,
                      isEditing ? 'Cannot edit category' : null
                    )
                  : null}
                {isEditing || hasDisplayValue(token.name)
                  ? renderEditable('Name', 'name', token.name, {
                      inputProps: { maxLength: 100 },
                    })
                  : null}
                {isEditing || hasDisplayValue(token.section)
                  ? isEditing
                    ? renderEditable(
                        'Section',
                        'section',
                        displayList(token.section),
                        {
                          inputProps: {
                            maxLength: 255,
                            placeholder: 'e.g., prod, AWS, security team',
                          },
                        }
                      )
                    : renderField('Section', displayList(token.section))
                  : null}
                {isEditing || hasDisplayValue(token.contact_group_id)
                  ? renderEditableSelect(
                      'Contact group',
                      'contact_group_id',
                      contactGroupOptions
                    )
                  : null}

                {isEditing
                  ? renderEditable(
                      'Asset expiration',
                      'expiresAt',
                      token.expiresAt,
                      { type: 'date' }
                    )
                  : renderDateField('Asset expiration', token.expiresAt)}
                {renderDateField('Created', token.created_at)}
                {renderDateField('Imported', token.imported_at)}
                {renderDateField('Last used', token.last_used)}
                {renderDateField('Last updated', token.updated_at)}
              </DashboardModalDataSection>
            ) : null}

            {/* Category-specific fields */}
            {token.category === 'cert' && hasCertificateDetails && (
              <DashboardModalDataSection
                title='Certificate details'
                tokens={modalTokens}
                icon={FileText}
              >
                {(isEditing || hasDisplayValue(token.domains)) &&
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
                {(isEditing || hasDisplayValue(token.issuer)) &&
                  renderEditable('Issuer', 'issuer', token.issuer, {
                    inputProps: {
                      maxLength: 100,
                      placeholder: "Let's Encrypt, DigiCert",
                    },
                  })}
                {(isEditing || hasDisplayValue(token.serial_number)) &&
                  renderEditable(
                    'Serial number',
                    'serial_number',
                    token.serial_number,
                    { inputProps: { maxLength: 50, placeholder: 'Optional' } }
                  )}
                {(isEditing || hasDisplayValue(token.subject)) &&
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
                  : hasDisplayValue(token.renewal_url) &&
                    renderEditable(
                      'Renewal URL',
                      'renewal_url',
                      token.renewal_url,
                      {
                        type: 'url',
                        inputProps: { maxLength: 500 },
                      }
                    )}
                {renderContactsField(
                  'Contacts (Key custodian)',
                  'Who manages this certificate?'
                )}
                <GridItem gridColumn='1 / -1' minW={0}>
                  <Grid
                    templateColumns={{
                      base: 'minmax(0, 1fr)',
                      md: 'repeat(2, minmax(0, 1fr))',
                    }}
                    gap={{ base: 3, md: 4 }}
                  >
                    <TokenCertOpsPanel token={token} tokenId={token.id} />
                  </Grid>
                </GridItem>
              </DashboardModalDataSection>
            )}

            {token.category === 'key_secret' && hasKeySecretDetails && (
              <DashboardModalDataSection
                title='Key/secret details'
                tokens={modalTokens}
                icon={KeyRound}
              >
                {(isEditing || hasDisplayValue(token.location)) &&
                  renderEditable('Locations', 'location', token.location, {
                    multiline: true,
                    inputProps: {
                      maxLength: 1000,
                      placeholder: 'One location per line',
                      rows: 3,
                    },
                  })}
                {(isEditing || hasDisplayValue(token.used_by)) &&
                  renderEditable('Used by', 'used_by', token.used_by, {
                    inputProps: {
                      maxLength: 200,
                      placeholder: 'Application, service',
                    },
                  })}
                {(isEditing || hasDisplayValue(token.privileges)) &&
                  renderEditable('Privileges', 'privileges', token.privileges, {
                    multiline: true,
                    inputProps: {
                      maxLength: 5000,
                      placeholder:
                        'e.g. read:api, write:registry, secrets:read',
                      rows: 3,
                    },
                  })}
                {(isEditing || hasDisplayValue(token.description)) &&
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
                    (isEditing
                      ? allowAlgo
                      : hasDisplayValue(token.algorithm)) &&
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
                    (isEditing ? allowSize : hasDisplayValue(token.key_size)) &&
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
                  : hasDisplayValue(token.renewal_url) &&
                    renderEditable(
                      'Renewal URL',
                      'renewal_url',
                      token.renewal_url,
                      {
                        type: 'url',
                        inputProps: { maxLength: 500 },
                      }
                    )}
                {renderContactsField(
                  'Contacts (Key custodian)',
                  'Who manages this key/secret?'
                )}
              </DashboardModalDataSection>
            )}

            {token.category === 'license' && hasLicenseDetails && (
              <DashboardModalDataSection
                title='License details'
                tokens={modalTokens}
                icon={BadgeCheck}
              >
                {(isEditing || hasDisplayValue(token.vendor)) &&
                  renderEditable('Vendor', 'vendor', token.vendor, {
                    inputProps: {
                      maxLength: 100,
                      placeholder: 'Microsoft, Adobe',
                    },
                  })}
                {(isEditing || hasDisplayValue(token.license_type)) &&
                  renderEditable(
                    'License type',
                    'license_type',
                    token.license_type,
                    {
                      inputProps: {
                        maxLength: 50,
                        placeholder: 'Perpetual, Subscription',
                      },
                    }
                  )}
                {(isEditing || hasDisplayValue(token.cost)) &&
                  renderEditable('Cost', 'cost', token.cost, {
                    type: 'number',
                    inputProps: {
                      min: 0,
                      max: 999999999999.99,
                      step: 0.01,
                      placeholder: '0.00',
                    },
                  })}
                {renderContactsField('Contacts', 'Who owns this renewal?')}
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
              </DashboardModalDataSection>
            )}

            {token.category === 'general' && hasGeneralDetails && (
              <DashboardModalDataSection
                title='General details'
                tokens={modalTokens}
                icon={List}
              >
                {(isEditing || hasDisplayValue(token.location)) &&
                  renderEditable('Locations', 'location', token.location, {
                    multiline: true,
                    inputProps: {
                      maxLength: 1000,
                      placeholder: 'One location per line',
                      rows: 3,
                    },
                  })}
                {(isEditing || hasDisplayValue(token.used_by)) &&
                  renderEditable('Used by', 'used_by', token.used_by, {
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
                  : hasDisplayValue(token.renewal_url) &&
                    renderEditable(
                      'Renewal URL',
                      'renewal_url',
                      token.renewal_url,
                      {
                        type: 'url',
                        inputProps: { maxLength: 500 },
                      }
                    )}
                {renderContactsField('Contacts', 'Who manages this item?')}
              </DashboardModalDataSection>
            )}

            {/* Notes */}
            {(isEditing || hasDisplayValue(token.notes)) && (
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
          </DashboardModalDetailsGrid>
          {/* Datalist for workspace contacts suggestions */}
          <datalist id='workspace-contacts-suggestions'>
            {workspaceContactOptions}
          </datalist>
        </ModalBody>

        <DashboardDetailsModalFooter
          footerProps={footerProps}
          tokens={modalTokens}
          isViewer={isViewer}
          isEditing={isEditing}
          saveError={saveError}
          saving={saving}
          onBeginEdit={beginEditing}
          onCancelEdit={cancelEditing}
          onClose={onClose}
          onSave={handleSave}
          outlineButtonProps={outlineButtonProps}
          primaryButtonProps={primaryButtonProps}
        />
      </DashboardDetailsModalFrame>
    </Modal>
  );
}

export default memo(TokenDetailModal);
