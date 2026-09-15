import {
  Children,
  cloneElement,
  isValidElement,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react';
import {
  Badge,
  Box,
  Grid,
  Heading,
  HStack,
  Icon,
  Input,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalHeader,
  ModalOverlay,
  Select,
  Spinner,
  Text,
  Textarea,
  VStack,
} from '@chakra-ui/react';
import { FileText, Info, Settings } from 'lucide-react';
import { TOKEN_CATEGORIES } from '../../constants/tokenCategories.js';
import { tokenAPI } from '../../utils/apiClient';
import CopyableId from '../CopyableId.jsx';
import {
  DASHBOARD_MODAL_HEADING_FONT,
  DashboardDetailsModalFrame,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import {
  DashboardDetailsModalFooter,
  DashboardDetailsModalHeader,
  DashboardDetailsSummary,
} from '../DashboardModalDetails.jsx';
import {
  createTokenEditData,
  createTokenUpdatePayload,
} from '../tokenDetailForm.js';
import CertificateInstances from './CertificateInstances.jsx';
import CertificateTimeline from './CertificateTimeline.jsx';
import KeyLocalityBadge from './KeyLocalityBadge.jsx';
import KeyLocalityList from './KeyLocalityList.jsx';
import RenewalBadge from './RenewalBadge.jsx';
import RenewalPathBadge from './RenewalPathBadge.jsx';
import {
  expiryDescriptor,
  formatDate,
  keyModeLabel,
  renewalDescriptor,
  sourceLabel,
  statusLabel,
  statusScheme,
} from './certopsFormat.js';

function hasValue(value) {
  if (Array.isArray(value)) return value.some(hasValue);
  if (typeof value === 'string') return value.trim().length > 0;
  return value !== null && value !== undefined;
}

function hasAnyValue(...values) {
  return values.some(hasValue);
}

function listLabel(value) {
  const values = Array.isArray(value) ? value : hasValue(value) ? [value] : [];
  return values
    .flatMap(item =>
      typeof item === 'string' ? item.split(',') : [String(item)]
    )
    .map(item => item.trim())
    .filter(Boolean)
    .join(', ');
}

function Section({
  title,
  description,
  children,
  mb = 6,
  columns = 1,
  enclosed = false,
  compactValues = false,
  contentBorder = true,
  propertyValueRows = false,
  icon: SectionIcon,
}) {
  const visibleChildren = Children.toArray(children).filter(Boolean);
  if (visibleChildren.length === 0) return null;
  const usesTwoColumns = columns === 2;
  const renderedChildren =
    compactValues || enclosed
      ? visibleChildren.map(child =>
          isValidElement(child)
            ? cloneElement(child, {
                compactValue: compactValues,
                tableStyle: enclosed,
                propertyValueStyle: propertyValueRows,
              })
            : child
        )
      : visibleChildren;

  const detailsGrid = (
    <Grid
      data-detail-columns={columns}
      data-section-enclosed={String(enclosed)}
      templateColumns='minmax(0, 1fr)'
      position='relative'
      mx={enclosed ? 3 : 0}
      border={contentBorder ? '1px solid' : 0}
      borderWidth={enclosed ? 0 : undefined}
      borderLeftWidth={enclosed ? 0 : undefined}
      borderRightWidth={enclosed ? 0 : undefined}
      borderColor='dashboard.modal.border'
      _before={
        usesTwoColumns
          ? {
              content: '""',
              display: { base: 'none', md: 'block' },
              position: 'absolute',
              top: propertyValueRows ? 2 : 0,
              bottom: propertyValueRows ? 2 : 0,
              left: '50%',
              width: '1px',
              bg: 'dashboard.modal.border',
              pointerEvents: 'none',
            }
          : undefined
      }
      sx={{
        '& > [data-detail-row]:last-of-type': { borderBottom: 0 },
        ...(usesTwoColumns
          ? {
              '@media screen and (min-width: 48em)': {
                gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
                '& > [data-detail-row]:nth-of-type(odd)': {
                  paddingRight: enclosed ? '16px' : '20px',
                },
                '& > [data-detail-row]:nth-of-type(even)': {
                  paddingLeft: enclosed ? '16px' : '20px',
                },
                '& > [data-detail-row]:nth-last-of-type(-n + 2)': {
                  borderBottom: 0,
                },
              },
            }
          : {}),
      }}
    >
      {renderedChildren}
    </Grid>
  );

  if (enclosed) {
    return (
      <Box
        as='section'
        data-compact-section='true'
        mb={mb}
        minW={0}
        border='1px solid'
        borderColor='dashboard.modal.border'
        borderRadius='8px'
        overflow='hidden'
      >
        <HStack
          data-compact-section-heading
          mx={3}
          pt={2.5}
          pb={2}
          spacing={2}
          borderBottom='1px solid'
          borderColor='dashboard.modal.border'
        >
          {SectionIcon ? (
            <Icon
              as={SectionIcon}
              boxSize={4}
              flexShrink={0}
              color='dashboard.modal.muted'
              aria-hidden='true'
            />
          ) : null}
          <Box minW={0}>
            <Heading
              as='h3'
              fontFamily={DASHBOARD_MODAL_HEADING_FONT}
              fontSize='sm'
              fontWeight='bold'
              letterSpacing='0.01em'
            >
              {title}
            </Heading>
            {description ? (
              <Text mt={1} fontSize='xs' color='dashboard.modal.muted'>
                {description}
              </Text>
            ) : null}
          </Box>
        </HStack>
        {detailsGrid}
      </Box>
    );
  }

  return (
    <Box as='section' mb={mb} minW={0}>
      <Box mb={2}>
        <Heading
          as='h3'
          fontFamily={DASHBOARD_MODAL_HEADING_FONT}
          fontSize='sm'
          fontWeight='bold'
          letterSpacing='0.01em'
        >
          {title}
        </Heading>
        {description ? (
          <Text mt={1} fontSize='xs' color='dashboard.modal.muted'>
            {description}
          </Text>
        ) : null}
      </Box>
      {detailsGrid}
    </Box>
  );
}

function DetailRow({
  label,
  children,
  value,
  muted = false,
  mono = false,
  labelWidth = '150px',
  compactValue = false,
  tableStyle = false,
  propertyValueStyle = false,
  valueTitle,
}) {
  const content = children ?? (hasValue(value) ? value : '--');
  const showLabelDivider = tableStyle && !propertyValueStyle;
  return (
    <Grid
      data-detail-row
      data-compact-value={String(compactValue)}
      data-table-style={String(tableStyle)}
      data-property-value-style={String(propertyValueStyle)}
      templateColumns={{
        base: 'minmax(0, 1fr)',
        sm: `${labelWidth} minmax(0, 1fr)`,
      }}
      gap={{ base: 1, sm: propertyValueStyle ? 2 : tableStyle ? 0 : 4 }}
      alignItems={tableStyle ? 'center' : 'start'}
      py={tableStyle ? 1.75 : 2.25}
      borderBottom={propertyValueStyle ? 0 : '1px solid'}
      borderColor='dashboard.modal.border'
      minW={0}
    >
      <Text
        pr={{ base: 0, sm: showLabelDivider ? 3 : 0 }}
        fontSize='xs'
        fontWeight='semibold'
        lineHeight='1.45'
        color='dashboard.modal.muted'
      >
        {label}
        {propertyValueStyle ? ' :' : ''}
      </Text>
      {typeof content === 'string' || typeof content === 'number' ? (
        <Text
          pl={{ base: 0, sm: showLabelDivider ? 3 : 0 }}
          borderLeftWidth={{ base: 0, sm: showLabelDivider ? '1px' : 0 }}
          borderColor='dashboard.modal.border'
          fontSize='sm'
          color={muted ? 'dashboard.modal.muted' : 'dashboard.modal.text'}
          fontFamily={mono ? 'mono' : undefined}
          fontWeight={compactValue ? 'medium' : undefined}
          lineHeight='1.45'
          overflowWrap={compactValue ? 'normal' : 'anywhere'}
          whiteSpace={compactValue ? 'nowrap' : 'pre-wrap'}
          overflow={compactValue ? 'hidden' : undefined}
          textOverflow={compactValue ? 'ellipsis' : undefined}
          title={compactValue ? valueTitle || String(content) : undefined}
          minW={0}
        >
          {content}
        </Text>
      ) : (
        <Box
          pl={{ base: 0, sm: showLabelDivider ? 3 : 0 }}
          borderLeftWidth={{ base: 0, sm: showLabelDivider ? '1px' : 0 }}
          borderColor='dashboard.modal.border'
          color='dashboard.modal.text'
          minW={0}
          title={compactValue ? valueTitle : undefined}
          sx={
            compactValue
              ? {
                  '& > .chakra-text': {
                    fontWeight: 'medium',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  },
                }
              : undefined
          }
        >
          {content}
        </Box>
      )}
    </Grid>
  );
}

function CertificateStateBadges({ status, expiry }) {
  return (
    <>
      {status ? (
        <Badge
          colorScheme={statusScheme(status)}
          variant='subtle'
          textTransform='none'
        >
          {statusLabel(status)}
        </Badge>
      ) : null}
      {expiry ? (
        <Badge
          colorScheme={expiry.scheme}
          variant='subtle'
          textTransform='none'
        >
          {expiry.label}
        </Badge>
      ) : null}
    </>
  );
}

export default function CertificateDetailsModal({
  token,
  isOpen,
  onClose,
  isViewer,
  contactGroups = [],
  workspaceContacts = [],
  onTokenUpdated,
  certOps = {},
  compactTableSections = false,
  propertyValueRows = false,
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
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState('');
  const [isEditing, setIsEditing] = useState(false);
  const [editData, setEditData] = useState(() => createTokenEditData(token));

  const {
    certificate,
    certificateCount = 0,
    instances = [],
    instancesAvailable = true,
    instancesError = '',
    loading: certOpsLoading = false,
    error: certOpsError = '',
  } = certOps;

  useEffect(() => {
    setSaveError('');
    setSaving(false);
    setIsEditing(false);
    setEditData(createTokenEditData(token));
  }, [token]);

  const category = TOKEN_CATEGORIES.find(
    item => item.value === token?.category
  );
  const type = category?.types.find(item => item.value === token?.type);
  const categoryLabel = category?.label || token?.category || 'Certificate';
  const typeLabel = type?.label || token?.type || 'Unknown type';
  const renewal = renewalDescriptor(certificate?.renewal);
  // The managed certificate's parsed X.509 validity drives lifecycle state.
  // The token's manually tracked asset date remains visible in Basic
  // information and is still editable, but must not override `notAfter`.
  const expiresAt = certificate?.notAfter || token?.expiresAt;
  const expiry = expiryDescriptor(expiresAt);
  const sections = listLabel(token?.section);
  const domains = listLabel(token?.domains);
  const sans = listLabel(certificate?.subjectAltNames);
  const publicKey = [
    certificate?.publicKeyAlgorithm,
    certificate?.publicKeySize,
  ]
    .filter(Boolean)
    .join(' ');
  const certificateIssuer = hasValue(token?.issuer)
    ? token.issuer
    : certificate?.issuer;
  const certificateSerialNumber = hasValue(token?.serial_number)
    ? token.serial_number
    : certificate?.serialNumber;
  const hasRenewalData = hasAnyValue(
    certificate?.renewal?.state,
    certificate?.renewal?.detail,
    certificate?.renewal?.renewBeforeDays,
    certificate?.renewal?.renewsFrom
  );
  const hasKeyLocality = hasAnyValue(
    certificate?.keyMode,
    certificate?.keyReference
  );
  const hasCertificateDetails = hasAnyValue(
    domains,
    certificateIssuer,
    certificateSerialNumber,
    token?.subject,
    token?.contacts,
    token?.renewal_url
  );
  const hasCertificateState = hasAnyValue(
    certificate?.status,
    certificate?.notAfter
  );
  const hasCertificateOperations = hasAnyValue(
    certificate?.status,
    certificate?.notAfter,
    certificate?.keyMode,
    certificate?.keyReference,
    hasRenewalData ? certificate?.renewal : null,
    certificate?.source,
    certificate?.sourceRef,
    certificate?.serialNumber,
    certificate?.notBefore,
    publicKey,
    certificate?.signatureAlgorithm,
    sans,
    certificate?.fingerprintSha256,
    certificate?.id
  );
  const hasObservedLocations = Array.isArray(instances) && instances.length > 0;
  const expiryColor =
    expiry.scheme === 'red'
      ? 'dashboard.state.danger'
      : expiry.scheme === 'orange'
        ? 'dashboard.state.warning'
        : undefined;
  const summaryItems = [
    hasValue(expiresAt)
      ? {
          label: 'Expires',
          value: formatDate(expiresAt),
          help: expiry.label,
          accent: expiryColor,
        }
      : null,
    hasValue(certificate?.notBefore)
      ? { label: 'Valid from', value: formatDate(certificate.notBefore) }
      : null,
    hasValue(certificate?.notAfter)
      ? { label: 'Valid to', value: formatDate(certificate.notAfter) }
      : null,
    hasRenewalData
      ? {
          label: 'Auto-renewal',
          value: renewal.state === 'auto' ? 'Enabled' : renewal.label,
          help: renewal.state === 'auto' ? renewal.label : undefined,
        }
      : null,
    hasKeyLocality
      ? {
          label: 'Key locality',
          value: keyModeLabel(certificate?.keyMode),
        }
      : null,
  ].filter(Boolean);
  const contactGroupLabel = useMemo(() => {
    if (!token?.contact_group_id) return 'Use workspace default';
    const group = contactGroups.find(
      item => String(item.id) === String(token.contact_group_id)
    );
    return group?.name || 'Use workspace default';
  }, [contactGroups, token?.contact_group_id]);

  const workspaceContactOptions = useMemo(
    () =>
      workspaceContacts.map(contact => {
        const name = [contact.first_name, contact.last_name]
          .filter(Boolean)
          .join(' ')
          .trim();
        const label = [name, (contact.phone_e164 || '').trim()]
          .filter(Boolean)
          .join(' - ');
        return <option key={contact.id} value={label} />;
      }),
    [workspaceContacts]
  );

  const commonInputProps = {
    bg: modalTokens.inputBg,
    borderColor: modalTokens.inputBorder,
    borderRadius: '8px',
    color: modalTokens.text,
    size: 'sm',
    _placeholder: { color: modalTokens.muted },
    _hover: { borderColor: modalTokens.focusBorder },
    _focusVisible: {
      borderColor: modalTokens.focusBorder,
      boxShadow: `0 0 0 1px ${modalTokens.focusBorder}`,
    },
  };

  const updateField = useCallback(
    key => event => {
      setEditData(current => ({ ...current, [key]: event.target.value }));
    },
    []
  );

  const beginEditing = useCallback(() => {
    setEditData(createTokenEditData(token));
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
      const updated = await tokenAPI.updateToken(
        token.id,
        createTokenUpdatePayload(editData, token)
      );
      onTokenUpdated?.(updated);
      setIsEditing(false);
    } catch (error) {
      setSaveError(
        error?.response?.data?.error ||
          error?.message ||
          'Failed to update certificate details'
      );
    } finally {
      setSaving(false);
    }
  }, [editData, onTokenUpdated, token]);

  if (!token) return null;

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
            badgeColorScheme='blue'
            statusBadges={
              hasAnyValue(
                certificate?.status,
                expiresAt,
                hasRenewalData ? certificate?.renewal : null,
                hasKeyLocality
                  ? certificate?.keyMode || certificate?.keyReference
                  : null,
                certificate?.renewalPathState &&
                  certificate.renewalPathState !== 'healthy'
                  ? certificate.renewalPathState
                  : null
              ) ? (
                <>
                  <CertificateStateBadges
                    status={certificate?.status}
                    expiry={hasValue(expiresAt) ? expiry : null}
                  />
                  {hasRenewalData ? (
                    <RenewalBadge renewal={certificate.renewal} />
                  ) : null}
                  {hasKeyLocality ? (
                    <KeyLocalityBadge
                      keyMode={certificate.keyMode}
                      keyReference={certificate.keyReference}
                    />
                  ) : null}
                  {certificate?.renewalPathState &&
                  certificate.renewalPathState !== 'healthy' ? (
                    <RenewalPathBadge certificate={certificate} />
                  ) : null}
                  {certificate?.renewalPathState &&
                  certificate.renewalPathState !== 'healthy' ? (
                    <Text
                      w='100%'
                      fontSize='xs'
                      color='dashboard.state.warning'
                    >
                      {certificate.renewalPathSummary ||
                        'Renewal path health could not be fully explained.'}
                    </Text>
                  ) : null}
                </>
              ) : null
            }
          />
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} top={{ base: 3, md: 3 }} />

        <ModalBody {...bodyProps} py={{ base: 4, md: 4 }}>
          <DashboardDetailsSummary items={summaryItems} />

          {certOpsLoading ? (
            <HStack mb={4} spacing={2} color='dashboard.modal.muted'>
              <Spinner size='xs' />
              <Text fontSize='sm'>Loading certificate operations data...</Text>
            </HStack>
          ) : null}
          {certOpsError ? (
            <Text mb={4} fontSize='sm' color='red.400'>
              {certOpsError}
            </Text>
          ) : null}
          {certificateCount > 1 ? (
            <Text mb={4} fontSize='xs' color='dashboard.modal.muted'>
              {certificateCount} certificates reference this token. Showing the
              most recently updated active certificate.
            </Text>
          ) : null}

          <Box minW={0}>
            <Section
              title='Basic information'
              icon={Info}
              columns={2}
              enclosed={compactTableSections}
              compactValues={compactTableSections && !isEditing}
              propertyValueRows={propertyValueRows}
            >
              {hasValue(token.id) ? (
                <DetailRow label='Token ID'>
                  <CopyableId
                    id={token.id}
                    size='sm'
                    color='dashboard.modal.text'
                  />
                </DetailRow>
              ) : null}
              {hasValue(token.type) ? (
                <DetailRow label='Type' value={typeLabel} />
              ) : null}
              {hasValue(token.category) ? (
                <DetailRow label='Category' value={categoryLabel} />
              ) : null}
              {isEditing || hasValue(token.name) ? (
                <DetailRow label='Name' valueTitle={token.name}>
                  {isEditing ? (
                    <Input
                      {...commonInputProps}
                      value={editData.name}
                      onChange={updateField('name')}
                      maxLength={100}
                    />
                  ) : (
                    <Text fontSize='sm'>{token.name}</Text>
                  )}
                </DetailRow>
              ) : null}
              {isEditing || hasValue(sections) ? (
                <DetailRow label='Section' valueTitle={sections}>
                  {isEditing ? (
                    <Input
                      {...commonInputProps}
                      value={editData.section}
                      onChange={updateField('section')}
                      maxLength={255}
                      placeholder='e.g. prod, AWS, security team'
                    />
                  ) : (
                    <Text fontSize='sm'>{sections}</Text>
                  )}
                </DetailRow>
              ) : null}
              {isEditing || hasValue(token.contact_group_id) ? (
                <DetailRow label='Contact group' valueTitle={contactGroupLabel}>
                  {isEditing ? (
                    <Select
                      {...commonInputProps}
                      value={editData.contact_group_id}
                      onChange={updateField('contact_group_id')}
                    >
                      <option value=''>Use workspace default</option>
                      {contactGroups.map(group => (
                        <option key={group.id} value={group.id}>
                          {group.name}
                        </option>
                      ))}
                    </Select>
                  ) : (
                    <Text fontSize='sm'>{contactGroupLabel}</Text>
                  )}
                </DetailRow>
              ) : null}
              {isEditing || hasValue(token.expiresAt) ? (
                <DetailRow label='Asset expiration'>
                  {isEditing ? (
                    <Input
                      {...commonInputProps}
                      type='date'
                      value={editData.expiresAt}
                      onChange={updateField('expiresAt')}
                    />
                  ) : (
                    <Text fontSize='sm'>{formatDate(token.expiresAt)}</Text>
                  )}
                </DetailRow>
              ) : null}
              {hasValue(token.created_at) ? (
                <DetailRow
                  label='Created'
                  value={formatDate(token.created_at)}
                />
              ) : null}
              {token.imported_at ? (
                <DetailRow
                  label='Imported'
                  value={formatDate(token.imported_at)}
                />
              ) : null}
              {hasValue(token.updated_at) ? (
                <DetailRow
                  label='Last updated'
                  value={formatDate(token.updated_at)}
                />
              ) : null}
              {hasValue(token.last_used) ? (
                <DetailRow
                  label='Last used'
                  value={formatDate(token.last_used)}
                />
              ) : null}
            </Section>

            {isEditing || hasCertificateDetails ? (
              <Section
                title='Certificate details'
                icon={FileText}
                columns={2}
                enclosed={compactTableSections}
                compactValues={compactTableSections && !isEditing}
                propertyValueRows={propertyValueRows}
              >
                {isEditing || hasValue(domains) ? (
                  <DetailRow label='Domains' valueTitle={domains}>
                    {isEditing ? (
                      <Input
                        {...commonInputProps}
                        value={editData.domains}
                        onChange={updateField('domains')}
                        maxLength={500}
                        placeholder='example.com, www.example.com'
                      />
                    ) : (
                      <Text fontSize='sm' overflowWrap='anywhere'>
                        {domains}
                      </Text>
                    )}
                  </DetailRow>
                ) : null}
                {isEditing || hasValue(certificateIssuer) ? (
                  <DetailRow label='Issuer' valueTitle={certificateIssuer}>
                    {isEditing ? (
                      <Input
                        {...commonInputProps}
                        value={editData.issuer}
                        onChange={updateField('issuer')}
                        maxLength={100}
                        placeholder="Let's Encrypt, DigiCert"
                      />
                    ) : (
                      <Text fontSize='sm'>{certificateIssuer}</Text>
                    )}
                  </DetailRow>
                ) : null}
                {isEditing || hasValue(certificateSerialNumber) ? (
                  <DetailRow label='Serial number'>
                    {isEditing ? (
                      <Input
                        {...commonInputProps}
                        value={editData.serial_number}
                        onChange={updateField('serial_number')}
                        maxLength={50}
                        placeholder='Optional'
                      />
                    ) : (
                      <CopyableId
                        id={certificateSerialNumber}
                        size='sm'
                        color='dashboard.modal.text'
                      />
                    )}
                  </DetailRow>
                ) : null}
                {isEditing || hasValue(token.subject) ? (
                  <DetailRow label='Subject' valueTitle={token.subject}>
                    {isEditing ? (
                      <Textarea
                        {...commonInputProps}
                        minH='64px'
                        value={editData.subject}
                        onChange={updateField('subject')}
                        maxLength={300}
                        placeholder='CN=example.com, O=Example Corp, C=US'
                      />
                    ) : (
                      <Text fontSize='sm' overflowWrap='anywhere'>
                        {token.subject}
                      </Text>
                    )}
                  </DetailRow>
                ) : null}
                {isEditing || hasValue(token.contacts) ? (
                  <DetailRow
                    label='Contacts / key custodian'
                    valueTitle={token.contacts}
                  >
                    {isEditing ? (
                      <Input
                        {...commonInputProps}
                        value={editData.contacts}
                        onChange={updateField('contacts')}
                        list='certificate-workspace-contacts'
                        maxLength={200}
                        placeholder='Who manages this certificate?'
                      />
                    ) : (
                      <Text fontSize='sm'>{token.contacts}</Text>
                    )}
                  </DetailRow>
                ) : null}
                {isEditing || hasValue(token.renewal_url) ? (
                  <DetailRow label='Renewal URL' valueTitle={token.renewal_url}>
                    {isEditing ? (
                      <Input
                        {...commonInputProps}
                        type='url'
                        value={editData.renewal_url}
                        onChange={updateField('renewal_url')}
                        maxLength={500}
                        placeholder='https://provider.com/renew'
                      />
                    ) : (
                      <Text fontSize='sm' overflowWrap='anywhere'>
                        {token.renewal_url}
                      </Text>
                    )}
                  </DetailRow>
                ) : null}
              </Section>
            ) : null}

            {hasCertificateOperations ? (
              <Section
                title='Certificate operations'
                icon={Settings}
                columns={2}
                enclosed={compactTableSections}
                compactValues={compactTableSections && !isEditing}
                propertyValueRows={propertyValueRows}
              >
                {hasCertificateState ? (
                  <DetailRow label='Certificate state'>
                    <HStack spacing={2} flexWrap='wrap'>
                      <CertificateStateBadges
                        status={certificate.status}
                        expiry={hasValue(certificate.notAfter) ? expiry : null}
                      />
                    </HStack>
                  </DetailRow>
                ) : null}
                {hasKeyLocality ? (
                  <DetailRow label='Key locality'>
                    <KeyLocalityList
                      keyMode={certificate.keyMode}
                      keyReference={certificate.keyReference}
                    />
                  </DetailRow>
                ) : null}
                {hasRenewalData ? (
                  <DetailRow label='Automatic renewal'>
                    <VStack align='start' spacing={1}>
                      <RenewalBadge renewal={certificate.renewal} />
                      <Text fontSize='xs' color='dashboard.modal.muted'>
                        {renewal.help}
                      </Text>
                    </VStack>
                  </DetailRow>
                ) : null}
                {hasAnyValue(certificate?.source, certificate?.sourceRef) ? (
                  <DetailRow label='Registration source'>
                    <VStack align='start' spacing={1}>
                      {hasValue(certificate.source) ? (
                        <Text fontSize='sm'>
                          {sourceLabel(certificate.source)}
                        </Text>
                      ) : null}
                      {certificate.sourceRef ? (
                        <CopyableId
                          id={certificate.sourceRef}
                          label='Reference'
                          size='xs'
                          color='dashboard.modal.text'
                        />
                      ) : null}
                    </VStack>
                  </DetailRow>
                ) : null}
                {hasValue(certificate?.serialNumber) ? (
                  <DetailRow label='Serial number (managed)'>
                    <CopyableId
                      id={certificate.serialNumber}
                      size='sm'
                      color='dashboard.modal.text'
                    />
                  </DetailRow>
                ) : null}
                {hasValue(certificate?.notBefore) ? (
                  <DetailRow
                    label='Valid from'
                    value={formatDate(certificate.notBefore)}
                  />
                ) : null}
                {hasValue(certificate?.notAfter) ? (
                  <DetailRow
                    label='Valid to'
                    value={formatDate(certificate.notAfter)}
                  />
                ) : null}
                {hasValue(publicKey) ? (
                  <DetailRow label='Public key' value={publicKey} />
                ) : null}
                {hasValue(certificate?.signatureAlgorithm) ? (
                  <DetailRow
                    label='Signature algorithm'
                    value={certificate.signatureAlgorithm}
                  />
                ) : null}
                {hasValue(sans) ? (
                  <DetailRow
                    label='Subject alternative names (managed)'
                    value={sans}
                    valueTitle={sans}
                  />
                ) : null}
                {hasValue(certificate?.fingerprintSha256) ? (
                  <DetailRow label='SHA-256 fingerprint'>
                    <CopyableId
                      id={certificate.fingerprintSha256}
                      size='sm'
                      color='dashboard.modal.text'
                    />
                  </DetailRow>
                ) : null}
                {hasValue(certificate?.id) ? (
                  <DetailRow label='Managed certificate ID'>
                    <CopyableId
                      id={certificate.id}
                      size='sm'
                      color='dashboard.modal.text'
                    />
                  </DetailRow>
                ) : null}
              </Section>
            ) : null}

            {isEditing || hasValue(token.notes) ? (
              <Section title='Notes'>
                <DetailRow label='Notes'>
                  {isEditing ? (
                    <Textarea
                      {...commonInputProps}
                      minH='72px'
                      value={editData.notes}
                      onChange={updateField('notes')}
                      maxLength={500}
                      placeholder='Additional information'
                    />
                  ) : (
                    <Text fontSize='sm' whiteSpace='pre-wrap'>
                      {token.notes}
                    </Text>
                  )}
                </DetailRow>
              </Section>
            ) : null}
            {hasObservedLocations ? (
              <Section
                title='Observed locations'
                description='Where this certificate has most recently been observed.'
                contentBorder={false}
              >
                <Box data-detail-row>
                  <CertificateInstances
                    instances={instances}
                    available={instancesAvailable}
                    error={instancesError}
                  />
                </Box>
              </Section>
            ) : null}

            {certificate?.id ? (
              <CertificateTimeline
                compact
                hideWhenEmpty
                subjectType='managed_certificate'
                subjectId={certificate.id}
                renderContainer={content => (
                  <Section
                    title='Job history'
                    description='Latest certificate operation and its activity.'
                    contentBorder={false}
                  >
                    <Box data-detail-row py={2}>
                      {content}
                    </Box>
                  </Section>
                )}
              />
            ) : null}
          </Box>

          <datalist id='certificate-workspace-contacts'>
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
