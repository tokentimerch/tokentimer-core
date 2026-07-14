import { useCallback } from 'react';
import {
  Box,
  Button,
  Checkbox,
  Circle,
  Flex,
  HStack,
  IconButton,
  Link,
  Table,
  Tbody,
  Td,
  Text,
  Th,
  Thead,
  Tooltip,
  Tr,
  VStack,
  Badge,
  useColorMode,
  useColorModeValue,
} from '@chakra-ui/react';
import {
  Archive,
  BadgeCheck,
  CalendarClock,
  Database,
  KeyRound,
  LockKeyhole,
  MoreVertical,
  Trash2,
} from 'lucide-react';
import { FiActivity, FiExternalLink } from 'react-icons/fi';
import { AccessibleSpinner } from './Accessibility';
import TruncatedText from './TruncatedText';
import { isRetiredStatus } from './certops/certopsFormat';
import KeyLocalityBadge from './certops/KeyLocalityBadge.jsx';
import { domainValueToUrl } from '../utils/domains.jsx';
import { formatDate } from '../utils/apiClient';
import { formatExpirationDate } from '../utils/dateUtils';

/**
 * Display metadata for retired (revoked/decommissioned) managed certificates.
 * Mirrors the StatusPill shape; light-mode styles live in LIGHT_STATUS_STYLES.
 */
const RETIRED_STATUS_META = {
  revoked: {
    key: 'revoked',
    label: 'Revoked',
    color: '#f87171',
    bg: 'rgba(239, 68, 68, 0.14)',
  },
  decommissioned: {
    key: 'decommissioned',
    label: 'Decommissioned',
    color: '#94a3b8',
    bg: 'rgba(148, 163, 184, 0.14)',
  },
};

/**
 * Resolves the badge a row should show: a retired managed-certificate state
 * (revoked/decommissioned) wins over the expiry-derived status, so retired
 * certs read as retired rather than "expired/healthy" (plan D7).
 */
function effectiveStatusMeta(token, getStatusMeta) {
  const managed = token.__managedCert;
  if (managed && isRetiredStatus(managed.status)) {
    return (
      RETIRED_STATUS_META[String(managed.status).toLowerCase()] ||
      RETIRED_STATUS_META.decommissioned
    );
  }
  return getStatusMeta(token.expiresAt);
}

const CATEGORY_ICON_META = {
  cert: { icon: BadgeCheck, scheme: 'blue' },
  key_secret: { icon: KeyRound, scheme: 'green' },
  license: { icon: LockKeyhole, scheme: 'purple' },
  general: { icon: Database, scheme: 'gray' },
  default: { icon: Database, scheme: 'gray' },
};

const CATEGORY_VISUAL_PALETTES = {
  light: {
    blue: { bg: '#eff6ff', color: '#2563eb', border: '#bfdbfe' },
    green: { bg: '#f0fdf4', color: '#15803d', border: '#bbf7d0' },
    purple: { bg: '#faf5ff', color: '#7e22ce', border: '#e9d5ff' },
    gray: { bg: '#f1f5f9', color: '#475569', border: '#cbd5e1' },
  },
  dark: {
    blue: {
      bg: 'rgba(37, 99, 235, 0.22)',
      color: '#93c5fd',
      border: 'rgba(59, 130, 246, 0.35)',
    },
    green: {
      bg: 'rgba(22, 163, 74, 0.22)',
      color: '#86efac',
      border: 'rgba(34, 197, 94, 0.35)',
    },
    purple: {
      bg: 'rgba(126, 34, 206, 0.22)',
      color: '#d8b4fe',
      border: 'rgba(168, 85, 247, 0.35)',
    },
    gray: {
      bg: 'rgba(100, 116, 139, 0.22)',
      color: '#cbd5e1',
      border: 'rgba(148, 163, 184, 0.35)',
    },
  },
};

export function resolveCategoryVisual(categoryValue, isLight) {
  const meta = CATEGORY_ICON_META[categoryValue] || CATEGORY_ICON_META.default;
  const palette = isLight
    ? CATEGORY_VISUAL_PALETTES.light
    : CATEGORY_VISUAL_PALETTES.dark;
  const colors = palette[meta.scheme] || palette.gray;
  return { icon: meta.icon, ...colors };
}

const COLUMN_META = {
  name: { label: 'Name', minW: '210px', sortable: true },
  type: { label: 'Type', minW: '160px', sortable: true },
  location: { label: 'Domain / Location', minW: '190px', sortable: true },
  owner: { label: 'Owner / Used By', minW: '170px', sortable: true },
  used_by: { label: 'Used By', minW: '120px', sortable: true },
  contact_group: {
    label: 'Contact group',
    minW: '140px',
    sortable: true,
  },
  last_used: { label: 'Last Used', minW: '120px', sortable: true },
  domains: { label: 'Domains', minW: '130px', sortable: true },
  issuer: { label: 'Issuer', minW: '100px', sortable: true },
  privileges: { label: 'Privileges', minW: '130px', sortable: true },
  vendor: { label: 'Vendor', minW: '120px', sortable: true },
  license_type: { label: 'License Type', minW: '130px', sortable: true },
  expiresAt: { label: 'Expiration', minW: '130px', sortable: true },
  status: { label: 'Status', minW: '110px', sortable: true },
  actions: { label: 'Actions', minW: '116px', sortable: false, align: 'right' },
};

const SORT_HEADER_BUTTON_PROPS = {
  variant: 'ghost',
  size: 'xs',
  px: 1,
  color: 'rgba(148, 163, 184, 0.95)',
  _hover: {
    bg: 'rgba(30, 41, 59, 0.72)',
    color: 'white',
  },
};

/** Column keys per inventory mode (Phase 2 plan). */
export const columnsByMode = {
  mixed: [
    'name',
    'type',
    'location',
    'owner',
    'contact_group',
    'expiresAt',
    'status',
    'actions',
  ],
  cert: [
    'name',
    'type',
    'domains',
    'issuer',
    'contact_group',
    'expiresAt',
    'status',
    'actions',
  ],
  key_secret: [
    'name',
    'type',
    'location',
    'used_by',
    'contact_group',
    'privileges',
    'last_used',
    'expiresAt',
    'status',
    'actions',
  ],
  license: [
    'name',
    'type',
    'vendor',
    'license_type',
    'contact_group',
    'expiresAt',
    'status',
    'actions',
  ],
  general: [
    'name',
    'type',
    'location',
    'used_by',
    'contact_group',
    'expiresAt',
    'status',
    'actions',
  ],
};

const SINGLE_CATEGORY_MODES = ['cert', 'key_secret', 'license', 'general'];

/**
 * Derive inventory table mode from active category filters.
 * @param {string[] | undefined} selectedCategories
 * @returns {'mixed' | 'cert' | 'key_secret' | 'license' | 'general'}
 */
export function inventoryMode(selectedCategories) {
  const categories = Array.isArray(selectedCategories)
    ? selectedCategories.filter(Boolean)
    : [];
  if (
    categories.length === 1 &&
    SINGLE_CATEGORY_MODES.includes(categories[0])
  ) {
    return categories[0];
  }
  return 'mixed';
}

/**
 * Alert contact group label for a token (explicit id or workspace default).
 * @param {object | null | undefined} token
 * @param {Array<{ id: string, name?: string }>} contactGroups
 * @param {string} defaultContactGroupId
 * @returns {string}
 */
export function resolveContactGroupLabel(
  token,
  contactGroups = [],
  defaultContactGroupId = ''
) {
  const explicitId =
    token?.contact_group_id != null &&
    String(token.contact_group_id).trim() !== ''
      ? String(token.contact_group_id).trim()
      : '';
  const effectiveId = explicitId || String(defaultContactGroupId || '').trim();
  if (!effectiveId) return 'Workspace default';
  const groups = Array.isArray(contactGroups) ? contactGroups : [];
  const group = groups.find(g => String(g?.id) === effectiveId);
  return group?.name || effectiveId;
}

function truncateNameHint(text, maxLen = 72) {
  const trimmed = text ? String(text).trim() : '';
  if (!trimmed) return '';
  return trimmed.length > maxLen ? `${trimmed.slice(0, maxLen)}…` : trimmed;
}

/**
 * Name subtitle for fields not shown as table columns (e.g. privileges in mixed mode).
 * @param {object | null | undefined} token
 * @param {'mixed' | 'cert' | 'key_secret' | 'license' | 'general'} mode
 * @returns {string}
 */
export function getNameSubtitle(token, mode) {
  if (!token) return '';

  const columns = new Set(columnsByMode[mode] || columnsByMode.mixed);

  if (token.category === 'key_secret' && !columns.has('privileges')) {
    return truncateNameHint(token.privileges);
  }
  if (token.category === 'cert' && !columns.has('subject')) {
    return truncateNameHint(token.subject);
  }
  if (!columns.has('vendor') && !columns.has('license_type')) {
    const parts = [token.vendor, token.license_type]
      .map(value => (value ? String(value).trim() : ''))
      .filter(Boolean);
    return truncateNameHint(parts.join(' · '));
  }

  return '';
}

function resolveColumns(mode) {
  const keys = columnsByMode[mode] || columnsByMode.mixed;
  return keys.map(key => {
    const meta = {
      key,
      ...(COLUMN_META[key] || { label: key, minW: '100px', sortable: true }),
    };
    if (key === 'location' && (mode === 'key_secret' || mode === 'general')) {
      meta.label = 'Location';
      meta.minW = mode === 'general' ? '100px' : '100px';
    }
    if (key === 'used_by' && mode === 'general') {
      meta.minW = '150px';
    }
    return meta;
  });
}

function sortAriaValue(sort, columnKey) {
  if (!sort || sort.key !== columnKey) return 'none';
  return sort.direction === 'asc' ? 'ascending' : 'descending';
}

function SortableHeader({ column, sort, onSort }) {
  if (!column.sortable) {
    return (
      <Th
        key={column.key}
        minW={column.minW}
        textAlign={column.align || 'left'}
      >
        {column.label}
      </Th>
    );
  }

  const sortKey = column.key === 'used_by' ? 'owner' : column.key;
  const isActive = sort?.key === sortKey;

  return (
    <Th
      key={column.key}
      minW={column.minW}
      textAlign={column.align || 'left'}
      aria-sort={sortAriaValue(sort, sortKey)}
    >
      <Button
        {...SORT_HEADER_BUTTON_PROPS}
        onClick={() => onSort(sortKey)}
        aria-label={`Sort by ${column.label}`}
      >
        {column.label}
        {isActive && (
          <Text
            as='span'
            ml={2}
            fontSize='10px'
            color='rgba(147, 197, 253, 0.96)'
          >
            {sort.direction === 'asc' ? 'Asc' : 'Desc'}
          </Text>
        )}
      </Button>
    </Th>
  );
}

const LIGHT_STATUS_STYLES = {
  'never-expires': {
    bg: '#ecfeff',
    color: '#0e7490',
    dot: '#0891b2',
    border: '#a5f3fc',
  },
  expired: {
    bg: '#f1f5f9',
    color: '#475569',
    dot: '#64748b',
    border: '#cbd5e1',
  },
  critical: {
    bg: '#fef2f2',
    color: '#b91c1c',
    dot: '#dc2626',
    border: '#fecaca',
  },
  'due-soon': {
    bg: '#fff7ed',
    color: '#c2410c',
    dot: '#ea580c',
    border: '#fed7aa',
  },
  healthy: {
    bg: '#f0fdf4',
    color: '#15803d',
    dot: '#16a34a',
    border: '#bbf7d0',
  },
  revoked: {
    bg: '#fef2f2',
    color: '#b91c1c',
    dot: '#dc2626',
    border: '#fecaca',
  },
  decommissioned: {
    bg: '#f1f5f9',
    color: '#475569',
    dot: '#64748b',
    border: '#cbd5e1',
  },
};

function resolveStatusBadgeStyles(status, isLight) {
  if (isLight) {
    return LIGHT_STATUS_STYLES[status.key] || LIGHT_STATUS_STYLES.healthy;
  }

  return {
    bg: status.bg,
    color: status.color,
    dot: status.color,
    border: status.color,
  };
}

function StatusPill({ status, styles, minW, justify = 'flex-start' }) {
  return (
    <Box
      as='span'
      display='inline-flex'
      alignItems='center'
      justifyContent={justify}
      bg={styles.bg}
      color={styles.color}
      border='1px solid'
      borderColor={styles.border}
      borderRadius='md'
      px={2.5}
      py={0.5}
      fontWeight='semibold'
      fontSize='xs'
      lineHeight='short'
      minW={minW}
      flexShrink={0}
      whiteSpace='nowrap'
      sx={{ color: `${styles.color} !important` }}
    >
      <HStack spacing={1.5} minW={0} flexWrap='nowrap'>
        <Circle size='6px' bg={styles.dot} flexShrink={0} />
        <Text
          as='span'
          fontSize='xs'
          fontWeight='semibold'
          whiteSpace='nowrap'
          noOfLines={1}
          sx={{ color: `${styles.color} !important` }}
        >
          {status.label}
        </Text>
      </HStack>
    </Box>
  );
}

function MobileMetaItem({ label, value, children }) {
  const labelColor = useColorModeValue('gray.500', 'rgba(148, 163, 184, 0.92)');
  const valueColor = useColorModeValue('gray.800', 'rgba(226, 232, 240, 0.92)');

  return (
    <Box minW={0} flex='1'>
      <Text
        color={labelColor}
        fontSize='10px'
        fontWeight='semibold'
        lineHeight='short'
        textTransform='uppercase'
        mb={1}
      >
        {label}
      </Text>
      {children || (
        <Text color={valueColor} fontSize='sm' noOfLines={2}>
          {value || '-'}
        </Text>
      )}
    </Box>
  );
}

function StatusBadge({ token, getStatusMeta }) {
  const { colorMode } = useColorMode();
  const status = effectiveStatusMeta(token, getStatusMeta);
  const styles = resolveStatusBadgeStyles(status, colorMode === 'light');
  const managed = token.__managedCert;

  return (
    <HStack spacing={2} flexWrap='wrap'>
      <StatusPill status={status} styles={styles} />
      {managed?.status && !isRetiredStatus(managed.status) ? (
        <Tooltip label='Managed certificate lifecycle status'>
          <Badge
            colorScheme='purple'
            variant='subtle'
            textTransform='none'
            fontSize='xs'
          >
            {managed.status}
          </Badge>
        </Tooltip>
      ) : null}
      {token.monitor_health_status && (
        <Tooltip
          label={`${token.monitor_url || 'Endpoint'}: ${token.monitor_health_status}${
            token.monitor_response_ms ? ` (${token.monitor_response_ms}ms)` : ''
          }`}
        >
          <Box as='span' display='inline-flex'>
            <FiActivity
              size={16}
              color={
                token.monitor_health_status === 'healthy'
                  ? '#22c55e'
                  : token.monitor_health_status === 'error'
                    ? '#e11d48'
                    : '#ff6b00'
              }
            />
          </Box>
        </Tooltip>
      )}
    </HStack>
  );
}

function DomainsCell({ token, mutedTextColor }) {
  const domains = Array.isArray(token.domains) ? token.domains : [];
  if (domains.length === 0) {
    return <Text color={mutedTextColor}>-</Text>;
  }

  return (
    <VStack align='start' spacing={1} maxW='240px'>
      <HStack spacing={1} minW={0} w='full'>
        <Link
          href={domainValueToUrl(domains[0])}
          isExternal
          color='blue.300'
          fontSize='sm'
          noOfLines={1}
          minW={0}
          wordBreak='break-all'
          title={domains[0]}
          onClick={event => event.stopPropagation()}
        >
          {domains[0]}
        </Link>
        <FiExternalLink size={13} style={{ flexShrink: 0 }} />
      </HStack>
      {domains.length > 1 && (
        <Text color={mutedTextColor} fontSize='xs'>
          +{domains.length - 1} more
        </Text>
      )}
    </VStack>
  );
}

function LocationCell({ token, getTokenLocation, mutedTextColor }) {
  const location = getTokenLocation(token);
  const isDomain =
    token.category === 'cert' &&
    Array.isArray(token.domains) &&
    token.domains.length > 0;

  if (isDomain) {
    return (
      <HStack spacing={1} minW={0} maxW='240px'>
        <Link
          href={domainValueToUrl(location)}
          isExternal
          color='blue.300'
          fontSize='sm'
          noOfLines={1}
          minW={0}
          wordBreak='break-all'
          title={location}
          onClick={event => event.stopPropagation()}
        >
          {location}
        </Link>
        <FiExternalLink size={13} style={{ flexShrink: 0 }} />
        {token.domains.length > 1 && (
          <Text color={mutedTextColor} fontSize='xs'>
            +{token.domains.length - 1}
          </Text>
        )}
      </HStack>
    );
  }

  return <TruncatedText text={location} maxLines={2} maxWidth='180px' />;
}

function NameCell({ token, mode, getCategoryVisual, mutedTextColor }) {
  const nameColor = useColorModeValue('gray.900', 'white');
  const visual = getCategoryVisual(token.category);
  const VisualIcon = visual.icon;
  const subtitle = getNameSubtitle(token, mode);
  const managed = token.__managedCert;

  return (
    <HStack spacing={3} minW={0} maxW='340px'>
      <Circle
        size='32px'
        bg={visual.bg}
        color={visual.color}
        border='1px solid'
        borderColor={visual.border}
        flex='0 0 auto'
      >
        <VisualIcon size={16} />
      </Circle>
      <Box minW={0} maxW='296px'>
        <Text
          color={nameColor}
          fontWeight='medium'
          noOfLines={1}
          wordBreak='break-all'
          title={token.name}
        >
          {token.name}
        </Text>
        {subtitle ? (
          <Text color={mutedTextColor} fontSize='xs' noOfLines={1}>
            {subtitle}
          </Text>
        ) : null}
        {managed ? (
          <Box mt={1}>
            <KeyLocalityBadge
              keyMode={managed.keyMode}
              keyReference={managed.keyReference}
            />
          </Box>
        ) : null}
      </Box>
    </HStack>
  );
}

function InventoryRowActions({
  token,
  isViewer,
  onOpenTokenModal,
  onOpenRenew,
  onDeleteToken,
}) {
  const detailsColor = useColorModeValue(
    'gray.600',
    'rgba(203, 213, 225, 0.9)'
  );
  const actionHoverBg = useColorModeValue('gray.100', 'rgba(30, 41, 59, 0.72)');
  const actionFocusShadow = useColorModeValue(
    '0 0 0 2px rgba(37, 99, 235, 0.28)',
    '0 0 0 2px rgba(96, 165, 250, 0.34)'
  );
  const actionButtonProps = {
    size: 'sm',
    variant: 'ghost',
    color: detailsColor,
    borderRadius: 'md',
    transition:
      'background 140ms ease, color 140ms ease, box-shadow 140ms ease',
    _hover: { bg: actionHoverBg },
    _active: { bg: actionHoverBg },
    _focusVisible: {
      bg: actionHoverBg,
      boxShadow: actionFocusShadow,
    },
  };

  return (
    <HStack spacing={1} justify='flex-end'>
      <Tooltip label='Details'>
        <IconButton
          {...actionButtonProps}
          aria-label={`Show full details for token ${token.name}`}
          icon={<MoreVertical size={16} />}
          onClick={() => onOpenTokenModal(token)}
        />
      </Tooltip>
      {!isViewer && (
        <>
          <Tooltip label='Renew'>
            <IconButton
              {...actionButtonProps}
              aria-label={`Renew token ${token.name}`}
              icon={<CalendarClock size={16} />}
              onClick={() => onOpenRenew(token)}
            />
          </Tooltip>
          {token.__managedCert ? (
            <Tooltip label='Retire (revoke / decommission)'>
              <IconButton
                {...actionButtonProps}
                aria-label={`Retire certificate ${token.name}`}
                icon={<Archive size={16} />}
                onClick={() => onDeleteToken(token.id)}
              />
            </Tooltip>
          ) : (
            <Tooltip label='Delete'>
              <IconButton
                {...actionButtonProps}
                aria-label={`Delete token ${token.name}`}
                icon={<Trash2 size={16} />}
                onClick={() => onDeleteToken(token.id)}
              />
            </Tooltip>
          )}
        </>
      )}
    </HStack>
  );
}

function renderDataCell({ column, token, mode, helpers }) {
  const {
    getAssetTypeLabel,
    getTokenLocation,
    getTokenOwner,
    getStatusMeta,
    mutedTextColor,
  } = helpers;

  switch (column.key) {
    case 'name':
      return (
        <NameCell
          token={token}
          mode={mode}
          getCategoryVisual={helpers.getCategoryVisual}
          mutedTextColor={mutedTextColor}
        />
      );
    case 'type':
      return (
        <TruncatedText
          text={getAssetTypeLabel(token)}
          maxLines={2}
          maxWidth='150px'
        />
      );
    case 'location':
      if (mode === 'key_secret' || mode === 'general') {
        return (
          <TruncatedText
            text={token.location || '-'}
            maxLines={2}
            maxWidth='100px'
          />
        );
      }
      return (
        <LocationCell
          token={token}
          getTokenLocation={getTokenLocation}
          mutedTextColor={mutedTextColor}
        />
      );
    case 'owner':
    case 'used_by':
      return (
        <TruncatedText
          text={
            column.key === 'used_by'
              ? token.used_by || '-'
              : getTokenOwner(token)
          }
          maxLines={2}
          maxWidth={mode === 'general' ? '150px' : '160px'}
        />
      );
    case 'contact_group':
      return (
        <TruncatedText
          text={helpers.getTokenContactGroup(token)}
          maxLines={2}
          maxWidth='140px'
        />
      );
    case 'domains':
      return <DomainsCell token={token} mutedTextColor={mutedTextColor} />;
    case 'issuer':
      return (
        <TruncatedText
          text={token.__managedCert?.issuer || token.issuer}
          maxLines={2}
          maxWidth='100px'
        />
      );
    case 'privileges':
      return (
        <TruncatedText text={token.privileges} maxLines={3} maxWidth='130px' />
      );
    case 'vendor':
      return (
        <TruncatedText text={token.vendor} maxLines={3} maxWidth='120px' />
      );
    case 'license_type':
      return (
        <TruncatedText
          text={token.license_type}
          maxLines={3}
          maxWidth='130px'
        />
      );
    case 'last_used':
      return (
        <Text color={mutedTextColor} fontSize='sm'>
          {token.last_used ? formatDate(token.last_used) : '-'}
        </Text>
      );
    case 'expiresAt':
      return formatExpirationDate(token.expiresAt);
    case 'status':
      return <StatusBadge token={token} getStatusMeta={getStatusMeta} />;
    case 'actions':
      return (
        <InventoryRowActions
          token={token}
          isViewer={helpers.isViewer}
          onOpenTokenModal={helpers.onOpenTokenModal}
          onOpenRenew={helpers.onOpenRenew}
          onDeleteToken={helpers.onDeleteToken}
        />
      );
    default:
      return null;
  }
}

function AssetInventoryMobileCard({
  token,
  mode,
  isViewer,
  selectedIds,
  onToggleSelect,
  helpers,
}) {
  const { colorMode } = useColorMode();
  const status = effectiveStatusMeta(token, helpers.getStatusMeta);
  const statusStyles = resolveStatusBadgeStyles(status, colorMode === 'light');
  const cardTitleColor = useColorModeValue('gray.900', 'white');
  const cardBg = useColorModeValue('white', 'rgba(13, 19, 26, 0.96)');
  const cardHoverBg = useColorModeValue('gray.50', 'rgba(17, 24, 39, 0.98)');
  const cardBorderColor = useColorModeValue(
    'gray.200',
    'rgba(148, 163, 184, 0.2)'
  );
  const metaBorderColor = useColorModeValue(
    'gray.100',
    'rgba(148, 163, 184, 0.12)'
  );
  const metaBg = useColorModeValue(
    'rgba(248, 250, 252, 0.86)',
    'rgba(2, 6, 23, 0.22)'
  );
  const actionBorderColor = useColorModeValue(
    'gray.100',
    'rgba(148, 163, 184, 0.14)'
  );
  const neutralButtonColor = useColorModeValue(
    'gray.600',
    'rgba(203, 213, 225, 0.9)'
  );
  const actionHoverBg = useColorModeValue('gray.100', 'rgba(30, 41, 59, 0.72)');
  const actionFocusShadow = useColorModeValue(
    '0 0 0 2px rgba(37, 99, 235, 0.28)',
    '0 0 0 2px rgba(96, 165, 250, 0.34)'
  );
  const mobileActionButtonProps = {
    size: 'sm',
    h: '38px',
    flex: '1',
    minW: 0,
    borderRadius: '0',
    variant: 'ghost',
    color: neutralButtonColor,
    fontSize: 'xs',
    fontWeight: 'semibold',
    transition:
      'background 140ms ease, color 140ms ease, box-shadow 140ms ease',
    _hover: { bg: actionHoverBg },
    _active: { bg: actionHoverBg },
    _focusVisible: {
      bg: actionHoverBg,
      boxShadow: actionFocusShadow,
      zIndex: 1,
    },
  };
  const visual = helpers.getCategoryVisual(token.category);
  const VisualIcon = visual.icon;
  const nameSubtitle = getNameSubtitle(token, mode);
  const location = helpers.getTokenLocation(token);
  const owner = helpers.getTokenOwner(token);
  const contactGroup = helpers.getTokenContactGroup(token);
  const expiresAtLabel = formatExpirationDate(token.expiresAt);

  return (
    <Box
      p={0}
      bg={cardBg || helpers.mobileCardBg}
      border='1px solid'
      borderColor={cardBorderColor}
      borderRadius='md'
      overflow='hidden'
      boxShadow='0 14px 32px rgba(0, 0, 0, 0.18)'
      transition='background 140ms ease, border-color 140ms ease'
      _hover={{ bg: cardHoverBg, borderColor: 'rgba(59, 130, 246, 0.3)' }}
    >
      <VStack align='stretch' spacing={0}>
        <HStack align='start' spacing={3} p={3.5}>
          <HStack align='start' spacing={3} minW={0} flex='1'>
            <Box pt={1} flex='0 0 auto'>
              {!isViewer && (
                <Checkbox
                  isChecked={selectedIds.includes(token.id)}
                  onChange={() => onToggleSelect(token.id)}
                />
              )}
            </Box>
            <Circle
              size='38px'
              bg={visual.bg}
              color={visual.color}
              border='1px solid'
              borderColor={visual.border}
              flex='0 0 auto'
            >
              <VisualIcon size={18} />
            </Circle>
            <Box minW={0} flex='1'>
              <Text
                fontWeight='bold'
                color={cardTitleColor}
                wordBreak='break-word'
                lineHeight='short'
                noOfLines={2}
              >
                {token.name}
              </Text>
              <Text
                color={helpers.secondaryTextColor}
                fontSize='sm'
                lineHeight='short'
                mt={1}
                noOfLines={1}
              >
                {helpers.getAssetTypeLabel(token)}
              </Text>
              {nameSubtitle ? (
                <Text
                  color={helpers.mutedTextColor}
                  fontSize='xs'
                  mt={1}
                  noOfLines={2}
                >
                  {nameSubtitle}
                </Text>
              ) : null}
              <Box mt={2}>
                <StatusPill
                  status={status}
                  styles={statusStyles}
                  minW='96px'
                  justify='center'
                />
              </Box>
            </Box>
          </HStack>
        </HStack>

        <Box px={3.5} pb={3.5}>
          <Box
            bg={metaBg}
            border='1px solid'
            borderColor={metaBorderColor}
            borderRadius='md'
            p={3}
          >
            <VStack align='stretch' spacing={3}>
              <HStack align='start' spacing={3}>
                <MobileMetaItem label='Location' value={location} />
                <MobileMetaItem label='Owner' value={owner} />
              </HStack>
              <HStack align='start' spacing={3}>
                <MobileMetaItem label='Contact group' value={contactGroup} />
                <MobileMetaItem label='Expiration' value={expiresAtLabel} />
              </HStack>
            </VStack>
          </Box>
        </Box>

        <HStack
          spacing={0}
          borderTop='1px solid'
          borderColor={actionBorderColor}
          align='stretch'
        >
          <Button
            {...mobileActionButtonProps}
            leftIcon={<MoreVertical size={14} />}
            onClick={() => helpers.onOpenTokenModal(token)}
          >
            Details
          </Button>
          {!isViewer && (
            <>
              <Button
                {...mobileActionButtonProps}
                leftIcon={<CalendarClock size={14} />}
                onClick={() => helpers.onOpenRenew(token)}
              >
                Renew
              </Button>
              {token.__managedCert ? (
                <Button
                  {...mobileActionButtonProps}
                  leftIcon={<Archive size={14} />}
                  onClick={() => helpers.onDeleteToken(token.id)}
                >
                  Retire
                </Button>
              ) : (
                <Button
                  {...mobileActionButtonProps}
                  leftIcon={<Trash2 size={14} />}
                  onClick={() => helpers.onDeleteToken(token.id)}
                >
                  Delete
                </Button>
              )}
            </>
          )}
        </HStack>
      </VStack>
    </Box>
  );
}

/**
 * Asset inventory table with mode-specific columns (mixed + per-category).
 */
export default function AssetInventoryTable({
  tokens = [],
  selectedCategories,
  inventoryMode: inventoryModeProp,
  sort,
  onSort,
  selectedIds = [],
  onToggleSelect,
  onToggleSelectAll,
  isViewer = false,
  bulkActions = null,
  paginationControls = null,
  visibleCount = 0,
  tokensLoading = false,
  allTokensCount = 0,
  sortedVisibleCount = 0,
  emptyMessage,
  noMatchMessage = 'No assets match the current filters.',
  getAssetTypeLabel,
  getCategoryLabel = () => '-',
  getTokenLocation,
  getTokenOwner,
  getTokenContactGroup,
  getStatusMeta,
  getCategoryVisual: getCategoryVisualProp,
  contactGroups = [],
  defaultContactGroupId = '',
  onOpenTokenModal,
  onOpenRenew,
  onDeleteToken,
  mutedTextColor = 'rgba(148, 163, 184, 0.88)',
  secondaryTextColor = 'rgba(203, 213, 225, 0.9)',
  emptyTextColor = 'rgba(148, 163, 184, 0.88)',
  hoverBgColor = 'rgba(30, 41, 59, 0.45)',
  mobileCardBg = 'rgba(15, 23, 42, 0.55)',
  loadMoreCategories = [],
  fetchTokensForCategory,
  categoryLoading = {},
}) {
  const { colorMode } = useColorMode();
  const resolveVisual = useCallback(
    category => resolveCategoryVisual(category, colorMode === 'light'),
    [colorMode]
  );
  const getCategoryVisual = getCategoryVisualProp ?? resolveVisual;

  const resolveContactGroup =
    getTokenContactGroup ||
    (token =>
      resolveContactGroupLabel(token, contactGroups, defaultContactGroupId));

  const mode = inventoryModeProp || inventoryMode(selectedCategories);
  const columns = resolveColumns(mode);
  const dataColumns = columns.filter(column => column.key !== 'actions');
  const actionsColumn = columns.find(column => column.key === 'actions');

  const helpers = {
    getAssetTypeLabel,
    getCategoryLabel,
    getTokenLocation,
    getTokenOwner,
    getTokenContactGroup: resolveContactGroup,
    getStatusMeta,
    getCategoryVisual,
    isViewer,
    onOpenTokenModal,
    onOpenRenew,
    onDeleteToken,
    mutedTextColor,
    secondaryTextColor,
    mobileCardBg,
  };

  const pageIds = tokens.map(token => token.id);
  const selectedOnPage = selectedIds.filter(id => pageIds.includes(id));
  const allOnPageSelected =
    tokens.length > 0 && selectedOnPage.length === tokens.length;
  const someOnPageSelected =
    selectedOnPage.length > 0 && selectedOnPage.length < tokens.length;

  const resolvedEmptyMessage =
    emptyMessage ||
    (isViewer
      ? 'No tokens in this workspace.'
      : 'No tokens found. Create your first token above.');

  return (
    <>
      {(visibleCount > 0 || paginationControls) && (
        <Flex
          align={{ base: 'stretch', md: 'center' }}
          justify='space-between'
          direction={{ base: 'column', lg: 'row' }}
          gap={3}
          mb={4}
        >
          <Text color={mutedTextColor} fontSize='sm' whiteSpace='nowrap'>
            {visibleCount} visible
          </Text>
          {paginationControls}
        </Flex>
      )}

      {bulkActions}

      {tokensLoading && allTokensCount === 0 ? (
        <Flex justify='center' p={{ base: 4, md: 8 }} overflowX='hidden'>
          <AccessibleSpinner size='lg' aria-label='Loading tokens' />
        </Flex>
      ) : allTokensCount === 0 ? (
        <Text textAlign='center' color={emptyTextColor} p={{ base: 4, md: 8 }}>
          {resolvedEmptyMessage}
        </Text>
      ) : sortedVisibleCount === 0 ? (
        <Text textAlign='center' color={emptyTextColor} p={{ base: 4, md: 8 }}>
          {noMatchMessage}
        </Text>
      ) : tokens.length === 0 ? (
        <Text textAlign='center' color={emptyTextColor} p={{ base: 4, md: 8 }}>
          {noMatchMessage}
        </Text>
      ) : (
        <>
          <Box display={{ base: 'block', lg: 'none' }}>
            <VStack align='stretch' spacing={3}>
              {tokens.map(token => (
                <AssetInventoryMobileCard
                  key={token.id}
                  token={token}
                  mode={mode}
                  isViewer={isViewer}
                  selectedIds={selectedIds}
                  onToggleSelect={onToggleSelect}
                  helpers={helpers}
                />
              ))}
            </VStack>
          </Box>

          <Box overflowX='auto' display={{ base: 'none', lg: 'block' }}>
            <Table variant='simple' size='sm'>
              <Thead>
                <Tr>
                  {!isViewer && (
                    <Th w='42px'>
                      <Checkbox
                        isChecked={allOnPageSelected}
                        isIndeterminate={someOnPageSelected}
                        onChange={event => {
                          if (typeof onToggleSelectAll === 'function') {
                            onToggleSelectAll(event.target.checked, pageIds);
                          }
                        }}
                      />
                    </Th>
                  )}
                  {dataColumns.map(column => (
                    <SortableHeader
                      key={column.key}
                      column={column}
                      sort={sort}
                      onSort={onSort}
                    />
                  ))}
                  {actionsColumn ? (
                    <Th textAlign='right' minW={actionsColumn.minW}>
                      {actionsColumn.label}
                    </Th>
                  ) : null}
                </Tr>
              </Thead>
              <Tbody>
                {tokens.map(token => (
                  <Tr
                    key={token.id}
                    cursor='pointer'
                    _hover={{ bg: hoverBgColor }}
                    onClick={event => {
                      if (event.target.closest('button')) return;
                      if (event.target.closest('a')) return;
                      if (event.target.closest('input[type="checkbox"]'))
                        return;
                      onOpenTokenModal(token);
                    }}
                  >
                    {!isViewer && (
                      <Td onClick={event => event.stopPropagation()}>
                        <Checkbox
                          isChecked={selectedIds.includes(token.id)}
                          onChange={() => onToggleSelect(token.id)}
                        />
                      </Td>
                    )}
                    {dataColumns.map(column => (
                      <Td key={column.key}>
                        {renderDataCell({ column, token, mode, helpers })}
                      </Td>
                    ))}
                    {actionsColumn ? (
                      <Td textAlign='right'>
                        {renderDataCell({
                          column: actionsColumn,
                          token,
                          mode,
                          helpers,
                        })}
                      </Td>
                    ) : null}
                  </Tr>
                ))}
              </Tbody>
            </Table>
          </Box>

          {loadMoreCategories.length > 0 && (
            <HStack spacing={2} flexWrap='wrap' justify='center' mt={4}>
              {loadMoreCategories.map(category => (
                <Button
                  key={category.value}
                  size='sm'
                  variant='outline'
                  borderColor='rgba(148, 163, 184, 0.22)'
                  color='rgba(226, 232, 240, 0.94)'
                  _hover={{ bg: 'rgba(30, 41, 59, 0.72)' }}
                  onClick={() => fetchTokensForCategory?.(category.value)}
                  isLoading={!!categoryLoading?.[category.value]}
                  loadingText='Loading...'
                >
                  Load more {category.label}
                </Button>
              ))}
            </HStack>
          )}
        </>
      )}
    </>
  );
}
