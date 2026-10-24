import { Button, Text, Th, Tooltip, useColorModeValue } from '@chakra-ui/react';

const SORT_HEADER_BUTTON_PROPS = {
  variant: 'ghost',
  size: 'xs',
  px: 1,
  h: '24px',
  minH: '24px',
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'flex-start',
  lineHeight: '1',
  whiteSpace: 'nowrap',
  color: 'rgba(148, 163, 184, 0.95)',
  _hover: {
    bg: 'rgba(30, 41, 59, 0.72)',
    color: 'white',
  },
};

export function CertOpsSortableHeader({
  label,
  sortKey,
  sort,
  onSort,
  compact = false,
}) {
  const isActive = sort?.key === sortKey;
  return (
    <Th
      aria-sort={
        isActive
          ? sort.direction === 'asc'
            ? 'ascending'
            : 'descending'
          : 'none'
      }
    >
      <Button
        {...SORT_HEADER_BUTTON_PROPS}
        {...(compact
          ? { whiteSpace: 'normal', maxW: '100%', h: 'auto', flexWrap: 'wrap' }
          : {})}
        onClick={() => onSort(sortKey)}
        aria-label={`Sort by ${label}`}
      >
        {label}
        <Text
          as='span'
          minW={compact ? '0' : '30px'}
          ml={compact ? 1 : 2}
          fontSize='10px'
          lineHeight='1'
          textAlign='left'
          color='rgba(147, 197, 253, 0.96)'
          visibility={isActive ? 'visible' : 'hidden'}
          display={compact && !isActive ? 'none' : 'inline-block'}
          aria-hidden={!isActive}
        >
          {compact
            ? sort?.direction === 'desc'
              ? '↓'
              : '↑'
            : isActive && sort.direction === 'desc'
              ? 'Desc'
              : 'Asc'}
        </Text>
      </Button>
    </Th>
  );
}

export function nextCertOpsTableSort(current, key) {
  return {
    key,
    direction:
      current?.key === key && current.direction === 'asc' ? 'desc' : 'asc',
  };
}

export function CertOpsMobileFieldLabel({
  children,
  color,
  desktopBreakpoint = 'lg',
}) {
  return (
    <Text
      display={{ base: 'block', [desktopBreakpoint]: 'none' }}
      mb={1}
      fontSize='2xs'
      fontWeight='bold'
      color={color}
      textTransform='uppercase'
      letterSpacing='0.08em'
    >
      {children}
    </Text>
  );
}

export function CertOpsTruncatedText({ value, maxLength = 40, ...textProps }) {
  const fullValue =
    value === null || value === undefined || value === ''
      ? '--'
      : String(value);
  const displayValue =
    fullValue.length > maxLength
      ? `${fullValue.slice(0, Math.max(0, maxLength - 1))}…`
      : fullValue;

  return (
    <Tooltip label={fullValue} hasArrow placement='top' openDelay={250}>
      <Text {...textProps} minW={0} noOfLines={1}>
        {displayValue}
      </Text>
    </Tooltip>
  );
}

export function useCertOpsResponsiveTableStyles({
  desktopBreakpoint = 'lg',
} = {}) {
  const rowHoverBg = useColorModeValue('gray.50', 'rgba(30, 41, 59, 0.45)');
  const tableHeadBg = useColorModeValue('gray.50', 'rgba(8, 13, 22, 0.84)');
  const tableHeadColor = useColorModeValue(
    'gray.600',
    'rgba(148, 163, 184, 0.92)'
  );
  const tableCellColor = useColorModeValue(
    'gray.800',
    'rgba(226, 232, 240, 0.94)'
  );
  const mobileCardBg = useColorModeValue('white', 'rgba(13, 19, 26, 0.96)');
  const mobileCardBorder = useColorModeValue(
    'gray.200',
    'rgba(148, 163, 184, 0.2)'
  );
  const mobileMetaBg = useColorModeValue(
    'rgba(248, 250, 252, 0.86)',
    'rgba(2, 6, 23, 0.22)'
  );
  const mobileActionBorder = useColorModeValue(
    'gray.100',
    'rgba(148, 163, 184, 0.14)'
  );

  return {
    tableContainerProps: {
      overflowX: { base: 'visible', [desktopBreakpoint]: 'auto' },
      whiteSpace: { base: 'normal', [desktopBreakpoint]: 'nowrap' },
    },
    tableProps: {
      size: 'sm',
      variant: 'simple',
      display: { base: 'block', [desktopBreakpoint]: 'table' },
      sx: {
        'thead th': {
          color: tableHeadColor,
          background: tableHeadBg,
          fontSize: '0.72rem',
          fontWeight: 'bold',
          letterSpacing: 0,
          textTransform: 'none',
          paddingTop: '0.55rem',
          paddingBottom: '0.55rem',
        },
        'tbody td': { color: tableCellColor },
      },
    },
    theadProps: {
      display: 'table-header-group',
      sx: {
        [`@media screen and (max-width: ${desktopBreakpoint === 'xl' ? '79.99em' : '61.99em'})`]:
          { display: 'none' },
      },
    },
    tbodyProps: {
      display: { base: 'grid', [desktopBreakpoint]: 'table-row-group' },
      gap: { base: 3, [desktopBreakpoint]: 0 },
    },
    rowProps: {
      display: { base: 'grid', [desktopBreakpoint]: 'table-row' },
      gridTemplateColumns: { base: 'repeat(2, minmax(0, 1fr))' },
      bg: { base: mobileCardBg, [desktopBreakpoint]: 'transparent' },
      borderWidth: { base: '1px', [desktopBreakpoint]: 0 },
      borderStyle: 'solid',
      borderColor: mobileCardBorder,
      borderRadius: { base: 'md', [desktopBreakpoint]: 0 },
      overflow: 'hidden',
      boxShadow: {
        base: '0 14px 32px rgba(0, 0, 0, 0.18)',
        [desktopBreakpoint]: 'none',
      },
      _hover: { bg: rowHoverBg },
    },
    primaryCellProps: {
      gridColumn: { base: '1 / -1', [desktopBreakpoint]: 'auto' },
      px: { base: 3.5, [desktopBreakpoint]: 4 },
      py: { base: 3.5, [desktopBreakpoint]: '0.55rem' },
      borderBottomWidth: '1px',
      borderColor: mobileActionBorder,
    },
    cellProps: {
      px: { base: 3.5, [desktopBreakpoint]: 4 },
      py: { base: 2.5, [desktopBreakpoint]: '0.55rem' },
      bg: { base: mobileMetaBg, [desktopBreakpoint]: 'transparent' },
      borderBottomWidth: { base: 0, [desktopBreakpoint]: '1px' },
    },
    fullWidthCellProps: {
      gridColumn: { base: '1 / -1', [desktopBreakpoint]: 'auto' },
      px: { base: 3.5, [desktopBreakpoint]: 4 },
      py: { base: 2.5, [desktopBreakpoint]: '0.55rem' },
      bg: { base: mobileMetaBg, [desktopBreakpoint]: 'transparent' },
      borderBottomWidth: { base: 0, [desktopBreakpoint]: '1px' },
    },
    actionCellProps: {
      gridColumn: { base: '1 / -1', [desktopBreakpoint]: 'auto' },
      px: { base: 3.5, [desktopBreakpoint]: 4 },
      py: { base: 2.5, [desktopBreakpoint]: '0.55rem' },
      borderTopWidth: { base: '1px', [desktopBreakpoint]: 0 },
      borderBottomWidth: { base: 0, [desktopBreakpoint]: '1px' },
      borderColor: mobileActionBorder,
    },
  };
}
