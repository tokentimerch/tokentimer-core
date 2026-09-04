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

export function CertOpsSortableHeader({ label, sortKey, sort, onSort }) {
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
        onClick={() => onSort(sortKey)}
        aria-label={`Sort by ${label}`}
      >
        {label}
        <Text
          as='span'
          display='inline-block'
          minW='30px'
          ml={2}
          fontSize='10px'
          lineHeight='1'
          textAlign='left'
          color='rgba(147, 197, 253, 0.96)'
          visibility={isActive ? 'visible' : 'hidden'}
          aria-hidden={!isActive}
        >
          {isActive && sort.direction === 'desc' ? 'Desc' : 'Asc'}
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

export function CertOpsMobileFieldLabel({ children, color }) {
  return (
    <Text
      display={{ base: 'block', lg: 'none' }}
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

export function useCertOpsResponsiveTableStyles() {
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
      overflowX: { base: 'visible', lg: 'auto' },
      whiteSpace: { base: 'normal', lg: 'nowrap' },
    },
    tableProps: {
      size: 'sm',
      variant: 'simple',
      display: { base: 'block', lg: 'table' },
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
        '@media screen and (max-width: 61.99em)': { display: 'none' },
      },
    },
    tbodyProps: {
      display: { base: 'grid', lg: 'table-row-group' },
      gap: { base: 3, lg: 0 },
    },
    rowProps: {
      display: { base: 'grid', lg: 'table-row' },
      gridTemplateColumns: { base: 'repeat(2, minmax(0, 1fr))' },
      bg: { base: mobileCardBg, lg: 'transparent' },
      borderWidth: { base: '1px', lg: 0 },
      borderStyle: 'solid',
      borderColor: mobileCardBorder,
      borderRadius: { base: 'md', lg: 0 },
      overflow: 'hidden',
      boxShadow: { base: '0 14px 32px rgba(0, 0, 0, 0.18)', lg: 'none' },
      _hover: { bg: rowHoverBg },
    },
    primaryCellProps: {
      gridColumn: { base: '1 / -1', lg: 'auto' },
      px: { base: 3.5, lg: 4 },
      py: { base: 3.5, lg: '0.55rem' },
      borderBottomWidth: '1px',
      borderColor: mobileActionBorder,
    },
    cellProps: {
      px: { base: 3.5, lg: 4 },
      py: { base: 2.5, lg: '0.55rem' },
      bg: { base: mobileMetaBg, lg: 'transparent' },
      borderBottomWidth: { base: 0, lg: '1px' },
    },
    fullWidthCellProps: {
      gridColumn: { base: '1 / -1', lg: 'auto' },
      px: { base: 3.5, lg: 4 },
      py: { base: 2.5, lg: '0.55rem' },
      bg: { base: mobileMetaBg, lg: 'transparent' },
      borderBottomWidth: { base: 0, lg: '1px' },
    },
    actionCellProps: {
      gridColumn: { base: '1 / -1', lg: 'auto' },
      px: { base: 3.5, lg: 4 },
      py: { base: 2.5, lg: '0.55rem' },
      borderTopWidth: { base: '1px', lg: 0 },
      borderBottomWidth: { base: 0, lg: '1px' },
      borderColor: mobileActionBorder,
    },
  };
}
