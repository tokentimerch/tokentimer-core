import { createContext, useContext } from 'react';
import {
  Badge,
  Box,
  Button,
  Flex,
  Grid,
  GridItem,
  Heading,
  Icon,
  ModalFooter,
  Text,
  Tooltip,
} from '@chakra-ui/react';
import { DASHBOARD_MODAL_HEADING_FONT } from './DashboardModalFrame.jsx';

const DashboardModalDataSectionContext = createContext(false);

function hasDisplayValue(value) {
  if (Array.isArray(value)) return value.some(hasDisplayValue);
  if (typeof value === 'string') return value.trim().length > 0;
  return value !== null && value !== undefined;
}

export function DashboardDetailsModalHeader({
  title,
  subtitle,
  badgeLabel,
  badgeColorScheme = 'gray',
  statusBadges,
}) {
  return (
    <Flex
      justify='space-between'
      align='flex-start'
      gap={5}
      pr={{ base: 0, md: 10 }}
      pt={{ base: 9, md: 0 }}
      position='relative'
    >
      <Box minW={0} flex='1'>
        <Heading
          as='h2'
          fontFamily={DASHBOARD_MODAL_HEADING_FONT}
          fontSize={{ base: 'lg', md: 'xl' }}
          lineHeight='short'
          noOfLines={2}
        >
          {title}
        </Heading>
        {subtitle ? (
          <Text mt={1} fontSize='sm' color='dashboard.modal.subtleText'>
            {subtitle}
          </Text>
        ) : null}
        {statusBadges ? (
          <Flex mt={3} gap={2} align='center' flexWrap='wrap'>
            {statusBadges}
          </Flex>
        ) : null}
      </Box>

      {badgeLabel ? (
        <Badge
          colorScheme={badgeColorScheme}
          variant='subtle'
          fontSize='2xs'
          letterSpacing='0.08em'
          px={2.5}
          py={1.5}
          textTransform='uppercase'
          flexShrink={0}
          position={{ base: 'absolute', md: 'static' }}
          top={{ base: 0, md: 'auto' }}
          right={{ base: 10, md: 'auto' }}
        >
          {String(badgeLabel).toUpperCase()}
        </Badge>
      ) : null}
    </Flex>
  );
}

export function DashboardDetailsSummary({ items = [] }) {
  const visibleItems = items.filter(item => hasDisplayValue(item?.value));
  if (visibleItems.length === 0) return null;
  const lastTabletRowStart = Math.floor((visibleItems.length - 1) / 2) * 2;

  return (
    <Box
      as='section'
      aria-label='Important summary'
      w={{ base: '100%', lg: 'fit-content' }}
      maxW='100%'
      border='1px solid'
      borderColor='dashboard.modal.border'
      borderRadius='10px'
      overflow='hidden'
      bg='dashboard.modal.fieldBg'
      mb={5}
    >
      <Grid
        templateColumns={{
          base: 'minmax(0, 1fr)',
          sm: 'repeat(2, minmax(0, 1fr))',
          lg: `repeat(${visibleItems.length}, minmax(150px, max-content))`,
        }}
      >
        {visibleItems.map((item, index) => (
          <Box
            key={item.label}
            px={{ base: 3, md: 4 }}
            py={3}
            minW={{ lg: '170px' }}
            maxW={{ lg: '230px' }}
            borderRightWidth={{
              base: 0,
              sm:
                index % 2 === 0 && index < visibleItems.length - 1 ? '1px' : 0,
              lg: index < visibleItems.length - 1 ? '1px' : 0,
            }}
            borderBottomWidth={{
              base: index < visibleItems.length - 1 ? '1px' : 0,
              sm: index < lastTabletRowStart ? '1px' : 0,
              lg: 0,
            }}
            borderStyle='solid'
            borderColor='dashboard.modal.border'
          >
            <Text
              fontSize='2xs'
              fontWeight='bold'
              color='dashboard.modal.muted'
              textTransform='uppercase'
              letterSpacing='0.08em'
            >
              {item.label}
            </Text>
            <Text
              mt={1}
              fontSize='sm'
              fontWeight='semibold'
              color={item.accent || 'dashboard.modal.text'}
              overflowWrap='anywhere'
            >
              {item.value}
            </Text>
            {item.help ? (
              <Text mt={0.5} fontSize='xs' color='dashboard.modal.muted'>
                {item.help}
              </Text>
            ) : null}
          </Box>
        ))}
      </Grid>
    </Box>
  );
}

export function DashboardDetailsModalFooter({
  footerProps,
  tokens,
  isViewer,
  isEditing,
  saveError,
  saving,
  onBeginEdit,
  onCancelEdit,
  onClose,
  onSave,
  outlineButtonProps,
  primaryButtonProps,
  message,
}) {
  return (
    <ModalFooter {...footerProps} py={{ base: 2, md: 3 }}>
      <Flex
        w='100%'
        align={{ base: 'stretch', md: 'center' }}
        justify='space-between'
        gap={{ base: 2, md: 3 }}
        direction={{ base: 'column', md: 'row' }}
      >
        <Text
          fontSize='sm'
          fontWeight={saveError ? 'semibold' : 'normal'}
          color={saveError ? tokens.danger : tokens.muted}
        >
          {saveError ||
            message ||
            (isViewer
              ? 'You have read-only access to this asset.'
              : isEditing
                ? 'Review your changes before saving.'
                : 'Asset details are read-only until edit mode is enabled.')}
        </Text>

        <Flex
          gap={3}
          justify='flex-end'
          direction={{ base: 'column', sm: 'row' }}
          flexShrink={0}
        >
          {!isViewer ? (
            <Button
              {...outlineButtonProps}
              onClick={isEditing ? onCancelEdit : onBeginEdit}
              minW={{ base: '100%', sm: '88px' }}
            >
              {isEditing ? 'Cancel edit' : 'Edit'}
            </Button>
          ) : null}
          <Button
            {...primaryButtonProps}
            onClick={onClose}
            minW={{ base: '100%', sm: '88px' }}
          >
            Close
          </Button>
          {!isViewer && isEditing ? (
            <Button
              {...primaryButtonProps}
              colorScheme='green'
              onClick={onSave}
              isLoading={saving}
              minW={{ base: '100%', sm: '88px' }}
            >
              Save
            </Button>
          ) : null}
        </Flex>
      </Flex>
    </ModalFooter>
  );
}

export function DashboardModalSectionHeading({
  children,
  tokens,
  withDivider = true,
}) {
  return (
    <GridItem gridColumn='1 / -1' minW={0}>
      <Box
        borderTop={withDivider ? '1px solid' : '0'}
        borderColor={tokens.border}
        pt={withDivider ? 4 : 0}
        mt={withDivider ? 4 : 0}
        mb={2}
      >
        <Heading
          as='h3'
          fontFamily={DASHBOARD_MODAL_HEADING_FONT}
          fontSize='sm'
          fontWeight='bold'
          letterSpacing='0.01em'
          color={tokens.text}
        >
          {children}
        </Heading>
      </Box>
    </GridItem>
  );
}

export function DashboardModalDetailRow({
  label,
  children,
  value,
  tokens,
  labelWidth = '170px',
  tooltip,
  htmlFor,
  mono = false,
}) {
  const inDataSection = useContext(DashboardModalDataSectionContext);
  const content = children ?? value ?? '--';
  const row = (
    <Grid
      data-dashboard-detail-row
      templateColumns={{
        base: 'minmax(0, 1fr)',
        sm: `${labelWidth} minmax(0, 1fr)`,
      }}
      gap={{ base: 1, sm: inDataSection ? 2 : 4 }}
      alignItems={inDataSection ? 'center' : 'start'}
      py={inDataSection ? 1.75 : 2.25}
      borderBottom={inDataSection ? 0 : '1px solid'}
      borderColor={tokens.border}
      minW={0}
    >
      <Text
        as={htmlFor ? 'label' : 'p'}
        htmlFor={htmlFor}
        fontSize='xs'
        fontWeight='semibold'
        color={tokens.muted}
        pt={children ? 1 : 0}
      >
        {label}
        {inDataSection ? ' :' : ''}
      </Text>
      {typeof content === 'string' || typeof content === 'number' ? (
        <Text
          fontSize='sm'
          color={tokens.text}
          fontFamily={mono ? 'mono' : undefined}
          lineHeight='1.45'
          overflowWrap='anywhere'
          whiteSpace='pre-wrap'
          minW={0}
        >
          {content}
        </Text>
      ) : (
        <Box minW={0} color={tokens.text}>
          {content}
        </Box>
      )}
    </Grid>
  );

  return (
    <GridItem
      data-dashboard-detail-item
      gridColumn={inDataSection ? 'auto' : '1 / -1'}
      minW={0}
    >
      {tooltip ? (
        <Tooltip label={tooltip} hasArrow placement='top'>
          <Box>{row}</Box>
        </Tooltip>
      ) : (
        row
      )}
    </GridItem>
  );
}

export function DashboardModalDataSection({
  title,
  children,
  tokens,
  icon: SectionIcon,
}) {
  return (
    <GridItem gridColumn='1 / -1' minW={0}>
      <Box
        as='section'
        data-dashboard-data-section
        mb={6}
        minW={0}
        border='1px solid'
        borderColor={tokens.border}
        borderRadius='8px'
        overflow='hidden'
      >
        <Box
          mx={3}
          pt={2.5}
          pb={2}
          borderBottom='1px solid'
          borderColor={tokens.border}
        >
          <Flex align='center' gap={2}>
            {SectionIcon ? (
              <Icon
                as={SectionIcon}
                boxSize={4}
                flexShrink={0}
                color={tokens.muted}
                aria-hidden='true'
              />
            ) : null}
            <Heading
              as='h3'
              fontFamily={DASHBOARD_MODAL_HEADING_FONT}
              fontSize='sm'
              fontWeight='bold'
              letterSpacing='0.01em'
              color={tokens.text}
            >
              {title}
            </Heading>
          </Flex>
        </Box>
        <DashboardModalDataSectionContext.Provider value>
          <Grid
            templateColumns='minmax(0, 1fr)'
            position='relative'
            mx={3}
            minW={0}
            _before={{
              content: '""',
              display: { base: 'none', md: 'block' },
              position: 'absolute',
              top: 2,
              bottom: 2,
              left: '50%',
              width: '1px',
              bg: tokens.border,
              pointerEvents: 'none',
            }}
            sx={{
              '@media screen and (min-width: 48em)': {
                gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
                '& > [data-dashboard-detail-item]:nth-of-type(odd)': {
                  paddingRight: '16px',
                },
                '& > [data-dashboard-detail-item]:nth-of-type(even)': {
                  paddingLeft: '16px',
                },
              },
            }}
          >
            {children}
          </Grid>
        </DashboardModalDataSectionContext.Provider>
      </Box>
    </GridItem>
  );
}

export function DashboardModalDetailsGrid({ children }) {
  return (
    <Grid templateColumns='minmax(0, 1fr)' gap={0} minW={0}>
      {children}
    </Grid>
  );
}
