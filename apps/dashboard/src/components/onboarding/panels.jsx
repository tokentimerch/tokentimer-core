import {
  Alert,
  AlertDescription,
  AlertIcon,
  AlertTitle,
  Badge,
  Box,
  Flex,
  HStack,
  Icon,
  Text,
  VisuallyHidden,
  VStack,
} from '@chakra-ui/react';
import { FiCheck, FiChevronRight } from 'react-icons/fi';
import {
  useDashboardTheme,
  useDashboardThemeColors,
} from '../../hooks/useDashboardTheme';
import { DocsLink, resolveDocLinks } from '../LearnMorePanel';

// Small presentational pieces shared by the setup steps. They only draw what
// the step already knows: no data is read or written here.

const PANEL_ROLE = {
  info: 'status',
  success: 'status',
  warning: 'note',
  error: 'alert',
};

/**
 * Info, warning, success or error panel: one icon, an optional title, the
 * body and optional docs links. Uses the theme's Alert variants so contrast
 * holds in both color modes.
 */
export function StatusPanel({
  status = 'info',
  title,
  children,
  links,
  testId,
  ...rest
}) {
  const resolved = resolveDocLinks(links);
  return (
    <Alert
      status={status}
      variant={status}
      borderRadius='md'
      alignItems='flex-start'
      borderWidth='1px'
      role={PANEL_ROLE[status] || 'status'}
      data-testid={testId}
      {...rest}
    >
      <AlertIcon mt='3px' />
      <Box flex='1' minW={0}>
        {title ? (
          <AlertTitle fontSize='sm' lineHeight='1.4' mb={children ? 1 : 0}>
            {title}
          </AlertTitle>
        ) : null}
        {children ? (
          <AlertDescription
            fontSize='sm'
            display='block'
            overflowWrap='anywhere'
          >
            {children}
          </AlertDescription>
        ) : null}
        {resolved.length > 0 ? (
          <Flex wrap='wrap' gap={2} mt={2}>
            {resolved.map(link => (
              <DocsLink key={link.url} href={link.url}>
                {link.label}
              </DocsLink>
            ))}
          </Flex>
        ) : null}
      </Box>
    </Alert>
  );
}

const TONE_SCHEME = {
  green: 'green',
  success: 'green',
  orange: 'orange',
  warning: 'orange',
  red: 'red',
  danger: 'red',
  blue: 'blue',
  info: 'blue',
  gray: 'gray',
  neutral: 'gray',
};

/** Compact status label: tone decides the color, the text says the state. */
export function StatusTag({ tone = 'gray', children, ...rest }) {
  return (
    <Badge colorScheme={TONE_SCHEME[tone] || 'gray'} {...rest}>
      {children}
    </Badge>
  );
}

/**
 * A step inside a step: a number, a title, one line of description and a
 * status. `status` is 'done', 'todo', 'blocked' or omitted for a plain card.
 */
export function StepCard({
  n,
  title,
  description,
  status,
  who,
  children,
  testId,
}) {
  const { border, muted } = useDashboardTheme();
  const { dashboard } = useDashboardThemeColors();
  const done = status === 'done';
  const blocked = status === 'blocked';
  const ring = done
    ? dashboard.state.success
    : blocked
      ? dashboard.state.warning
      : border;
  return (
    <Box
      as='section'
      aria-label={n ? `${n}. ${title}` : title}
      data-testid={testId}
      data-status={status}
      borderWidth='1px'
      borderColor={border}
      borderRadius='md'
      p={{ base: 3, md: 4 }}
    >
      <Flex gap={3} align='flex-start'>
        {n ? (
          <Flex
            aria-hidden
            flexShrink={0}
            w='26px'
            h='26px'
            borderRadius='full'
            borderWidth='2px'
            borderColor={ring}
            align='center'
            justify='center'
            fontSize='xs'
            fontWeight='bold'
            color={done ? dashboard.state.success : muted}
            _light={{ color: done ? dashboard.state.success : muted }}
          >
            {done ? <Icon as={FiCheck} boxSize={3.5} /> : n}
          </Flex>
        ) : null}
        <VStack align='stretch' spacing={3} flex='1' minW={0}>
          <Box>
            <HStack spacing={2} flexWrap='wrap' align='center'>
              <Text as='h3' fontSize='sm' fontWeight='semibold'>
                {n ? <VisuallyHidden>{n}. </VisuallyHidden> : null}
                {title}
              </Text>
              {status === 'done' ? (
                <StatusTag tone='green'>Done</StatusTag>
              ) : status === 'blocked' ? (
                <StatusTag tone='orange'>Needs attention</StatusTag>
              ) : null}
              {who ? <StatusTag>{who}</StatusTag> : null}
            </HStack>
            {description ? (
              <Text fontSize='xs' color={muted} mt={0.5}>
                {description}
              </Text>
            ) : null}
          </Box>
          {children}
        </VStack>
      </Flex>
    </Box>
  );
}

/**
 * Key facts as a definition list: paths, ports, serials, names. Values can
 * be plain text or nodes; `mono` renders them as code.
 */
export function FactsList({ items, testId, ...rest }) {
  const { muted, border } = useDashboardTheme();
  const rows = (items || []).filter(
    item => item && item.value !== undefined && item.value !== null
  );
  if (rows.length === 0) return null;
  return (
    <Box
      as='dl'
      data-testid={testId}
      borderWidth='1px'
      borderColor={border}
      borderRadius='md'
      px={3}
      py={1}
      {...rest}
    >
      {rows.map((item, index) => (
        <Flex
          key={item.label}
          direction={{ base: 'column', md: 'row' }}
          gap={{ base: 0, md: 3 }}
          py={1.5}
          borderTopWidth={index === 0 ? 0 : '1px'}
          borderColor={border}
        >
          <Box
            as='dt'
            flex={{ md: '0 0 30%' }}
            fontSize='xs'
            fontWeight='semibold'
            color={muted}
            _light={{ color: muted }}
          >
            {item.label}
          </Box>
          <Box
            as='dd'
            flex='1'
            minW={0}
            fontSize='sm'
            overflowWrap='anywhere'
            fontFamily={item.mono ? 'mono' : undefined}
          >
            {item.value}
          </Box>
        </Flex>
      ))}
    </Box>
  );
}

const CALLOUT_KINDS = {
  before: { label: 'Before you start', accent: 'orange.400' },
  next: { label: 'What happens next', accent: 'blue.400' },
  check: { label: 'How to check', accent: 'green.500' },
};

/**
 * Prerequisites, what happens next, or what to check. Items become a short
 * list so long paragraphs stay scannable.
 */
export function Callout({ kind = 'next', title, items, children, testId }) {
  const { muted, border } = useDashboardTheme();
  const { dashboard } = useDashboardThemeColors();
  const def = CALLOUT_KINDS[kind] || CALLOUT_KINDS.next;
  const list = (items || []).filter(Boolean);
  return (
    <Box
      as='section'
      aria-label={title || def.label}
      data-testid={testId}
      data-kind={kind}
      borderWidth='1px'
      borderColor={border}
      borderLeftWidth='3px'
      borderLeftColor={def.accent}
      borderRadius='md'
      bg={dashboard.bg.nested}
      px={3}
      py={2.5}
    >
      <Text
        as='h4'
        fontSize='xs'
        fontWeight='bold'
        letterSpacing='0.02em'
        color={muted}
        _light={{ color: muted }}
        mb={1}
      >
        {title || def.label}
      </Text>
      {children ? (
        <Box fontSize='sm' overflowWrap='anywhere'>
          {children}
        </Box>
      ) : null}
      {list.length > 0 ? (
        <Box
          as='ul'
          listStyleType='none'
          fontSize='sm'
          display='flex'
          flexDirection='column'
          gap={1}
        >
          {list.map(item => (
            <Flex as='li' key={String(item)} gap={1.5} align='flex-start'>
              <Icon
                as={FiChevronRight}
                boxSize={3.5}
                mt='3px'
                flexShrink={0}
                color={muted}
                aria-hidden
              />
              <Box minW={0} overflowWrap='anywhere'>
                {item}
              </Box>
            </Flex>
          ))}
        </Box>
      ) : null}
    </Box>
  );
}

/**
 * Detail most people do not need, folded away behind a keyboard-friendly
 * disclosure. Native details/summary keeps focus and Enter/Space handling.
 */
export function DetailsSection({
  summary,
  children,
  defaultOpen = false,
  testId,
}) {
  const { border, muted } = useDashboardTheme();
  return (
    <Box
      as='details'
      open={defaultOpen || undefined}
      data-testid={testId}
      borderWidth='1px'
      borderColor={border}
      borderRadius='md'
      px={3}
      py={2}
    >
      <Text
        as='summary'
        fontSize='sm'
        fontWeight='semibold'
        cursor='pointer'
        color={muted}
        _light={{ color: muted }}
        borderRadius='sm'
        _focusVisible={{ boxShadow: 'outline', outline: 'none' }}
      >
        {summary}
      </Text>
      <VStack align='stretch' spacing={3} mt={3}>
        {children}
      </VStack>
    </Box>
  );
}
