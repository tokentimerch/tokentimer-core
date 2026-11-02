import {
  Alert,
  AlertIcon,
  Box,
  Flex,
  Icon,
  Link,
  Text,
} from '@chakra-ui/react';
import { FiExternalLink } from 'react-icons/fi';
import { useDashboardThemeColors } from '../hooks/useDashboardTheme';

/** Shared look of the small info panels across the dashboard. */
export const INFO_NOTE_PROPS = {
  status: 'info',
  size: 'sm',
  borderRadius: 'md',
};

/**
 * A documentation link as a small bordered chip: it looks clickable, shows
 * that it leaves the app, and has a hover and focus state.
 */
export function DocsLink({ href, children }) {
  const { dashboard } = useDashboardThemeColors();
  const color = dashboard.accent.interactiveForeground;

  return (
    <Link
      href={href}
      isExternal
      rel='noopener noreferrer'
      display='inline-flex'
      alignItems='center'
      gap={1.5}
      px={2.5}
      py={1}
      fontSize='xs'
      fontWeight='semibold'
      color={color}
      bg={dashboard.accent.interactiveSurface}
      borderWidth='1px'
      borderColor={dashboard.border.subtle}
      borderRadius='md'
      transition='border-color 0.15s, background-color 0.15s'
      _hover={{ textDecoration: 'none', borderColor: color }}
      _focusVisible={{ boxShadow: 'outline', textDecoration: 'none' }}
    >
      {children}
      <Icon as={FiExternalLink} boxSize={3} aria-hidden='true' />
    </Link>
  );
}

/** Keep links that resolve to a URL and drop repeated URLs. */
export function resolveDocLinks(links) {
  const seen = new Set();
  const out = [];
  for (const link of Array.isArray(links) ? links : []) {
    const url = link && (link.url || link.href);
    if (!url || seen.has(url)) continue;
    seen.add(url);
    out.push({ label: link.label, url });
  }
  return out;
}

/**
 * "Learn more" info panel with docs link chips. Renders nothing when no link
 * resolves, so a missing page is hidden rather than shown as a dead link.
 * `compact` fits tight modals and forms: the title sits inline with the chips.
 */
export default function LearnMorePanel({
  links,
  title = 'Learn more',
  variant = 'default',
  ...boxProps
}) {
  const resolved = resolveDocLinks(links);
  if (resolved.length === 0) return null;
  const compact = variant === 'compact';

  const chips = resolved.map(link => (
    <DocsLink key={link.url} href={link.url}>
      {link.label}
    </DocsLink>
  ));

  return (
    <Alert
      {...INFO_NOTE_PROPS}
      role='note'
      aria-label={title}
      alignItems={compact ? 'center' : 'flex-start'}
      py={compact ? 1.5 : undefined}
      {...boxProps}
    >
      <AlertIcon mt={compact ? 0 : '2px'} boxSize={compact ? 4 : undefined} />
      {compact ? (
        <Flex flex='1' minW={0} wrap='wrap' align='center' gap={2}>
          <Text fontSize='xs' fontWeight='semibold' lineHeight='1.45'>
            {title}
          </Text>
          {chips}
        </Flex>
      ) : (
        <Box flex='1' minW={0}>
          <Text fontSize='xs' fontWeight='semibold' lineHeight='1.45'>
            {title}
          </Text>
          <Flex wrap='wrap' gap={2} mt={2}>
            {chips}
          </Flex>
        </Box>
      )}
    </Alert>
  );
}
