import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
  Box,
  HStack,
  Icon,
  Link,
  Text,
  VStack,
} from '@chakra-ui/react';
import { FiBookOpen, FiExternalLink } from 'react-icons/fi';
import { DashboardPanel, DashboardPanelHeader } from '../DashboardPrimitives';
import { useDashboardThemeColors } from '../../hooks/useDashboardTheme';

export const STEP_KINDS = ['ui', 'runbook', 'handoff', 'verify', 'info'];

export function assertStepKind(kind) {
  if (!STEP_KINDS.includes(kind)) {
    throw new Error(`Unknown onboarding step kind: ${kind}`);
  }
  return kind;
}

const KIND_BADGE = {
  ui: { label: 'Guided in the dashboard', colorScheme: 'blue' },
  runbook: { label: 'Needs a command on your server', colorScheme: 'orange' },
  handoff: { label: 'Needs an administrator', colorScheme: 'purple' },
  verify: { label: 'Live check', colorScheme: 'green' },
  info: { label: 'Reference', colorScheme: 'gray' },
};

/**
 * A documentation link as a small bordered chip, in the same family as the
 * guide cards on Alert Preferences: it looks clickable, shows that it leaves
 * the app, and has a hover and focus state.
 */
export function DocsLink({ href, children }) {
  const { dashboard } = useDashboardThemeColors();
  const color = dashboard.accent.interactiveForeground;
  return (
    <Link
      href={href}
      isExternal
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

/**
 * One wizard step. The kind decides how the step is framed; the body is the
 * reused form, runbook text or status the caller passes as children. Docs
 * links come from the edition-aware resolver so a missing page is hidden
 * rather than rendered as a dead link.
 */
export default function StepFrame({
  kind,
  title,
  description,
  docs = [],
  blockers = [],
  actions,
  children,
}) {
  const { muted } = useDashboardThemeColors();
  assertStepKind(kind);
  const badge = KIND_BADGE[kind];
  const links = docs.filter(link => link && link.url);

  return (
    <DashboardPanel as='section' aria-label={title}>
      <DashboardPanelHeader
        title={title}
        description={description}
        action={
          <Badge colorScheme={badge.colorScheme} data-testid='step-kind'>
            {badge.label}
          </Badge>
        }
      />
      <VStack align='stretch' spacing={3}>
        {blockers.map(blocker => (
          <Alert
            key={blocker.code}
            status={kind === 'handoff' ? 'info' : 'warning'}
            borderRadius='md'
            variant='left-accent'
          >
            <AlertIcon />
            <AlertDescription fontSize='sm'>
              {blocker.remediation}
            </AlertDescription>
          </Alert>
        ))}
        <Box>{children}</Box>
        {links.length > 0 ? (
          <HStack spacing={2} flexWrap='wrap' pt={2} align='center'>
            <HStack spacing={1.5} color={muted}>
              <Icon as={FiBookOpen} boxSize={3.5} aria-hidden='true' />
              <Text fontSize='xs' fontWeight='semibold'>
                Learn more
              </Text>
            </HStack>
            {links.map(link => (
              <DocsLink key={link.url} href={link.url}>
                {link.label}
              </DocsLink>
            ))}
          </HStack>
        ) : null}
        {actions ? <HStack justify='flex-end'>{actions}</HStack> : null}
      </VStack>
    </DashboardPanel>
  );
}
