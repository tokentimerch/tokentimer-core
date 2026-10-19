import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
  Box,
  HStack,
  Link,
  Text,
  VStack,
} from '@chakra-ui/react';
import { DashboardPanel, DashboardPanelHeader } from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';

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
  const { muted } = useDashboardTheme();
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
          <HStack spacing={4} flexWrap='wrap' pt={1}>
            <Text fontSize='xs' color={muted}>
              Learn more:
            </Text>
            {links.map(link => (
              <Link
                key={link.url}
                href={link.url}
                isExternal
                fontSize='xs'
                color='blue.400'
              >
                {link.label}
              </Link>
            ))}
          </HStack>
        ) : null}
        {actions ? <HStack justify='flex-end'>{actions}</HStack> : null}
      </VStack>
    </DashboardPanel>
  );
}
