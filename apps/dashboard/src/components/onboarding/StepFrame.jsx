import { Children } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
  Box,
  Divider,
  HStack,
  VStack,
} from '@chakra-ui/react';
import { DashboardPanel, DashboardPanelHeader } from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import LearnMorePanel, { DocsLink, INFO_NOTE_PROPS } from '../LearnMorePanel';

// Re-exported so existing imports keep working.
export { DocsLink, INFO_NOTE_PROPS };

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
  assertStepKind(kind);
  const badge = KIND_BADGE[kind];
  const { border } = useDashboardTheme();
  // A divider only helps when something sits below the header.
  const hasBody =
    Children.toArray(children).length > 0 || blockers.length > 0 || !!actions;

  return (
    <DashboardPanel as='section' aria-label={title}>
      <DashboardPanelHeader
        title={title}
        description={description}
        mb={hasBody ? 3 : 4}
        action={
          <Badge colorScheme={badge.colorScheme} data-testid='step-kind'>
            {badge.label}
          </Badge>
        }
      />
      {hasBody ? (
        // Chakra's Divider hardcodes a dark-mode color; _dark keeps the card's.
        <Divider
          data-testid='step-divider'
          borderColor={border}
          _dark={{ borderColor: border }}
          opacity={1}
          mb={3}
        />
      ) : null}
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
        <LearnMorePanel links={docs} />
        {actions ? (
          <HStack justify='flex-end' flexWrap='wrap'>
            {actions}
          </HStack>
        ) : null}
      </VStack>
    </DashboardPanel>
  );
}
