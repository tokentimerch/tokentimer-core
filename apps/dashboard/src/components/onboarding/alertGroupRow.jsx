import { FiCheck, FiMinus } from 'react-icons/fi';
import { useInRouterContext, Link as RouterLink } from 'react-router';
import {
  Badge,
  Box,
  HStack,
  Link,
  Spinner,
  Text,
  VStack,
} from '@chakra-ui/react';
import { DashboardActionButton } from '../DashboardPrimitives';
import {
  useDashboardTheme,
  useDashboardThemeColors,
} from '../../hooks/useDashboardTheme';

const ALERT_PREFERENCES = '/workspace-preferences';

/** In-app link when a router is present, a plain link otherwise. */
export function AlertPreferencesLink() {
  const routed = useInRouterContext();
  const { dashboard } = useDashboardThemeColors();
  return (
    <Link
      {...(routed
        ? { as: RouterLink, to: ALERT_PREFERENCES }
        : { href: ALERT_PREFERENCES })}
      color={dashboard.accent.interactiveForeground}
      textDecoration='underline'
    >
      Open Alert Preferences
    </Link>
  );
}

// A native checkbox cannot show the mixed state the same way in every
// browser, so this one is a plain role=checkbox with the keyboard handled.
function TickBox({ label, state, disabled, busy, onToggle }) {
  const { dashboard } = useDashboardThemeColors();
  const checked = state === 'all';
  const mixed = state === 'some';
  const on = checked || mixed;
  const toggle = () => {
    if (!disabled) onToggle(!checked);
  };
  return (
    <Box
      role='checkbox'
      aria-checked={checked ? 'true' : mixed ? 'mixed' : 'false'}
      aria-label={label}
      aria-disabled={disabled ? 'true' : undefined}
      aria-busy={busy ? 'true' : undefined}
      tabIndex={disabled ? -1 : 0}
      onClick={toggle}
      onKeyDown={event => {
        if (event.key === ' ') {
          event.preventDefault();
          toggle();
        }
      }}
      display='inline-flex'
      alignItems='center'
      justifyContent='center'
      flex='0 0 auto'
      w='22px'
      h='22px'
      mt='1px'
      borderWidth='2px'
      borderRadius='md'
      borderColor={
        on ? dashboard.accent.interactiveForeground : dashboard.border.control
      }
      bg={on ? dashboard.accent.interactiveForeground : dashboard.bg.field}
      color={dashboard.bg.panel}
      cursor={disabled ? 'not-allowed' : 'pointer'}
      opacity={disabled && !busy ? 0.55 : 1}
      _focusVisible={{
        outline: '2px solid',
        outlineColor: dashboard.accent.interactiveForeground,
        outlineOffset: '2px',
      }}
    >
      {busy ? (
        <Spinner size='xs' />
      ) : checked ? (
        <FiCheck size={14} strokeWidth={3} />
      ) : mixed ? (
        <FiMinus size={14} strokeWidth={3} />
      ) : null}
    </Box>
  );
}

/**
 * One contact group. When `tick` is given the row carries a checkbox and is
 * highlighted for the state it shows; otherwise it is a plain list row.
 */
export function GroupRow({
  group,
  who,
  isDefault,
  reachesAnyone,
  tick,
  deletePlan,
  onEdit,
  onDelete,
}) {
  const { muted } = useDashboardTheme();
  const { dashboard } = useDashboardThemeColors();
  const state = tick?.state || 'none';
  const whyId = `delete-why-${group.id}`;
  const all = state === 'all';
  const some = state === 'some';
  return (
    <VStack
      data-testid={`group-${group.id}`}
      data-selected={tick ? state : undefined}
      align='stretch'
      spacing={2}
      borderWidth='1px'
      borderStyle={some ? 'dashed' : 'solid'}
      borderColor={
        all
          ? dashboard.accent.interactiveForeground
          : some
            ? dashboard.accent.interactiveBorder
            : dashboard.border.subtle
      }
      bg={all || some ? dashboard.accent.interactiveSurface : undefined}
      borderRadius='md'
      p={3}
    >
      <HStack align='start' spacing={3}>
        {tick ? (
          <TickBox
            label={group.name}
            state={state}
            disabled={tick.disabled}
            busy={tick.busy}
            onToggle={tick.onToggle}
          />
        ) : null}
        <HStack
          flex='1'
          minW={0}
          justify='space-between'
          align='start'
          spacing={3}
          flexWrap='wrap'
        >
          <VStack align='start' spacing={0} minW={0}>
            <HStack flexWrap='wrap'>
              <Text fontSize='sm' fontWeight='semibold'>
                {group.name}
              </Text>
              {isDefault ? <Badge colorScheme='blue'>Default</Badge> : null}
              {!reachesAnyone ? (
                <Badge colorScheme='orange'>Reaches nobody</Badge>
              ) : null}
            </HStack>
            <Text fontSize='xs' color={muted}>
              {who.length ? who.join(', ') : 'No recipients'}
            </Text>
          </VStack>
          <HStack spacing={2} flexWrap='wrap'>
            <DashboardActionButton size='xs' variant='outline' onClick={onEdit}>
              Edit
            </DashboardActionButton>
            <DashboardActionButton
              size='xs'
              variant='outline'
              colorScheme='red'
              aria-label={`Delete ${group.name}`}
              aria-describedby={deletePlan.allowed ? undefined : whyId}
              isDisabled={!deletePlan.allowed}
              onClick={onDelete}
            >
              Delete
            </DashboardActionButton>
          </HStack>
        </HStack>
      </HStack>
      {!deletePlan.allowed ? (
        <Text id={whyId} fontSize='xs' color={muted}>
          {`You cannot delete this group yet. ${deletePlan.reason} `}
          <AlertPreferencesLink />
        </Text>
      ) : null}
    </VStack>
  );
}
