import {
  Alert,
  AlertDescription,
  AlertIcon,
  Box,
  HStack,
  Text,
} from '@chakra-ui/react';
import { DashboardActionButton } from '../DashboardPrimitives';
import { useDashboardThemeColors } from '../../hooks/useDashboardTheme';
import PrimaryButton from './PrimaryButton.jsx';

/**
 * A slim warning that points to the setup guide. It uses the same callout
 * tokens as the paused-operations warning, so it reads as part of the product
 * and not as a stock alert, and it wraps on narrow screens instead of
 * squeezing the buttons.
 */
export default function SetupBanner({
  title,
  message,
  actionLabel,
  onAction,
  onHide,
  hideLabel = 'Hide',
  testId = 'setup-banner',
}) {
  const { dashboard } = useDashboardThemeColors();
  return (
    <Box mb={4} data-testid={testId}>
      <Alert
        status='warning'
        variant='left-accent'
        borderRadius='md'
        flexWrap='wrap'
        columnGap={3}
        rowGap={2}
        alignItems='center'
        bg={dashboard.callout.warningSurface}
        borderColor={dashboard.callout.warningBorder}
        color={dashboard.callout.warningText}
      >
        <AlertIcon />
        <AlertDescription fontSize='sm' flex='1 1 260px'>
          <Text as='span' fontWeight='semibold'>
            {title}
          </Text>{' '}
          {message}
        </AlertDescription>
        <HStack spacing={2} flexShrink={0}>
          <PrimaryButton size='sm' onClick={onAction}>
            {actionLabel}
          </PrimaryButton>
          {onHide ? (
            <DashboardActionButton variant='ghost' size='sm' onClick={onHide}>
              {hideLabel}
            </DashboardActionButton>
          ) : null}
        </HStack>
      </Alert>
    </Box>
  );
}
