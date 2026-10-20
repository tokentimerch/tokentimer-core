import {
  Alert,
  AlertDescription,
  AlertIcon,
  Box,
  HStack,
  useColorModeValue,
} from '@chakra-ui/react';
import { DashboardActionButton } from '../DashboardPrimitives';
import PrimaryButton from './PrimaryButton.jsx';

// This banner has to be noticed, so it is opaque and clearly outlined in both
// modes. The shared callout tokens are tuned for quiet in-modal alerts: their
// light surface is nearly white and their dark one translucent.
const AMBER = {
  light: {
    bg: '#fef3c7',
    border: '#fcd34d',
    accent: '#d97706',
    text: '#78350f',
  },
  dark: {
    bg: '#422006',
    border: '#92400e',
    accent: '#f59e0b',
    text: '#fde68a',
  },
};

/**
 * A slim warning that points to the setup guide. The banner spans the page
 * column so it lines up with the cards, but its content stays together on the
 * left: stretching the text would push the buttons to the far edge of a wide
 * screen, away from the message they belong to. On narrow screens the actions
 * wrap under the text.
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
  const bg = useColorModeValue(AMBER.light.bg, AMBER.dark.bg);
  const border = useColorModeValue(AMBER.light.border, AMBER.dark.border);
  const accent = useColorModeValue(AMBER.light.accent, AMBER.dark.accent);
  const text = useColorModeValue(AMBER.light.text, AMBER.dark.text);
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
        bg={bg}
        borderWidth='1px'
        borderLeftWidth='4px'
        borderColor={border}
        borderLeftColor={accent}
        color={text}
      >
        <AlertIcon color={accent} />
        <AlertDescription fontSize='sm' flex='0 1 auto' maxW='60ch'>
          <Box as='span' fontWeight='semibold'>
            {title}
          </Box>{' '}
          {message}
        </AlertDescription>
        <HStack spacing={2} flexShrink={0} ml={{ base: 0, md: 2 }}>
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
