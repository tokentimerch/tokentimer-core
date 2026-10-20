import {
  Alert,
  AlertDescription,
  AlertIcon,
  Box,
  HStack,
  useColorModeValue,
} from '@chakra-ui/react';
import { FiArrowRight } from 'react-icons/fi';
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
    // The quiet button needs a border that clears 3:1 on the amber surface.
    outline: '#b45309',
    outlineHover: 'rgba(180, 83, 9, 0.12)',
  },
  dark: {
    bg: '#422006',
    border: '#92400e',
    accent: '#f59e0b',
    text: '#fde68a',
    outline: '#f59e0b',
    outlineHover: 'rgba(245, 158, 11, 0.16)',
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
  const outline = useColorModeValue(AMBER.light.outline, AMBER.dark.outline);
  const outlineHover = useColorModeValue(
    AMBER.light.outlineHover,
    AMBER.dark.outlineHover
  );
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
          <PrimaryButton
            onClick={onAction}
            rightIcon={<FiArrowRight />}
            boxShadow='0 1px 2px rgba(0, 0, 0, 0.25)'
            _hover={{
              bg: 'blue.700',
              boxShadow: '0 4px 10px rgba(29, 78, 216, 0.35)',
              transform: 'translateY(-1px)',
            }}
            _active={{ bg: 'blue.800', transform: 'none' }}
            transition='background-color 0.15s, box-shadow 0.15s, transform 0.15s'
          >
            {actionLabel}
          </PrimaryButton>
          {onHide ? (
            <DashboardActionButton
              variant='outline'
              onClick={onHide}
              color={text}
              borderWidth='1px'
              borderColor={outline}
              bg='transparent'
              _hover={{ bg: outlineHover, borderColor: outline }}
              _active={{ bg: outlineHover }}
            >
              {hideLabel}
            </DashboardActionButton>
          ) : null}
        </HStack>
      </Alert>
    </Box>
  );
}
