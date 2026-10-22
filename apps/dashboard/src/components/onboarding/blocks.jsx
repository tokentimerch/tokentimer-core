import { useState } from 'react';
import {
  Box,
  Code,
  HStack,
  IconButton,
  Text,
  Tooltip,
  VStack,
  useColorModeValue,
} from '@chakra-ui/react';
import { FiCheck, FiCopy } from 'react-icons/fi';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { dashboardThemeColors } from '../../styles/theme.js';
import { SENSITIVE_PATTERN } from './certopsConfig.js';

// Same palette as the agent output panel, so commands and logs look alike.
const SHELL_BG = '#0f172a';
const SHELL_BORDER = 'rgba(148, 163, 184, 0.28)';
const SHELL_TEXT = '#e2e8f0';
const SHELL_PROMPT = '#4ade80';

/**
 * Error and warning lines. The theme gives every Text a fixed light-mode
 * colour that beats a plain color prop, so these set the colour through the
 * light-mode override as well and read right in both themes.
 */
export function ErrorText({ children, ...props }) {
  const { danger } = dashboardThemeColors.state;
  const color = useColorModeValue(danger.light, danger.dark);
  return (
    <Text fontSize='xs' color={color} _light={{ color }} {...props}>
      {children}
    </Text>
  );
}

export function WarnText({ children, ...props }) {
  const { warning } = dashboardThemeColors.state;
  const color = useColorModeValue(warning.light, warning.dark);
  return (
    <Text fontSize='xs' color={color} _light={{ color }} {...props}>
      {children}
    </Text>
  );
}

/** One line under a disabled main button saying what is missing. */
export function ContinueHint({ children, ...props }) {
  const { muted } = useDashboardTheme();
  return (
    <Text
      fontSize='xs'
      color={muted}
      w='100%'
      textAlign='right'
      data-testid='continue-hint'
      {...props}
    >
      To continue: {children}
    </Text>
  );
}

/**
 * A command or config the operator copies and runs on their host. By default
 * it refuses to render anything that looks like a credential so a bug upstream
 * can never put a secret on screen or in the clipboard. Only the one-time
 * token display opts in, and it is rendered from component state that is never
 * written to the session.
 */
export function CopyBlock({
  label,
  text,
  language = 'text',
  allowSecret = false,
  prompt = false,
}) {
  const { muted } = useDashboardTheme();
  const [copied, setCopied] = useState(false);
  if (!allowSecret && SENSITIVE_PATTERN.test(String(text))) {
    return (
      <ErrorText fontSize='sm' data-testid='copy-refused'>
        {label ? `${label}: ` : ''}this content contained something that looks
        like a credential, so it is not shown. Remove any token or key you
        pasted into a field above, and this block comes back.
      </ErrorText>
    );
  }
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch (_) {
      setCopied(false);
    }
  };
  return (
    <VStack align='stretch' spacing={1}>
      {label ? (
        <Text fontSize='xs' color={muted} fontWeight='semibold'>
          {label}
        </Text>
      ) : null}
      {/* Always-dark shell panel so a command reads the same in both themes. */}
      <Box
        position='relative'
        bg={SHELL_BG}
        borderWidth='1px'
        borderColor={SHELL_BORDER}
        borderRadius='md'
        p={3}
        pr={10}
        overflowX='auto'
        tabIndex={0}
        role='group'
        aria-label={label ? `${label} (command)` : 'Command'}
        _focusVisible={{ boxShadow: 'outline', outline: 'none' }}
      >
        <Code
          as='pre'
          display='block'
          bg='transparent'
          fontSize='xs'
          whiteSpace='pre'
          data-language={language}
          sx={{ color: `${SHELL_TEXT} !important` }}
        >
          {prompt ? (
            <Box
              as='span'
              aria-hidden
              userSelect='none'
              sx={{ color: `${SHELL_PROMPT} !important` }}
            >
              ${' '}
            </Box>
          ) : null}
          {text}
        </Code>
        <Tooltip label={copied ? 'Copied' : 'Copy'}>
          <IconButton
            aria-label={`Copy ${label || 'text'}`}
            size='xs'
            variant='ghost'
            position='absolute'
            top={1}
            right={1}
            color={SHELL_TEXT}
            _hover={{ bg: 'whiteAlpha.200' }}
            icon={copied ? <FiCheck /> : <FiCopy />}
            onClick={copy}
          />
        </Tooltip>
      </Box>
    </VStack>
  );
}

/** A checklist the operator ticks off; progress is kept in the session. */
export function Checklist({ items, checked = [], onToggle }) {
  const { muted } = useDashboardTheme();
  return (
    <VStack align='stretch' spacing={2}>
      {items.map(item => (
        <HStack key={item.id} align='start' spacing={2}>
          <input
            type='checkbox'
            id={`check-${item.id}`}
            checked={checked.includes(item.id)}
            onChange={() => onToggle(item.id)}
            style={{ marginTop: 4 }}
          />
          <label htmlFor={`check-${item.id}`}>
            <Text fontSize='sm'>{item.label}</Text>
            {item.hint ? (
              <Text fontSize='xs' color={muted}>
                {item.hint}
              </Text>
            ) : null}
          </label>
        </HStack>
      ))}
    </VStack>
  );
}
