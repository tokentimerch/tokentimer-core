import { useState } from 'react';
import {
  Box,
  Code,
  HStack,
  IconButton,
  Text,
  Tooltip,
  VStack,
} from '@chakra-ui/react';
import { FiCheck, FiCopy } from 'react-icons/fi';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { SENSITIVE_PATTERN } from './certopsConfig.js';

/**
 * Error and warning lines. The theme gives every Text a fixed light-mode
 * colour that beats a plain color prop, so these set the colour through the
 * light-mode override as well and read right in both themes.
 */
export function ErrorText({ children, ...props }) {
  const { dashboard } = useDashboardTheme();
  const color = dashboard.state.danger;
  return (
    <Text fontSize='xs' color={color} _light={{ color }} {...props}>
      {children}
    </Text>
  );
}

export function WarnText({ children, ...props }) {
  const { dashboard } = useDashboardTheme();
  const color = dashboard.state.warning;
  return (
    <Text fontSize='xs' color={color} _light={{ color }} {...props}>
      {children}
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
}) {
  const { border, muted } = useDashboardTheme();
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
      <Box
        position='relative'
        border='1px solid'
        borderColor={border}
        borderRadius='md'
        p={3}
        pr={10}
        overflowX='auto'
      >
        <Code
          as='pre'
          display='block'
          bg='transparent'
          fontSize='xs'
          whiteSpace='pre'
          data-language={language}
        >
          {text}
        </Code>
        <Tooltip label={copied ? 'Copied' : 'Copy'}>
          <IconButton
            aria-label={`Copy ${label || 'text'}`}
            size='xs'
            variant='outline'
            position='absolute'
            top={1}
            right={1}
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
