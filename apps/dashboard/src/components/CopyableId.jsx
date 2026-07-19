import React from 'react';
import { HStack, IconButton, Text, useColorModeValue } from '@chakra-ui/react';
import { FiCopy, FiCheck } from 'react-icons/fi';
import { showSuccess, showError } from '../utils/toast.js';

/**
 * Compact inline id chip: an optional label, a truncated monospace id, and a
 * copy-to-clipboard button that always copies the full untruncated value.
 * For multi-line secrets that need a bordered block, use CopyableCodeBlock
 * instead; this is for short ids inline in tables, badges, and timelines.
 *
 * @param {{ id: string, label?: string, display?: string, size?: 'xs'|'sm' }} props
 */
export default function CopyableId({ id, label, display, size = 'xs' }) {
  const [copied, setCopied] = React.useState(false);
  const value = String(id ?? '').trim();
  const shown = display ?? value;
  const labelColor = useColorModeValue('gray.500', 'gray.500');
  const idColor = useColorModeValue('gray.700', 'gray.300');

  if (!value) return null;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      showSuccess('Copied to clipboard');
      setTimeout(() => setCopied(false), 1500);
    } catch (e) {
      showError('Copy failed', e.message || 'Unknown error');
    }
  };

  return (
    <HStack spacing={1} display='inline-flex' align='center'>
      {label ? (
        <Text fontSize={size} color={labelColor} flexShrink={0}>
          {label}
        </Text>
      ) : null}
      <Text
        as='span'
        fontFamily='mono'
        fontSize={size}
        color={idColor}
        title={value}
      >
        {shown}
      </Text>
      <IconButton
        aria-label='Copy to clipboard'
        title='Copy to clipboard'
        icon={copied ? <FiCheck /> : <FiCopy />}
        onClick={handleCopy}
        size='xs'
        variant='ghost'
        minW='auto'
        h='auto'
        p={0.5}
        fontSize={size === 'sm' ? 'sm' : 'xs'}
      />
    </HStack>
  );
}
