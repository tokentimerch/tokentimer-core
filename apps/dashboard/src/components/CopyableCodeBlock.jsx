import React from 'react';
import { Box, IconButton, Text, useColorModeValue } from '@chakra-ui/react';
import { FiCopy, FiCheck } from 'react-icons/fi';
import { showSuccess, showError } from '../utils/toast.js';

export default function CopyableCodeBlock({
  code,
  label,
  copyable = true,
  monospace = true,
}) {
  const [copied, setCopied] = React.useState(false);
  const trimmed = String(code ?? '').trim();
  const display = trimmed || '-';
  const canCopy = copyable && Boolean(trimmed);
  const bg = useColorModeValue('gray.100', 'gray.900');
  const btnBg = useColorModeValue('blue.500', 'blue.400');
  const borderColor = useColorModeValue('gray.300', 'gray.700');
  const codeColor = useColorModeValue('gray.800', 'gray.100');
  const labelColor = useColorModeValue('gray.600', 'gray.400');
  const emptyColor = useColorModeValue('gray.500', 'gray.500');

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(trimmed);
      setCopied(true);
      showSuccess('Copied to clipboard');
      setTimeout(() => setCopied(false), 1500);
    } catch (e) {
      showError('Copy failed', e.message || 'Unknown error');
    }
  };

  return (
    <Box w='100%'>
      {label ? (
        <Text
          fontSize='xs'
          fontWeight='semibold'
          color={labelColor}
          textTransform='uppercase'
          letterSpacing='0.04em'
          mb={1}
        >
          {label}
        </Text>
      ) : null}
      <Box position='relative'>
        {canCopy ? (
          <IconButton
            aria-label='Copy to clipboard'
            title='Copy to clipboard'
            icon={copied ? <FiCheck /> : <FiCopy />}
            onClick={handleCopy}
            size='sm'
            variant='solid'
            colorScheme='blue'
            bg={btnBg}
            opacity={0.5}
            _hover={{ bg: btnBg, opacity: 1 }}
            _focus={{ opacity: 1 }}
            transition='opacity 0.2s ease'
            color='white'
            borderRadius='md'
            position='absolute'
            top='2'
            right='2'
            zIndex='1'
          />
        ) : null}
        <Box
          as={monospace ? 'pre' : 'div'}
          p={{ base: 3, md: 4 }}
          pr={canCopy ? { base: 10, md: 12 } : { base: 3, md: 4 }}
          bg={bg}
          borderRadius='md'
          overflowX='hidden'
          whiteSpace='pre-wrap'
          border='1px solid'
          borderColor={borderColor}
          borderLeftWidth='4px'
          borderLeftColor={useColorModeValue('blue.200', 'blue.500')}
          fontFamily={monospace ? 'mono' : 'body'}
          fontSize={{ base: 'sm', md: 'sm' }}
          lineHeight='1.5'
          color={trimmed ? codeColor : emptyColor}
          w='100%'
          maxW='100%'
          sx={{
            overflowWrap: 'anywhere',
            wordBreak: 'break-word',
            WebkitOverflowScrolling: 'touch',
          }}
        >
          {display}
        </Box>
      </Box>
    </Box>
  );
}
