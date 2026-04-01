import React from 'react';
import { Box, IconButton, useColorModeValue } from '@chakra-ui/react';
import { FiCopy, FiCheck } from 'react-icons/fi';
import { showSuccess, showError } from '../utils/toast.js';

export default function CopyableCodeBlock({ code }) {
  const [copied, setCopied] = React.useState(false);
  const bg = useColorModeValue('gray.100', 'gray.900');
  const btnBg = useColorModeValue('blue.500', 'blue.400');
  const borderColor = useColorModeValue('gray.300', 'gray.700');
  const codeColor = useColorModeValue('gray.800', 'gray.100');

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      showSuccess('Copied to clipboard');
      setTimeout(() => setCopied(false), 1500);
    } catch (e) {
      showError('Copy failed', e.message || 'Unknown error');
    }
  };

  return (
    <Box position='relative'>
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
      <Box
        as='pre'
        p={{ base: 3, md: 4 }}
        pr={{ base: 10, md: 12 }}
        bg={bg}
        borderRadius='md'
        overflowX='hidden'
        whiteSpace='pre-wrap'
        border='1px solid'
        borderColor={borderColor}
        borderLeftWidth='4px'
        borderLeftColor={useColorModeValue('blue.200', 'blue.500')}
        fontFamily='mono'
        fontSize={{ base: 'sm', md: 'sm' }}
        lineHeight='1.5'
        color={codeColor}
        w='100%'
        maxW='100%'
        sx={{
          overflowWrap: 'anywhere',
          wordBreak: 'break-word',
          WebkitOverflowScrolling: 'touch',
        }}
      >
        {code}
      </Box>
    </Box>
  );
}
