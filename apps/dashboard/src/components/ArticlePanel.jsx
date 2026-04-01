import { Box, useColorMode, useColorModeValue } from '@chakra-ui/react';
import useArticleColors from './useArticleColors';

export default function ArticlePanel({ children, maxW }) {
  const { sectionBg, borderColor } = useArticleColors();
  const { colorMode } = useColorMode();
  const boxShadow = useColorModeValue('md', 'sm');
  const borderWidth = useColorModeValue('1px', '1px');

  return (
    <Box
      key={colorMode}
      maxW={maxW || { base: 'full', md: '3xl', lg: '4xl' }}
      mx='auto'
      bg={sectionBg}
      border={borderWidth}
      borderColor={borderColor}
      borderRadius='lg'
      p={{ base: 5, md: 8, lg: 10 }}
      boxShadow={boxShadow}
      style={{ backdropFilter: 'saturate(120%) blur(4px)' }}
      overflowX='hidden'
      w='full'
    >
      {children}
    </Box>
  );
}
