import { IconButton, useColorMode, useColorModeValue } from '@chakra-ui/react';
import { FiSun, FiMoon } from 'react-icons/fi';

export default function ThemeToggle() {
  const { colorMode, toggleColorMode } = useColorMode();
  const isDark = colorMode === 'dark';
  const hoverBg = useColorModeValue('blue.50', 'blue.900');

  return (
    <IconButton
      aria-label={`Switch to ${isDark ? 'light' : 'dark'} mode`}
      icon={isDark ? <FiSun size={20} /> : <FiMoon size={20} />}
      onClick={toggleColorMode}
      variant='ghost'
      size='md'
      colorScheme='blue'
      bg='transparent'
      _hover={{
        bg: hoverBg,
      }}
    />
  );
}
