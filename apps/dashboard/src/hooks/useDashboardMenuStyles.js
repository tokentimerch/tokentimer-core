import { useColorModeValue } from '@chakra-ui/react';
import { useDashboardTheme } from './useDashboardTheme';

export function useDashboardMenuStyles() {
  const { border } = useDashboardTheme();
  const menuBg = useColorModeValue('white', 'rgba(15, 23, 42, 0.98)');
  const menuBorder = border;
  const chromeHoverBg = useColorModeValue('gray.100', 'rgba(30, 41, 59, 0.72)');
  const chromeHoverColor = useColorModeValue('gray.900', 'white');

  const menuListProps = {
    zIndex: 1500,
    bg: menuBg,
    borderColor: menuBorder,
  };

  const menuItemProps = {
    bg: 'transparent',
    _hover: { bg: chromeHoverBg },
    _focus: { bg: chromeHoverBg },
    _focusVisible: {
      bg: chromeHoverBg,
      boxShadow: `inset 0 0 0 1px ${menuBorder}`,
    },
    _active: { bg: chromeHoverBg },
    sx: {
      '&:hover, &[data-hover], &[data-focus]': {
        background: `${chromeHoverBg} !important`,
      },
    },
  };

  const inactiveMenuItemProps = {
    bg: 'transparent',
    _hover: { bg: 'transparent' },
    _focus: { bg: 'transparent' },
    _active: { bg: 'transparent' },
    sx: {
      '&:hover, &[data-hover], &[data-focus]': {
        background: 'transparent !important',
      },
    },
  };

  return {
    menuBg,
    menuBorder,
    chromeHoverBg,
    chromeHoverColor,
    menuListProps,
    menuItemProps,
    inactiveMenuItemProps,
  };
}
