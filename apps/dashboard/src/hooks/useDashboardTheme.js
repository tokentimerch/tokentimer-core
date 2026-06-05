import { createContext, useContext, createElement } from 'react';
import { useColorModeValue } from '@chakra-ui/react';

const DashboardThemeContext = createContext(null);

/** Shared dashboard chrome tokens (safe outside DashboardThemeProvider). */
export function useDashboardThemeColors() {
  const pageBg = 'transparent';
  const surface = useColorModeValue(
    'rgba(255,255,255,0.95)',
    'rgba(13, 19, 26, 0.95)'
  );
  const text = useColorModeValue('gray.900', 'white');
  const muted = useColorModeValue('gray.600', 'rgba(148,163,184,0.92)');
  const border = useColorModeValue('gray.200', 'rgba(100,116,139,0.2)');
  const inputBg = useColorModeValue('white', 'rgba(2, 6, 23, 0.58)');
  const footerLink = useColorModeValue('gray.700', 'rgba(203, 213, 225, 0.82)');
  const footerLinkHoverBg = useColorModeValue(
    'gray.100',
    'rgba(30, 41, 59, 0.72)'
  );
  const footerLinkHoverBorder = useColorModeValue(
    'gray.300',
    'rgba(148, 163, 184, 0.22)'
  );

  return {
    pageBg,
    surface,
    text,
    muted,
    border,
    inputBg,
    footerLink,
    footerLinkHoverBg,
    footerLinkHoverBorder,
  };
}

export function DashboardThemeProvider({ children }) {
  const value = useDashboardThemeColors();

  return createElement(DashboardThemeContext.Provider, { value }, children);
}

export function useDashboardTheme() {
  const context = useContext(DashboardThemeContext);
  if (context == null) {
    throw new Error(
      'useDashboardTheme must be used within DashboardThemeProvider'
    );
  }
  return context;
}
