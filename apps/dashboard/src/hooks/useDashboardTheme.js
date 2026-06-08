import { createContext, useContext, createElement } from 'react';
import { useColorModeValue } from '@chakra-ui/react';
import { dashboardThemeColors } from '../styles/theme.js';

const DashboardThemeContext = createContext(null);

function useDashboardToken({ light, dark }) {
  return useColorModeValue(light, dark);
}

/** Shared dashboard chrome tokens (safe outside DashboardThemeProvider). */
export function useDashboardThemeColors() {
  const dashboard = {
    bg: {
      canvas: useDashboardToken(dashboardThemeColors.bg.canvas),
      shell: useDashboardToken(dashboardThemeColors.bg.shell),
      panel: useDashboardToken(dashboardThemeColors.bg.panel),
      panelHover: useDashboardToken(dashboardThemeColors.bg.panelHover),
    },
    border: {
      subtle: useDashboardToken(dashboardThemeColors.border.subtle),
      strong: useDashboardToken(dashboardThemeColors.border.strong),
    },
    text: {
      primary: useDashboardToken(dashboardThemeColors.text.primary),
      secondary: useDashboardToken(dashboardThemeColors.text.secondary),
      muted: useDashboardToken(dashboardThemeColors.text.muted),
    },
    accent: {
      primary: useDashboardToken(dashboardThemeColors.accent.primary),
    },
    state: {
      danger: useDashboardToken(dashboardThemeColors.state.danger),
      warning: useDashboardToken(dashboardThemeColors.state.warning),
      success: useDashboardToken(dashboardThemeColors.state.success),
    },
  };

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
    dashboard,
    pageBg: 'transparent',
    surface: dashboard.bg.panel,
    text: dashboard.text.primary,
    muted: dashboard.text.muted,
    border: dashboard.border.subtle,
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
