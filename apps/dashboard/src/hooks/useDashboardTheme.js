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
      nested: useDashboardToken(dashboardThemeColors.bg.nested),
      field: useDashboardToken(dashboardThemeColors.bg.field),
    },
    border: {
      subtle: useDashboardToken(dashboardThemeColors.border.subtle),
      strong: useDashboardToken(dashboardThemeColors.border.strong),
      control: useDashboardToken(dashboardThemeColors.border.control),
      divider: useDashboardToken(dashboardThemeColors.border.divider),
    },
    text: {
      primary: useDashboardToken(dashboardThemeColors.text.primary),
      secondary: useDashboardToken(dashboardThemeColors.text.secondary),
      muted: useDashboardToken(dashboardThemeColors.text.muted),
    },
    accent: {
      primary: useDashboardToken(dashboardThemeColors.accent.primary),
      interactiveSurface: useDashboardToken(
        dashboardThemeColors.accent.interactiveSurface
      ),
      interactiveBorder: useDashboardToken(
        dashboardThemeColors.accent.interactiveBorder
      ),
      interactiveForeground: useDashboardToken(
        dashboardThemeColors.accent.interactiveForeground
      ),
      navActive: useDashboardToken(dashboardThemeColors.accent.navActive),
    },
    state: {
      danger: useDashboardToken(dashboardThemeColors.state.danger),
      warning: useDashboardToken(dashboardThemeColors.state.warning),
      success: useDashboardToken(dashboardThemeColors.state.success),
    },
    purple: {
      surface: useDashboardToken(dashboardThemeColors.purple.surface),
      surfaceHover: useDashboardToken(dashboardThemeColors.purple.surfaceHover),
      border: useDashboardToken(dashboardThemeColors.purple.border),
      icon: useDashboardToken(dashboardThemeColors.purple.icon),
    },
    callout: {
      warningSurface: useDashboardToken(
        dashboardThemeColors.callout.warningSurface
      ),
      warningBorder: useDashboardToken(
        dashboardThemeColors.callout.warningBorder
      ),
      warningText: useDashboardToken(dashboardThemeColors.callout.warningText),
      dangerSurface: useDashboardToken(
        dashboardThemeColors.callout.dangerSurface
      ),
      dangerBorder: useDashboardToken(dashboardThemeColors.callout.dangerBorder),
      dangerButton: useDashboardToken(dashboardThemeColors.callout.dangerButton),
      dangerButtonHover: useDashboardToken(
        dashboardThemeColors.callout.dangerButtonHover
      ),
    },
    table: {
      rowHover: useDashboardToken(dashboardThemeColors.table.rowHover),
    },
  };

  const inputBg = useColorModeValue('white', 'rgba(2, 6, 23, 0.58)');
  const footerLink = useColorModeValue('gray.700', 'rgba(203, 213, 225, 0.82)');
  const footerLinkHoverBg = useColorModeValue(
    'gray.100',
    'rgba(30, 41, 59, 0.72)'
  );
  const footerLinkHoverBorder = useColorModeValue(
    dashboard.border.strong,
    'rgba(148, 163, 184, 0.22)'
  );

  /** Settings pages: secondary body text (secondary in light, muted in dark). */
  const bodySecondary = useColorModeValue(
    dashboardThemeColors.text.secondary.light,
    dashboardThemeColors.text.muted.dark
  );

  /** Settings pages: section titles (strong contrast in light, inherit in dark). */
  const sectionTitleColor = useColorModeValue('#000000', 'inherit');

  return {
    dashboard,
    pageBg: 'transparent',
    surface: dashboard.bg.panel,
    text: dashboard.text.primary,
    muted: dashboard.text.muted,
    border: dashboard.border.subtle,
    borderStrong: dashboard.border.strong,
    borderControl: dashboard.border.control,
    bodySecondary,
    sectionTitleColor,
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
