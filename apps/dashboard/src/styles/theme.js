import { extendTheme } from '@chakra-ui/react';
import { chakraSemanticTokens as semanticTokens } from './colors';

/** Dashboard chrome palette (light = soft cool gray, dark = slate layered surfaces). */
export const dashboardThemeColors = {
  bg: {
    canvas: { light: '#f1f5f9', dark: 'transparent' },
    shell: {
      light: 'rgba(236, 242, 248, 0.94)',
      dark: 'rgba(13, 19, 26, 0.88)',
    },
    panel: {
      light: 'rgba(255, 255, 255, 0.98)',
      dark: 'rgba(30, 41, 59, 0.72)',
    },
    panelHover: {
      light: '#e8edf2',
      dark: 'rgba(51, 65, 85, 0.58)',
    },
    nested: {
      light: '#eef2f6',
      dark: 'rgba(51, 65, 85, 0.48)',
    },
    field: {
      light: '#f9fafb',
      dark: 'rgba(51, 65, 85, 0.58)',
    },
  },
  border: {
    subtle: { light: '#b8c5d2', dark: 'rgba(100, 116, 139, 0.32)' },
    strong: { light: '#9caab8', dark: 'rgba(148, 163, 184, 0.42)' },
    control: {
      light: 'rgba(148, 163, 184, 0.34)',
      dark: 'rgba(148, 163, 184, 0.18)',
    },
    divider: {
      light: 'rgba(148, 163, 184, 0.13)',
      dark: 'rgba(148, 163, 184, 0.13)',
    },
  },
  text: {
    primary: { light: '#0f172a', dark: '#ffffff' },
    secondary: { light: '#334155', dark: 'rgba(226, 232, 240, 0.92)' },
    muted: { light: '#64748b', dark: 'rgba(148, 163, 184, 0.92)' },
  },
  accent: {
    primary: { light: '#5a7d9a', dark: '#93c5fd' },
    interactiveSurface: { light: '#eff6ff', dark: 'rgba(255, 255, 255, 0.1)' },
    interactiveBorder: { light: '#bfdbfe', dark: '#2563eb' },
    interactiveForeground: { light: '#2563eb', dark: '#bfdbfe' },
    navActive: { light: '#1d4ed8', dark: '#bfdbfe' },
  },
  state: {
    danger: { light: '#dc2626', dark: '#f87171' },
    warning: { light: '#d97706', dark: '#fbbf24' },
    success: { light: '#16a34a', dark: '#4ade80' },
  },
  /** Purple callout surfaces (setup guides, help panels). Uses theme purple scale in light mode. */
  purple: {
    surface: { light: '#faf5ff', dark: 'rgba(88, 28, 135, 0.14)' },
    surfaceHover: { light: '#f3e8ff', dark: 'rgba(88, 28, 135, 0.22)' },
    border: { light: '#e9d5ff', dark: 'rgba(216, 180, 254, 0.28)' },
    icon: { light: '#7e22ce', dark: '#d8b4fe' },
  },
  /** Modal / AlertDialog shell and in-modal form controls. */
  modal: {
    overlay: { light: 'rgba(15, 23, 42, 0.46)', dark: 'rgba(2, 6, 23, 0.72)' },
    surface: { light: '#ffffff', dark: '#0d131a' },
    headerBg: { light: '#f8fafc', dark: '#0d131a' },
    footerBg: { light: '#f8fafc', dark: '#0d131a' },
    border: {
      light: 'rgba(148, 163, 184, 0.34)',
      dark: 'rgba(148, 163, 184, 0.18)',
    },
    text: { light: '#0f172a', dark: '#f8fafc' },
    muted: { light: '#64748b', dark: '#94a3b8' },
    subtleText: { light: '#475569', dark: '#cbd5e1' },
    fieldBg: { light: '#f8fafc', dark: '#0d131a' },
    inputBg: { light: '#ffffff', dark: '#090d15' },
    inputBorder: {
      light: 'rgba(100, 116, 139, 0.5)',
      dark: 'rgba(148, 163, 184, 0.28)',
    },
    focusBorder: { light: '#2563eb', dark: '#3b82f6' },
    sectionAccent: { light: '#2563eb', dark: '#60a5fa' },
    buttonBorder: {
      light: 'rgba(100, 116, 139, 0.48)',
      dark: 'rgba(148, 163, 184, 0.34)',
    },
    optionBg: { light: '#ffffff', dark: '#0f172a' },
    optionText: { light: '#0f172a', dark: '#f8fafc' },
    shadow: {
      light: '0 24px 70px rgba(0, 0, 0, 0.42)',
      dark: '0 24px 70px rgba(0, 0, 0, 0.42)',
    },
    danger: { light: '#dc2626', dark: '#f87171' },
  },
  /** Warning/danger alert panels and destructive actions in modals and danger zones. */
  callout: {
    warningSurface: { light: '#fff7ed', dark: 'rgba(146, 64, 14, 0.22)' },
    warningBorder: { light: '#fed7aa', dark: 'rgba(251, 191, 36, 0.34)' },
    warningText: { light: '#9a3412', dark: '#fde68a' },
    dangerSurface: { light: '#fef2f2', dark: 'rgba(127, 29, 29, 0.14)' },
    dangerBorder: { light: '#fecaca', dark: 'rgba(248, 113, 113, 0.28)' },
    dangerButton: { light: '#dc2626', dark: '#ef4444' },
    dangerButtonHover: { light: '#b91c1c', dark: '#dc2626' },
  },
  table: {
    rowHover: {
      light: 'rgba(0, 0, 0, 0.04)',
      dark: 'rgba(255, 255, 255, 0.1)',
    },
  },
};

const dashboardSemanticTokens = Object.fromEntries(
  Object.entries(dashboardThemeColors).flatMap(([group, entries]) =>
    Object.entries(entries).map(([name, { light, dark }]) => [
      `dashboard.${group}.${name}`,
      { default: light, _dark: dark },
    ])
  )
);

export const DASHBOARD_MODAL_HEADING_FONT = 'Archivo, system-ui, sans-serif';

function buildDashboardModalTokenMode(mode) {
  const modal = dashboardThemeColors.modal;
  return {
    overlayBg: modal.overlay[mode],
    surfaceBg: modal.surface[mode],
    fieldBg: modal.fieldBg[mode],
    headerBg: modal.headerBg[mode],
    footerBg: modal.footerBg[mode],
    border: modal.border[mode],
    text: modal.text[mode],
    muted: modal.muted[mode],
    subtleText: modal.subtleText[mode],
    inputBg: modal.inputBg[mode],
    inputBorder: modal.inputBorder[mode],
    focusBorder: modal.focusBorder[mode],
    sectionAccent: modal.sectionAccent[mode],
    buttonBorder: modal.buttonBorder[mode],
    danger: modal.danger[mode],
    optionBg: modal.optionBg[mode],
    optionText: modal.optionText[mode],
    shadow: modal.shadow[mode],
  };
}

/** Runtime token maps for modal JS (confirm cards, inline Text colors, etc.). */
export const dashboardModalTokenModes = Object.freeze({
  light: Object.freeze(buildDashboardModalTokenMode('light')),
  dark: Object.freeze(buildDashboardModalTokenMode('dark')),
});

/**
 * Shared base style for Modal and AlertDialog so every dialog matches the
 * dashboard panel language: opaque surface, subtle border, divided header and
 * footer, and an elevation shadow (no backdrop blur, to avoid jank).
 */
export const dashboardDialogFooterButtonSx = {
  '.chakra-button': {
    h: '36px',
    minH: '36px',
    px: 4,
    fontSize: 'sm',
    fontWeight: 'semibold',
    borderRadius: 'md',
  },
};

export const dashboardDialogFooterLayoutSx = {
  flex: '0 0 auto !important',
  flexGrow: '0 !important',
  flexShrink: '0 !important',
  flexBasis: 'auto !important',
  height: 'auto !important',
  minHeight: '0 !important',
  maxHeight: 'none !important',
  alignItems: 'flex-start !important',
  justifyContent: 'flex-start !important',
  '& > *': {
    flex: '0 0 auto !important',
    minHeight: '0 !important',
    width: '100%',
  },
};

export const dashboardDialogContentLayoutSx = {
  height: 'auto !important',
  minHeight: '0 !important',
};

export const dashboardDialogBodyControlSx = {
  '.chakra-form__label': {
    color: 'dashboard.modal.muted',
    fontWeight: 600,
    fontSize: { base: 'sm', md: 'md' },
    lineHeight: '1.375rem',
    mb: 1.5,
  },
  '.chakra-input, .chakra-select, .chakra-textarea': {
    bg: 'dashboard.modal.inputBg',
    borderColor: 'dashboard.modal.inputBorder',
    color: 'dashboard.modal.text',
    borderRadius: '10px',
    fontSize: '0.875rem',
  },
  '.chakra-input, .chakra-select': {
    h: '32px',
    minH: '32px',
    lineHeight: '1.25rem',
    px: 3,
  },
  '.chakra-textarea': {
    minH: '72px',
    py: 2,
    px: 3,
  },
  '.chakra-input::placeholder, .chakra-textarea::placeholder': {
    color: 'dashboard.modal.muted',
    opacity: 1,
  },
  '.chakra-input:hover, .chakra-select:hover, .chakra-textarea:hover': {
    borderColor: 'dashboard.modal.focusBorder',
  },
  '.chakra-input:focus-visible, .chakra-select:focus-visible, .chakra-textarea:focus-visible':
    {
      borderColor: 'dashboard.modal.focusBorder',
    },
  '.chakra-input[aria-invalid=true], .chakra-select[aria-invalid=true], .chakra-textarea[aria-invalid=true]':
    {
      borderColor: 'dashboard.modal.danger',
    },
  '.chakra-form__error-message': {
    color: 'dashboard.modal.danger',
    fontSize: 'xs',
  },
  '.chakra-table th': {
    color: 'dashboard.modal.muted',
    borderColor: 'dashboard.modal.border',
  },
  '.chakra-table td': {
    borderColor: 'dashboard.modal.border',
  },
  '.chakra-divider': {
    borderColor: 'dashboard.modal.border',
  },
  option: {
    bg: 'dashboard.modal.optionBg',
    color: 'dashboard.modal.optionText',
  },
};

export function createDashboardModalOutlineButtonProps(tokens) {
  return {
    variant: 'outline',
    borderColor: tokens.border,
    color: tokens.subtleText,
    _hover: {
      bg: tokens.fieldBg,
      borderColor: tokens.focusBorder,
    },
  };
}

export function createDashboardModalPrimaryButtonProps() {
  return {
    colorScheme: 'blue',
  };
}

export function createDashboardModalDangerButtonProps() {
  return {
    bg: 'dashboard.callout.dangerButton',
    color: 'white',
    _hover: { bg: 'dashboard.callout.dangerButtonHover' },
  };
}

export const dashboardModalTitleProps = {
  fontSize: { base: 'lg', md: 'xl' },
  fontWeight: 'bold',
  fontFamily: DASHBOARD_MODAL_HEADING_FONT,
  lineHeight: 'short',
};

export const dashboardModalDescriptionProps = {
  fontSize: { base: 'sm', md: 'md' },
  mt: 2,
  fontWeight: 'medium',
  lineHeight: '1.5',
};

/** Responsive action buttons inside modal body (not footer). */
export const dashboardModalInlineActionButtonProps = {
  w: { base: '100%', md: 'auto' },
  minH: { base: '44px', md: '40px' },
  h: { base: 'auto', md: undefined },
  whiteSpace: 'normal',
  flexShrink: 0,
};

export function createDashboardModalFieldProps(tokens) {
  return {
    bg: tokens.fieldBg,
    border: '1px solid',
    borderColor: tokens.border,
    borderRadius: '12px',
  };
}

export function createDashboardModalLabelProps(tokens) {
  return {
    color: tokens.muted,
    fontWeight: 'semibold',
    fontSize: { base: 'sm', md: 'md' },
  };
}

const dashboardDialogBaseStyle = {
  overlay: {
    _light: { bg: 'dashboard.modal.overlay' },
    _dark: { bg: 'dashboard.modal.overlay' },
  },
  dialogContainer: {
    bg: 'transparent',
    backgroundColor: 'transparent',
    py: { base: 4, md: 8 },
  },
  dialog: {
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
    borderRadius: { base: '14px', md: '18px' },
    border: '1px solid',
    mx: { base: 3, md: 0 },
    maxH: { base: 'calc(100dvh - 32px)', md: 'calc(100vh - 64px)' },
    minH: 0,
    height: 'auto',
    _light: {
      bg: 'dashboard.modal.surface',
      borderColor: 'dashboard.modal.border',
      boxShadow: dashboardThemeColors.modal.shadow.light,
      color: 'dashboard.modal.text',
    },
    _dark: {
      bg: 'dashboard.modal.surface',
      borderColor: 'dashboard.modal.border',
      boxShadow: dashboardThemeColors.modal.shadow.dark,
      color: 'dashboard.modal.text',
    },
    sx: dashboardDialogContentLayoutSx,
  },
  header: {
    fontFamily: DASHBOARD_MODAL_HEADING_FONT,
    fontWeight: 'bold',
    flexShrink: 0,
    px: { base: 5, md: 6 },
    py: { base: 5, md: 6 },
    pr: { base: 12, md: 14 },
    borderBottom: '1px solid',
    _light: {
      bg: 'dashboard.modal.headerBg',
      borderColor: 'dashboard.modal.border',
      color: 'dashboard.modal.text',
    },
    _dark: {
      bg: 'dashboard.modal.headerBg',
      borderColor: 'dashboard.modal.border',
      color: 'dashboard.modal.text',
    },
  },
  closeButton: {
    top: { base: 3, md: 4 },
    right: { base: 3, md: 4 },
    borderRadius: '10px',
    color: 'dashboard.modal.muted',
    _hover: {
      bg: 'dashboard.modal.fieldBg',
      color: 'dashboard.modal.text',
    },
  },
  body: {
    flex: '1 1 auto',
    flexGrow: 1,
    minH: 0,
    overflowY: 'auto',
    px: { base: 5, md: 6 },
    py: { base: 5, md: 6 },
    maxH: { base: 'calc(100dvh - 11rem)', md: 'calc(100vh - 12rem)' },
    _light: {
      bg: 'dashboard.modal.surface',
      color: 'dashboard.modal.text',
    },
    _dark: {
      bg: 'dashboard.modal.surface',
      color: 'dashboard.modal.text',
    },
    sx: {
      ...dashboardDialogBodyControlSx,
      flex: '1 1 auto !important',
      flexGrow: '1 !important',
      minHeight: '0 !important',
      overflowY: 'auto !important',
    },
  },
  footer: {
    px: { base: 4, md: 6 },
    pt: { base: 3, md: 5 },
    pb: { base: 3, md: 5 },
    gap: 3,
    borderTop: '1px solid',
    flex: '0 0 auto',
    flexShrink: 0,
    flexGrow: 0,
    mt: 'auto',
    alignItems: 'flex-start',
    justifyContent: 'flex-start',
    _light: {
      bg: 'dashboard.modal.footerBg',
      borderColor: 'dashboard.modal.border',
    },
    _dark: {
      bg: 'dashboard.modal.footerBg',
      borderColor: 'dashboard.modal.border',
    },
    sx: {
      ...dashboardDialogFooterButtonSx,
      ...dashboardDialogFooterLayoutSx,
    },
  },
};

// Design tokens for consistent theming
const colors = {
  // Primary brand colors
  primary: {
    50: '#e3f2fd',
    100: '#bbdefb',
    200: '#90caf9',
    300: '#64b5f6',
    400: '#42a5f5',
    500: '#2196f3', // Primary blue
    600: '#1e88e5',
    700: '#1976d2',
    800: '#1565c0',
    900: '#0d47a1',
  },
  // Semantic colors
  success: {
    50: '#e8f5e8',
    100: '#c8e6c9',
    200: '#a5d6a7',
    300: '#81c784',
    400: '#66bb6a',
    500: '#4caf50', // Success green
    600: '#43a047',
    700: '#388e3c',
    800: '#2e7d32',
    900: '#1b5e20',
  },
  warning: {
    50: '#fff8e1',
    100: '#ffecb3',
    200: '#ffe082',
    300: '#ffd54f',
    400: '#ffca28',
    500: '#ffc107', // Warning yellow
    600: '#ffb300',
    700: '#ffa000',
    800: '#ff8f00',
    900: '#ff6f00',
  },
  error: {
    50: '#ffebee',
    100: '#ffcdd2',
    200: '#ef9a9a',
    300: '#e57373',
    400: '#ef5350',
    500: '#f44336', // Error red
    600: '#e53935',
    700: '#d32f2f',
    800: '#c62828',
    900: '#b71c1c',
  },
  neutral: {
    50: '#fafafa',
    100: '#f5f5f5',
    200: '#eeeeee',
    300: '#e0e0e0',
    400: '#bdbdbd',
    500: '#9e9e9e',
    600: '#757575',
    700: '#616161',
    800: '#424242',
    900: '#212121',
  },
};

// Typography scale
const typography = {
  fonts: {
    heading:
      'Archivo, "Archivo Black", Archivo-Black, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    body: 'Montserrat, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    mono: '"Roboto Mono", Menlo, Monaco, "Courier New", monospace',
  },
  fontSizes: {
    xs: '0.75rem',
    sm: '0.875rem',
    md: '1rem',
    lg: '1.125rem',
    xl: '1.25rem',
    '2xl': '1.5rem',
    '3xl': '1.875rem',
    '4xl': '2.25rem',
    '5xl': '3rem',
    '6xl': '3.75rem',
  },
  fontWeights: {
    normal: 400,
    medium: 500,
    semibold: 600,
    bold: 700,
  },
  lineHeights: {
    normal: 'normal',
    none: 1,
    shorter: 1.25,
    short: 1.375,
    base: 1.5,
    tall: 1.625,
    taller: '2',
  },
};

// Spacing scale
const spacing = {
  space: {
    px: '1px',
    0.5: '0.125rem',
    1: '0.25rem',
    1.5: '0.375rem',
    2: '0.5rem',
    2.5: '0.625rem',
    3: '0.75rem',
    3.5: '0.875rem',
    4: '1rem',
    5: '1.25rem',
    6: '1.5rem',
    7: '1.75rem',
    8: '2rem',
    9: '2.25rem',
    10: '2.5rem',
    12: '3rem',
    14: '3.5rem',
    16: '4rem',
    20: '5rem',
    24: '6rem',
    28: '7rem',
    32: '8rem',
    36: '9rem',
    40: '10rem',
    44: '11rem',
    48: '12rem',
    52: '13rem',
    56: '14rem',
    60: '15rem',
    64: '16rem',
    72: '18rem',
    80: '20rem',
    96: '24rem',
  },
};

// Border radius scale
const radii = {
  none: '0',
  sm: '0.125rem',
  base: '0.25rem',
  md: '0.375rem',
  lg: '0.5rem',
  xl: '0.75rem',
  '2xl': '1rem',
  '3xl': '1.5rem',
  full: '9999px',
};

// Shadows
const shadows = {
  xs: '0 0 0 1px rgba(0, 0, 0, 0.05)',
  sm: '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
  base: '0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06)',
  md: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
  lg: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
  xl: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
  '2xl': '0 25px 50px -12px rgba(0, 0, 0, 0.25)',
  outline: '0 0 0 3px rgba(66, 153, 225, 0.6)',
  inner: 'inset 0 2px 4px 0 rgba(0, 0, 0, 0.06)',
  none: 'none',
};

// Component styles
const components = {
  Button: {
    baseStyle: {
      fontWeight: 'medium',
      borderRadius: 'lg',
      borderWidth: '1px',
      borderColor: 'transparent',
      _focus: {
        boxShadow: 'outline',
      },
      _loading: {
        opacity: 1,
        cursor: 'not-allowed',
        _hover: {
          opacity: 1,
        },
        '& .chakra-button__spinner': {
          opacity: 1,
          color: 'currentColor',
          animation: 'spin 0.65s linear infinite',
        },
      },
    },
    variants: {
      solid: props => ({
        bg: `${props.colorScheme}.500`,
        color: 'white',
        _hover: {
          bg: `${props.colorScheme}.600`,
        },
        _active: {
          bg: `${props.colorScheme}.700`,
        },
      }),
      outline: props => ({
        borderWidth: '1px',
        borderStyle: 'solid',
        borderColor: `${props.colorScheme}.600`,
        color: `${props.colorScheme}.700`,
        bg: 'transparent',
        _hover: {
          bg: `${props.colorScheme}.100`,
          borderColor: `${props.colorScheme}.700`,
        },
        _focus: {
          bg: 'transparent',
        },
        _active: {
          bg: 'transparent',
        },
        _dark: {
          borderWidth: '1px',
          color: `${props.colorScheme}.300`,
          borderColor: `${props.colorScheme}.300`,
          bg: 'transparent',
          _hover: {
            bg: `${props.colorScheme}.900`,
          },
        },
      }),
      ghost: props => ({
        color: `${props.colorScheme}.700`,
        bg: 'transparent', // Transparent background in light theme
        _hover: {
          bg: `${props.colorScheme}.100`,
          color: `${props.colorScheme}.800`,
        },
        _focus: {
          bg: 'transparent',
        },
        _active: {
          bg: 'transparent',
        },
        _dark: {
          color: `${props.colorScheme}.300`,
          bg: 'transparent',
          _hover: {
            bg: `${props.colorScheme}.900`,
          },
        },
      }),
    },
    sizes: {
      lg: {
        h: '48px',
        fontSize: 'lg',
        px: '6',
      },
      md: {
        h: '40px',
        fontSize: 'md',
        px: '4',
      },
      sm: {
        h: '32px',
        fontSize: 'sm',
        px: '3',
      },
    },
  },
  Spinner: {
    baseStyle: {
      color: 'blue.500',
      emptyColor: 'gray.200',
      speed: '0.65s',
      thickness: '3px',
      animation: 'spin 0.65s linear infinite',
    },
  },
  Input: {
    baseStyle: {
      field: {
        borderRadius: 'lg',
        _light: {
          borderColor: 'gray.400', // Stronger borders in light mode
          bg: 'rgba(255, 255, 255, 0.95)',
          color: 'gray.900',
        },
        _placeholder: {
          _light: {
            color: 'gray.500', // Better contrast for placeholders in light mode
          },
          _dark: {
            color: 'gray.500',
          },
        },
        _dark: {
          borderColor: 'gray.600',
        },
        _focus: {
          boxShadow: 'outline',
          borderColor: 'blue.500',
        },
        _disabled: {
          _light: {
            bg: 'rgba(255, 255, 255, 0.92)',
            borderColor: 'gray.400',
          },
          opacity: 0.8,
          cursor: 'not-allowed',
          _dark: {
            bg: 'gray.700',
            borderColor: 'gray.600',
          },
        },
      },
    },
  },
  Card: {
    baseStyle: {
      container: {
        borderRadius: 'xl',
        boxShadow: 'base',
        _light: {
          bg: 'rgba(255, 255, 255, 0.92)',
        },
      },
    },
  },
  Badge: {
    variants: {
      subtle: props => ({
        _light: {
          bg: `${props.colorScheme}.100`,
          color: `${props.colorScheme}.700`,
          border: '1px solid',
          borderColor: `${props.colorScheme}.300`,
        },
        fontWeight: 'semibold',
        _dark: {
          // Keep dark mode default behavior
        },
      }),
      solid: props => ({
        _light: {
          bg: `${props.colorScheme}.500`,
          color: 'white',
        },
        fontWeight: 'medium',
        _dark: {
          // Keep dark mode default behavior
        },
      }),
      outline: props => ({
        _light: {
          color: `${props.colorScheme}.700`,
          borderColor: `${props.colorScheme}.500`,
          borderWidth: '1px',
          bg: `${props.colorScheme}.50`,
        },
        borderWidth: '1px',
        fontWeight: 'medium',
        _dark: {
          // Keep dark mode default behavior
        },
      }),
    },
  },
  Alert: {
    variants: {
      info: {
        container: {
          bg: 'blue.50',
          borderColor: 'blue.200',
          color: 'blue.800',
          _dark: {
            bg: 'blue.900',
            borderColor: 'blue.700',
            color: 'blue.100',
          },
        },
      },
      warning: {
        container: {
          bg: 'orange.50',
          borderColor: 'orange.200',
          color: 'orange.800',
          _dark: {
            bg: 'orange.900',
            borderColor: 'orange.700',
            color: 'orange.100',
          },
        },
      },
      error: {
        container: {
          bg: 'red.50',
          borderColor: 'red.200',
          color: 'red.800',
          _dark: {
            bg: 'red.900',
            borderColor: 'red.700',
            color: 'red.100',
          },
        },
      },
      success: {
        container: {
          bg: 'green.50',
          borderColor: 'green.200',
          color: 'green.800',
          _dark: {
            bg: 'green.900',
            borderColor: 'green.700',
            color: 'green.100',
          },
        },
      },
    },
  },
  Switch: {
    baseStyle: {
      track: {
        bg: 'gray.300',
        _checked: {
          bg: 'blue.500',
        },
        _dark: {
          bg: 'gray.600',
          _checked: {
            bg: 'blue.600',
          },
        },
      },
    },
  },
  Divider: {
    baseStyle: {
      _light: {
        borderColor: 'dashboard.border.subtle',
      },
      _dark: {
        borderColor: 'gray.600',
      },
    },
  },
  Checkbox: {
    baseStyle: {
      control: {
        borderWidth: '2px',
        _light: {
          borderColor: 'gray.500',
          bg: 'white',
          _checked: {
            bg: 'blue.500',
            borderColor: 'blue.500',
            color: 'white',
            _hover: {
              bg: 'blue.600',
              borderColor: 'blue.600',
            },
          },
        },
        _checked: {
          bg: 'blue.500',
          borderColor: 'blue.500',
          color: 'white',
          _hover: {
            bg: 'blue.600',
            borderColor: 'blue.600',
          },
        },
        _focus: {
          boxShadow: '0 0 0 3px rgba(66, 153, 225, 0.3)',
        },
        _disabled: {
          _light: {
            bg: 'rgba(255, 255, 255, 0.92)',
            borderColor: 'gray.400',
          },
          opacity: 0.7,
          cursor: 'not-allowed',
        },
        _dark: {
          borderColor: 'gray.600',
          _checked: {
            bg: 'blue.500',
            borderColor: 'blue.500',
            _hover: {
              bg: 'blue.400',
              borderColor: 'blue.400',
            },
          },
          _disabled: {
            bg: 'gray.700',
            borderColor: 'gray.600',
            opacity: 0.7,
          },
        },
      },
      icon: {
        _light: {
          color: 'white',
        },
        color: 'white',
      },
      label: {
        _disabled: {
          opacity: 0.7, // More visible disabled text
          color: 'gray.500', // More visible in light theme
          _dark: {
            color: 'gray.400',
          },
        },
      },
    },
  },
  FormControl: {
    baseStyle: {
      label: {
        _light: {
          color: 'gray.700',
        },
        _disabled: {
          opacity: 0.7, // More visible disabled label
          color: 'gray.500', // More visible in light theme
          _dark: {
            color: 'gray.400',
          },
        },
      },
      helperText: {
        _light: {
          color: 'gray.600',
        },
        _disabled: {
          opacity: 0.7, // More visible disabled helper text
          color: 'gray.500',
          _dark: {
            color: 'gray.400',
          },
        },
      },
    },
  },
  FormLabel: {
    baseStyle: {
      _light: {
        color: 'gray.700',
      },
    },
  },
  Select: {
    parts: ['field', 'icon'],
    baseStyle: {
      field: {
        _light: {
          borderColor: 'gray.400',
          bg: 'rgba(255, 255, 255, 0.95)',
          backgroundColor: 'rgba(255, 255, 255, 0.95)',
          color: 'gray.900',
        },
        _dark: {
          borderColor: 'gray.600',
          bg: 'gray.800',
          backgroundColor: 'gray.800',
        },
        _focus: {
          borderColor: 'blue.500',
          boxShadow: '0 0 0 1px var(--chakra-colors-blue-500)',
        },
        _disabled: {
          _light: {
            bg: 'rgba(255, 255, 255, 0.92)',
            backgroundColor: 'rgba(255, 255, 255, 0.92)',
            borderColor: 'gray.400',
          },
          opacity: 0.8,
          cursor: 'not-allowed',
          _dark: {
            bg: 'gray.700',
            backgroundColor: 'gray.700',
            borderColor: 'gray.600',
          },
        },
      },
    },
  },
  Textarea: {
    baseStyle: {
      bg: 'transparent',
      _light: {
        borderColor: 'gray.400',
      },
      _placeholder: {
        _light: {
          color: 'gray.500',
        },
        _dark: {
          color: 'gray.500',
        },
      },
      _dark: {
        borderColor: 'gray.600',
      },
      _focus: {
        borderColor: 'blue.500',
        boxShadow: '0 0 0 1px var(--chakra-colors-blue-500)',
      },
      _disabled: {
        _light: {
          bg: 'rgba(255, 255, 255, 0.92)',
          borderColor: 'gray.400',
        },
        opacity: 0.8,
        cursor: 'not-allowed',
        _dark: {
          bg: 'gray.700',
          borderColor: 'gray.600',
        },
      },
    },
  },
  Menu: {
    baseStyle: {
      list: {
        bg: 'rgba(255, 255, 255, 0.95)', // Match landing page aesthetic - more opaque for readability
        borderColor: 'dashboard.border.subtle',
        borderWidth: '1px',
        _dark: {
          bg: 'gray.800',
          borderColor: 'gray.600',
        },
      },
      item: {
        bg: 'transparent', // Menu items should be transparent to show menu list background
        backgroundColor: 'transparent', // Explicitly set backgroundColor to override white
        _light: {
          bg: 'transparent',
          backgroundColor: 'transparent',
        },
        _dark: {
          bg: 'transparent',
          backgroundColor: 'transparent',
        },
        _focus: {
          bg: 'blue.50', // More visible focus state
          backgroundColor: 'blue.50',
          _dark: {
            bg: 'blue.900',
            backgroundColor: 'blue.900',
          },
        },
        _active: {
          bg: 'blue.100',
          backgroundColor: 'blue.100',
          _dark: {
            bg: 'blue.800',
            backgroundColor: 'blue.800',
          },
        },
        _hover: {
          bg: 'blue.50',
          backgroundColor: 'blue.50',
          _dark: {
            bg: 'blue.900',
            backgroundColor: 'blue.900',
          },
        },
      },
    },
  },
  Modal: {
    parts: [
      'overlay',
      'dialogContainer',
      'dialog',
      'header',
      'body',
      'footer',
      'closeButton',
    ],
    baseStyle: dashboardDialogBaseStyle,
  },
  AlertDialog: {
    parts: [
      'overlay',
      'dialogContainer',
      'dialog',
      'header',
      'body',
      'footer',
      'closeButton',
    ],
    baseStyle: dashboardDialogBaseStyle,
  },
  Table: {
    baseStyle: {
      th: {
        _light: {
          color: 'gray.700',
          borderBottomColor: 'dashboard.border.strong',
        },
        _dark: {
          color: 'gray.300',
          borderBottomColor: 'gray.600',
        },
      },
      td: {
        _light: {
          color: 'gray.800',
          borderBottomColor: 'dashboard.border.subtle',
        },
        _dark: {
          color: 'gray.100',
          borderBottomColor: 'gray.600',
        },
      },
    },
  },
  Text: {
    baseStyle: {
      _light: {
        color: 'gray.800',
      },
    },
  },
  Heading: {
    baseStyle: {
      _light: {
        color: 'gray.900',
      },
    },
  },
};

// Create unified theme with proper color mode support
export const theme = extendTheme({
  colors: {
    ...colors,
    // Enhanced semantic colors for better dark mode support
    red: {
      50: '#fef2f2',
      100: '#fee2e2',
      200: '#fecaca',
      300: '#fca5a5',
      400: '#f87171',
      500: '#ef4444',
      600: '#dc2626',
      700: '#b91c1c',
      800: '#991b1b',
      900: '#7f1d1d',
    },
    blue: {
      50: '#eff6ff',
      100: '#dbeafe',
      200: '#bfdbfe',
      300: '#93c5fd',
      400: '#60a5fa',
      500: '#3b82f6',
      600: '#2563eb',
      700: '#1d4ed8',
      800: '#1e40af',
      900: '#1e3a8a',
    },
    orange: {
      50: '#fff7ed',
      100: '#ffedd5',
      200: '#fed7aa',
      300: '#fdba74',
      400: '#fb923c',
      500: '#f97316',
      600: '#ea580c',
      700: '#c2410c',
      800: '#9a3412',
      900: '#7c2d12',
    },
    green: {
      50: '#f0fdf4',
      100: '#dcfce7',
      200: '#bbf7d0',
      300: '#86efac',
      400: '#4ade80',
      500: '#22c55e',
      600: '#16a34a',
      700: '#15803d',
      800: '#166534',
      900: '#14532d',
    },
    purple: {
      50: '#faf5ff',
      100: '#f3e8ff',
      200: '#e9d5ff',
      300: '#d8b4fe',
      400: '#c084fc',
      500: '#a855f7',
      600: '#9333ea',
      700: '#7e22ce',
      800: '#6b21a8',
      900: '#581c87',
    },
  },
  semanticTokens: {
    colors: {
      ...semanticTokens.colors,
      ...dashboardSemanticTokens,
    },
  },
  ...typography,
  ...spacing,
  radii,
  shadows,
  components,
  config: {
    initialColorMode: 'system',
    useSystemColorMode: true,
  },
  styles: {
    global: props => ({
      '@keyframes spin': {
        from: { transform: 'rotate(0deg)' },
        to: { transform: 'rotate(360deg)' },
      },
      '.chakra-button__spinner, .chakra-spinner': {
        animation: 'spin 0.65s linear infinite',
      },
      body: {
        bg: props.colorMode === 'dark' ? 'gray.900' : 'white',
        color: props.colorMode === 'dark' ? 'white' : 'gray.900',
        backgroundImage:
          props.colorMode === 'dark'
            ? "url('/Branding/background-blue.avif')"
            : "url('/Branding/background-light.avif')",
        backgroundRepeat: 'no-repeat',
        backgroundAttachment: 'fixed',
        backgroundSize: 'cover',
        backgroundPosition: 'center center',
        // Slightly increase contrast of background in light mode
        opacity: 1,
      },
      '.chakra-modal__footer, .chakra-alert-dialog__footer': {
        flex: '0 0 auto !important',
        flexGrow: '0 !important',
        minHeight: '0 !important',
        height: 'auto !important',
      },
      '.chakra-modal__footer > *, .chakra-alert-dialog__footer > *': {
        flex: '0 0 auto !important',
        minHeight: '0 !important',
      },
    }),
  },
});

// Theme utilities
export const getThemeColors = colorMode => {
  return colorMode === 'dark'
    ? {
        background: {
          primary: '#1a1a1a',
          secondary: '#2d2d2d',
          tertiary: '#404040',
        },
        text: {
          primary: '#ffffff',
          secondary: '#e0e0e0',
          tertiary: '#b0b0b0',
          inverse: '#1a1a1a',
        },
        border: {
          primary: '#4a4a4a',
          secondary: '#5a5a5a',
        },
        surface: {
          primary: '#1a1a1a',
          secondary: '#2d2d2d',
          elevated: '#404040',
        },
      }
    : {
        background: {
          primary: '#ffffff',
          secondary: '#f8f9fa',
          tertiary: '#f1f3f4',
        },
        text: {
          primary: '#202124',
          secondary: '#5f6368',
          tertiary: '#9aa0a6',
          inverse: '#ffffff',
        },
        border: {
          primary: '#9caab8',
          secondary: '#b8c5d2',
        },
        surface: {
          primary: '#ffffff',
          secondary: '#f8f9fa',
          elevated: '#ffffff',
        },
      };
};

export const getContrastTextColor = (bgColor, colorMode) => {
  const colors = getThemeColors(colorMode);
  // Simple contrast logic - can be enhanced with more sophisticated algorithms
  if (
    bgColor.includes('primary.500') ||
    bgColor.includes('success.500') ||
    bgColor.includes('error.500')
  ) {
    return colors.text.inverse;
  }
  return colors.text.primary;
};
