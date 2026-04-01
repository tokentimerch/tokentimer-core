/**
 * TokenTimer Color System
 * Centralized design tokens for full visual consistency
 * Brand: Clean, professional, developer-friendly, privacy-focused
 */

// ===== PRIMITIVE COLORS =====
// Base palette - do not use directly in components

export const primitives = {
  // Brand Primary (Vibrant Blue)
  blue: {
    50: '#eff6ff',
    100: '#dbeafe',
    200: '#bfdbfe',
    300: '#93c5fd',
    400: '#60a5fa',
    500: '#3b82f6', // Primary brand - vibrant
    600: '#2563eb',
    700: '#1d4ed8',
    800: '#1e40af',
    900: '#1e3a8a',
    950: '#0a3a8a', // Deep brand
  },

  // Neutrals (Surfaces, Text, Borders)
  slate: {
    50: '#f8fafc',
    100: '#f1f5f9',
    200: '#e2e8f0',
    300: '#cbd5e1',
    400: '#94a3b8',
    500: '#64748b',
    600: '#475569',
    700: '#334155',
    800: '#1e293b',
    900: '#0f172a',
    950: '#020617',
  },

  // Status: Success/Safe (Vibrant Green)
  green: {
    50: '#f0fdf4',
    100: '#dcfce7',
    200: '#bbf7d0',
    300: '#86efac',
    400: '#4ade80',
    500: '#22c55e', // Safe expiry (≥30 days) - vibrant
    600: '#16a34a',
    700: '#15803d',
    800: '#166534',
    900: '#14532d',
  },

  // Status: Warning (Vibrant Orange)
  orange: {
    50: '#fff7ed',
    100: '#ffedd5',
    200: '#fed7aa',
    300: '#fdba74',
    400: '#fb923c',
    500: '#ff6b00', // Warning expiry (8-29 days) - more vibrant
    600: '#f05000', // Danger expiry (1-7 days) - more vibrant
    700: '#c2410c',
    800: '#9a3412',
    900: '#7c2d12',
  },

  // Status: Danger/Error (Vibrant Red)
  red: {
    50: '#fef2f2',
    100: '#fee2e2',
    200: '#fecaca',
    300: '#fca5a5',
    400: '#f87171',
    500: '#ef4444',
    600: '#e11d48', // Expired - more vibrant
    700: '#b91c1c',
    800: '#991b1b',
    900: '#7f1d1d',
  },

  // Status: Info (Vibrant Cyan)
  cyan: {
    50: '#ecfeff',
    100: '#cffafe',
    200: '#a5f3fc',
    300: '#67e8f9',
    400: '#22d3ee',
    500: '#06b6d4',
    600: '#0891b2',
    700: '#0e7490',
    800: '#155e75',
    900: '#164e63',
  },
};

// ===== SEMANTIC TOKENS =====
// Use these in components - they map to primitives with context

export const tokens = {
  // Text hierarchy - high contrast for light mode
  text: {
    primary: {
      light: '#111827', // Near black for maximum contrast
      dark: '#ffffff',
    },
    secondary: {
      light: '#1f2937', // Very dark gray for strong contrast
      dark: 'rgba(255,255,255,0.92)',
    },
    tertiary: {
      light: '#374151', // Dark gray for good contrast
      dark: 'rgba(255,255,255,0.75)',
    },
    disabled: {
      light: primitives.slate[500], // Darker disabled text
      dark: 'rgba(255,255,255,0.38)',
    },
    inverse: {
      light: '#ffffff',
      dark: primitives.slate[900],
    },
  },

  // Background hierarchy
  bg: {
    surface: {
      light: 'rgba(255, 255, 255, 0.95)', // High opacity for better contrast
      dark: 'rgba(26,32,44,0.85)',
    },
    surfaceAlt: {
      light: 'rgba(255, 255, 255, 0.98)', // Nearly opaque for elevated elements
      dark: 'rgba(15,23,42,0.92)',
    },
    elevated: {
      light: 'rgba(255, 255, 255, 0.95)', // High opacity for better contrast
      dark: 'rgba(2,6,23,0.46)',
    },
    overlay: {
      light: 'rgba(255, 255, 255, 0.98)', // Nearly opaque white
      dark: 'rgba(2,6,23,0.92)',
    },
    hover: {
      light: 'rgba(255, 255, 255, 0.95)', // More opaque on hover
      dark: 'rgba(255,255,255,0.05)',
    },
    active: {
      light: 'rgba(255, 255, 255, 0.98)', // Nearly opaque when active
      dark: 'rgba(255,255,255,0.08)',
    },
  },

  // Border hierarchy
  border: {
    default: {
      light: primitives.slate[300], // More visible borders for better definition in light mode
      dark: 'rgba(255,255,255,0.08)', // Dark mode unchanged
    },
    subtle: {
      light: primitives.slate[200], // Subtle but visible in light mode
      dark: 'rgba(255,255,255,0.04)', // Dark mode unchanged
    },
    strong: {
      light: primitives.slate[400], // Strong separation in light mode
      dark: 'rgba(255,255,255,0.12)', // Dark mode unchanged
    },
    focus: {
      light: primitives.blue[500], // Vibrant focus indicator in light mode
      dark: primitives.blue[400], // Dark mode unchanged
    },
  },

  // Brand colors (more vibrant in light mode)
  brand: {
    primary: {
      light: primitives.blue[500], // More vibrant primary
      dark: primitives.blue[500],
    },
    primaryHover: {
      light: primitives.blue[600], // More vibrant hover
      dark: primitives.blue[600],
    },
    primaryActive: {
      light: primitives.blue[700], // More vibrant active
      dark: primitives.blue[700],
    },
    secondary: {
      light: primitives.blue[100],
      dark: primitives.blue[900],
    },
    accent: {
      light: primitives.blue[500], // Vibrant accent
      dark: primitives.blue[400],
    },
  },

  // Status colors (expiry logic) - more vibrant
  status: {
    ok: {
      light: primitives.green[500], // ≥30 days - more vibrant
      dark: primitives.green[500],
    },
    warning: {
      light: primitives.orange[500], // 8-29 days - vibrant orange
      dark: primitives.orange[400],
    },
    danger: {
      light: primitives.orange[600], // 1-7 days - vibrant red-orange
      dark: primitives.orange[500],
    },
    critical: {
      light: primitives.red[600], // Expired or today - vibrant red
      dark: primitives.red[500],
    },
    info: {
      light: primitives.cyan[500], // More vibrant cyan
      dark: primitives.cyan[500],
    },
  },

  // Interactive elements (more vibrant)
  interactive: {
    default: {
      light: primitives.blue[500], // Vibrant interactive color
      dark: primitives.blue[400],
    },
    hover: {
      light: primitives.blue[600], // Vibrant hover feedback
      dark: primitives.blue[300],
    },
    active: {
      light: primitives.blue[700], // Vibrant active state
      dark: primitives.blue[200],
    },
    disabled: {
      light: primitives.slate[400],
      dark: 'rgba(255,255,255,0.26)',
    },
  },
};

// Integration/Vendor Brand Colors
export const integrationBrandColors = {
  slack: {
    default: '#4A154B',
    hover: '#611F69',
  },
  teams: {
    default: '#6264A7',
    hover: '#4e5190',
  },
  discord: {
    default: '#5865F2',
    hover: '#4752c4',
  },
  pagerduty: {
    default: '#06AC38',
    hover: '#058a2d',
  },
  whatsapp: {
    default: '#25D366',
    hover: '#1da851',
  },
  github: {
    default: '#181717',
    hover: '#000000',
  },
  gitlab: {
    default: '#FC6D26',
    hover: '#e74c0c',
  },
  google: {
    default: '#4285F4',
    hover: '#357ae8',
  },
  microsoft: {
    default: '#00A4EF',
    hover: '#0078d4',
  },
  azure: {
    default: '#0078D4',
    hover: '#005a9e',
  },
  aws: {
    default: '#FF9900',
    hover: '#ec8800',
  },
  vault: {
    default: '#000000',
    hover: '#1a1a1a',
  },
};

// ===== CHAKRA UI SEMANTIC TOKENS =====
// Maps design tokens to Chakra UI's semantic token system

export const chakraSemanticTokens = {
  colors: {
    // Text
    'text.primary': {
      default: tokens.text.primary.light,
      _dark: tokens.text.primary.dark,
    },
    'text.secondary': {
      default: tokens.text.secondary.light,
      _dark: tokens.text.secondary.dark,
    },
    'text.tertiary': {
      default: tokens.text.tertiary.light,
      _dark: tokens.text.tertiary.dark,
    },
    'text.disabled': {
      default: tokens.text.disabled.light,
      _dark: tokens.text.disabled.dark,
    },
    'text.inverse': {
      default: tokens.text.inverse.light,
      _dark: tokens.text.inverse.dark,
    },

    // Backgrounds
    'bg.surface': {
      default: tokens.bg.surface.light,
      _dark: tokens.bg.surface.dark,
    },
    'bg.surfaceAlt': {
      default: tokens.bg.surfaceAlt.light,
      _dark: tokens.bg.surfaceAlt.dark,
    },
    'bg.elevated': {
      default: tokens.bg.elevated.light,
      _dark: tokens.bg.elevated.dark,
    },
    'bg.overlay': {
      default: tokens.bg.overlay.light,
      _dark: tokens.bg.overlay.dark,
    },
    'bg.hover': {
      default: tokens.bg.hover.light,
      _dark: tokens.bg.hover.dark,
    },
    'bg.active': {
      default: tokens.bg.active.light,
      _dark: tokens.bg.active.dark,
    },

    // Borders
    'border.default': {
      default: tokens.border.default.light,
      _dark: tokens.border.default.dark,
    },
    'border.subtle': {
      default: tokens.border.subtle.light,
      _dark: tokens.border.subtle.dark,
    },
    'border.strong': {
      default: tokens.border.strong.light,
      _dark: tokens.border.strong.dark,
    },
    'border.focus': {
      default: tokens.border.focus.light,
      _dark: tokens.border.focus.dark,
    },

    // Brand
    'brand.primary': {
      default: tokens.brand.primary.light,
      _dark: tokens.brand.primary.dark,
    },
    'brand.primaryHover': {
      default: tokens.brand.primaryHover.light,
      _dark: tokens.brand.primaryHover.dark,
    },
    'brand.primaryActive': {
      default: tokens.brand.primaryActive.light,
      _dark: tokens.brand.primaryActive.dark,
    },
    'brand.secondary': {
      default: tokens.brand.secondary.light,
      _dark: tokens.brand.secondary.dark,
    },
    'brand.accent': {
      default: tokens.brand.accent.light,
      _dark: tokens.brand.accent.dark,
    },

    // Status
    'status.ok': {
      default: tokens.status.ok.light,
      _dark: tokens.status.ok.dark,
    },
    'status.warning': {
      default: tokens.status.warning.light,
      _dark: tokens.status.warning.dark,
    },
    'status.danger': {
      default: tokens.status.danger.light,
      _dark: tokens.status.danger.dark,
    },
    'status.critical': {
      default: tokens.status.critical.light,
      _dark: tokens.status.critical.dark,
    },
    'status.info': {
      default: tokens.status.info.light,
      _dark: tokens.status.info.dark,
    },

    // Interactive
    'interactive.default': {
      default: tokens.interactive.default.light,
      _dark: tokens.interactive.default.dark,
    },
    'interactive.hover': {
      default: tokens.interactive.hover.light,
      _dark: tokens.interactive.hover.dark,
    },
    'interactive.active': {
      default: tokens.interactive.active.light,
      _dark: tokens.interactive.active.dark,
    },
    'interactive.disabled': {
      default: tokens.interactive.disabled.light,
      _dark: tokens.interactive.disabled.dark,
    },
  },
};

/**
 * Helper function to get color value based on color mode
 * @param {string} lightColor - Color value for light mode
 * @param {string} darkColor - Color value for dark mode
 * @returns {Array} - [lightValue, darkValue] for use with useColorModeValue
 */
export function colorModeValue(lightColor, darkColor) {
  return [lightColor, darkColor];
}

/**
 * Get expiry status with AA-compliant colors and label
 * Returns color values and text for status badges
 * @param {string|Date} expiry - Expiration date
 * @returns {Object} - { color, textColor, label }
 */
export function getExpiryStatus(expiry) {
  // Handle "never expires" sentinel value (year 9999 or 2099-12-31) or missing expiry
  const expiryStr = String(expiry || '');
  if (
    !expiry ||
    expiryStr === 'N/A' ||
    expiryStr.startsWith('9999-') ||
    expiryStr.startsWith('2099-12-31')
  ) {
    return {
      color: primitives.cyan[500], // Vibrant cyan
      textColor: '#ffffff',
      label: 'Never expires',
    };
  }

  try {
    const expirationDate = new Date(expiry);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    expirationDate.setHours(0, 0, 0, 0);

    const diffTime = expirationDate - today;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

    // Critical: Expired (Grey to de-emphasize)
    if (diffDays < 0) {
      return {
        color: primitives.slate[500],
        textColor: '#ffffff',
        label: 'Expired',
      };
    }

    // Critical: Expires today (Red)
    if (diffDays === 0) {
      return {
        color: primitives.red[600],
        textColor: '#ffffff',
        label: 'Expires today',
      };
    }

    // Danger zone: 1-7 days (Red for urgency)
    if (diffDays <= 7) {
      return {
        color: primitives.red[600],
        textColor: '#ffffff',
        label: '≤ 7 days',
      };
    }

    // Warning zone: 8-29 days (AA compliant orange)
    if (diffDays <= 29) {
      return {
        color: primitives.orange[500], // AA compliant
        textColor: '#ffffff',
        label: '< 30 days',
      };
    }

    // Safe: 30 days to 2 years (vibrant green)
    if (diffDays < 730) {
      // 2 years = ~730 days
      return {
        color: primitives.green[500], // Vibrant green
        textColor: '#ffffff',
        label: '≥ 30 days',
      };
    }

    // Long term: ≥2 years (vibrant green, but different label)
    return {
      color: primitives.green[500], // Vibrant green
      textColor: '#ffffff',
      label: 'Long term',
    };
  } catch (e) {
    return {
      color: primitives.slate[500],
      textColor: '#ffffff',
      label: 'Invalid date',
    };
  }
}

/**
 * Generate a deterministic color from a string
 * Used for section chips to ensure consistent colors for the same section names
 * @param {string} str - Input string (e.g., section name)
 * @returns {string} - Chakra UI color scheme name
 */
export function getColorFromString(str) {
  if (!str) return 'gray';

  // Predefined color schemes that work well in both light and dark modes
  const colorSchemes = [
    'blue',
    'purple',
    'pink',
    'red',
    'orange',
    'yellow',
    'green',
    'teal',
    'cyan',
  ];

  // Simple hash function to convert string to number
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = str.charCodeAt(i) + ((hash << 5) - hash);
    hash = hash & hash; // Convert to 32-bit integer
  }

  // Convert hash to positive index
  const index = Math.abs(hash) % colorSchemes.length;
  return colorSchemes[index];
}

// primitives and tokens are already exported above with export const
// Integration colors and semantic tokens exported here

// Export tokens as default
export default {
  tokens,
  primitives,
  integrationBrandColors,
  chakraSemanticTokens,
  colorModeValue,
  getExpiryStatus,
  getColorFromString,
};
