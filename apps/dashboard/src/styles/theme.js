import { extendTheme } from '@chakra-ui/react';
import { chakraSemanticTokens as semanticTokens } from './colors';

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
      _focus: {
        boxShadow: 'outline',
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
        border: '1px solid',
        borderColor: `${props.colorScheme}.600`,
        color: `${props.colorScheme}.700`,
        bg: 'transparent', // Transparent background in light theme
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
          borderWidth: '1.5px',
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
        borderColor: 'gray.300',
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
        borderColor: 'gray.200',
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
    parts: ['overlay', 'dialogContainer', 'dialog'],
    baseStyle: {
      dialogContainer: {
        bg: 'transparent',
        backgroundColor: 'transparent',
        backdropFilter: 'blur(10px)',
        WebkitBackdropFilter: 'blur(10px)',
        _light: {
          bg: 'transparent',
          backgroundColor: 'transparent',
        },
        _dark: {
          bg: 'transparent',
          backgroundColor: 'transparent',
        },
      },
    },
  },
  AlertDialog: {
    parts: ['overlay', 'dialogContainer', 'dialog'],
    baseStyle: {
      dialogContainer: {
        bg: 'transparent',
        backgroundColor: 'transparent',
        backdropFilter: 'blur(10px)',
        WebkitBackdropFilter: 'blur(10px)',
        _light: {
          bg: 'transparent',
          backgroundColor: 'transparent',
        },
        _dark: {
          bg: 'transparent',
          backgroundColor: 'transparent',
        },
      },
    },
  },
  Table: {
    baseStyle: {
      th: {
        _light: {
          color: 'gray.700',
          borderBottomColor: 'gray.300',
        },
        _dark: {
          color: 'gray.300',
          borderBottomColor: 'gray.600',
        },
      },
      td: {
        _light: {
          color: 'gray.800',
          borderBottomColor: 'gray.200',
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
  semanticTokens,
  ...typography,
  ...spacing,
  radii,
  shadows,
  components,
  config: {
    initialColorMode: 'light',
    useSystemColorMode: false,
  },
  styles: {
    global: props => ({
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
          primary: '#94a3b8', // More visible - slate-400
          secondary: '#cbd5e1', // More visible - slate-300
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
