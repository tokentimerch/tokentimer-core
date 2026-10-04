/** Shared badge geometry and typography for dashboard status and metadata. */
export const dashboardBadgeBaseStyle = {
  display: 'inline-flex',
  alignItems: 'center',
  verticalAlign: 'middle',
  px: 2,
  py: 0.5,
  minH: '24px',
  borderRadius: 'md',
  fontSize: 'xs',
  fontWeight: 'semibold',
  lineHeight: 'short',
  textTransform: 'none',
};

export const badgeColorScheme = scheme =>
  scheme === 'yellow' ? 'orange' : scheme || 'gray';

export const dashboardBadgeTheme = {
  baseStyle: dashboardBadgeBaseStyle,
  defaultProps: { variant: 'subtle', colorScheme: 'gray' },
  variants: {
    subtle: ({ colorScheme }) => {
      const scheme = badgeColorScheme(colorScheme);
      return {
        border: '1px solid',
        boxShadow: 'none',
        bg: `${scheme}.100`,
        color: `${scheme}.800`,
        borderColor: `${scheme}.300`,
        _dark: {
          bg: `${scheme}.900`,
          color: `${scheme}.100`,
          borderColor: `${scheme}.700`,
        },
      };
    },
    solid: ({ colorScheme }) => {
      const scheme = badgeColorScheme(colorScheme);
      return {
        border: '1px solid',
        boxShadow: 'none',
        bg: `${scheme}.800`,
        color: 'white',
        borderColor: `${scheme}.700`,
        _dark: {
          bg: `${scheme}.800`,
          color: 'white',
          borderColor: `${scheme}.500`,
        },
      };
    },
    outline: ({ colorScheme }) => {
      const scheme = badgeColorScheme(colorScheme);
      return {
        border: '1px solid',
        boxShadow: 'none',
        bg: 'transparent',
        color: `${scheme}.800`,
        borderColor: `${scheme}.400`,
        _dark: { color: `${scheme}.100`, borderColor: `${scheme}.700` },
      };
    },
  },
};
