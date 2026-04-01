/**
 * TokenTimer Color Hooks
 * Provides semantic color tokens with automatic light/dark mode switching
 */

import { useColorModeValue } from '@chakra-ui/react';
import { tokens, integrationBrandColors, primitives } from '../styles/colors';

/**
 * Hook for text colors (primary, secondary, tertiary, disabled, inverse)
 */
export function useTextColors() {
  const primary = useColorModeValue(
    tokens.text.primary.light,
    tokens.text.primary.dark
  );
  const secondary = useColorModeValue(
    tokens.text.secondary.light,
    tokens.text.secondary.dark
  );
  const tertiary = useColorModeValue(
    tokens.text.tertiary.light,
    tokens.text.tertiary.dark
  );
  const disabled = useColorModeValue(
    tokens.text.disabled.light,
    tokens.text.disabled.dark
  );
  const inverse = useColorModeValue(
    tokens.text.inverse.light,
    tokens.text.inverse.dark
  );

  return { primary, secondary, tertiary, disabled, inverse };
}

/**
 * Hook for background colors (surface, surfaceAlt, elevated, overlay, hover, active)
 */
export function useBackgroundColors() {
  const surface = useColorModeValue(
    tokens.bg.surface.light,
    tokens.bg.surface.dark
  );
  const surfaceAlt = useColorModeValue(
    tokens.bg.surfaceAlt.light,
    tokens.bg.surfaceAlt.dark
  );
  const elevated = useColorModeValue(
    tokens.bg.elevated.light,
    tokens.bg.elevated.dark
  );
  const overlay = useColorModeValue(
    tokens.bg.overlay.light,
    tokens.bg.overlay.dark
  );
  const hover = useColorModeValue(tokens.bg.hover.light, tokens.bg.hover.dark);
  const active = useColorModeValue(
    tokens.bg.active.light,
    tokens.bg.active.dark
  );

  return { surface, surfaceAlt, elevated, overlay, hover, active };
}

/**
 * Hook for border colors (default, subtle, strong, focus)
 */
export function useBorderColors() {
  const defaultBorder = useColorModeValue(
    tokens.border.default.light,
    tokens.border.default.dark
  );
  const subtle = useColorModeValue(
    tokens.border.subtle.light,
    tokens.border.subtle.dark
  );
  const strong = useColorModeValue(
    tokens.border.strong.light,
    tokens.border.strong.dark
  );
  const focus = useColorModeValue(
    tokens.border.focus.light,
    tokens.border.focus.dark
  );

  return { default: defaultBorder, subtle, strong, focus };
}

/**
 * Hook for brand colors (primary, primaryHover, primaryActive, secondary, accent)
 */
export function useBrandColors() {
  const primary = useColorModeValue(
    tokens.brand.primary.light,
    tokens.brand.primary.dark
  );
  const primaryHover = useColorModeValue(
    tokens.brand.primaryHover.light,
    tokens.brand.primaryHover.dark
  );
  const primaryActive = useColorModeValue(
    tokens.brand.primaryActive.light,
    tokens.brand.primaryActive.dark
  );
  const secondary = useColorModeValue(
    tokens.brand.secondary.light,
    tokens.brand.secondary.dark
  );
  const accent = useColorModeValue(
    tokens.brand.accent.light,
    tokens.brand.accent.dark
  );

  return { primary, primaryHover, primaryActive, secondary, accent };
}

/**
 * Hook for status colors (ok, warning, danger, critical, info)
 * Maps to expiry logic: ok=≥30d, warning=8-29d, danger=1-7d, critical=expired
 */
export function useStatusColors() {
  const ok = useColorModeValue(tokens.status.ok.light, tokens.status.ok.dark);
  const warning = useColorModeValue(
    tokens.status.warning.light,
    tokens.status.warning.dark
  );
  const danger = useColorModeValue(
    tokens.status.danger.light,
    tokens.status.danger.dark
  );
  const critical = useColorModeValue(
    tokens.status.critical.light,
    tokens.status.critical.dark
  );
  const info = useColorModeValue(
    tokens.status.info.light,
    tokens.status.info.dark
  );

  return { ok, warning, danger, critical, info, success: ok, error: critical };
}

/**
 * Hook for interactive element colors (default, hover, active, disabled)
 */
export function useInteractiveColors() {
  const defaultColor = useColorModeValue(
    tokens.interactive.default.light,
    tokens.interactive.default.dark
  );
  const hover = useColorModeValue(
    tokens.interactive.hover.light,
    tokens.interactive.hover.dark
  );
  const active = useColorModeValue(
    tokens.interactive.active.light,
    tokens.interactive.active.dark
  );
  const disabled = useColorModeValue(
    tokens.interactive.disabled.light,
    tokens.interactive.disabled.dark
  );

  return {
    default: defaultColor,
    hover,
    active,
    disabled,
    link: defaultColor,
    linkHover: hover,
    primary: defaultColor,
  };
}

/**
 * Hook for integration/vendor brand colors
 * Returns all integration colors (no color mode switching for brand colors)
 */
export function useIntegrationColors() {
  return integrationBrandColors;
}

/**
 * Hook for article/blog pages
 * Consolidated colors for content pages - matches landing page aesthetic
 */
export function useArticleColors() {
  const text = useTextColors();
  const bg = useBackgroundColors();
  const border = useBorderColors();
  const interactive = useInteractiveColors();

  // Use darker colors for better contrast on overlay
  const textColor = useColorModeValue('gray.800', 'gray.300');
  const headingColor = useColorModeValue('gray.900', 'white');
  const subtleText = useColorModeValue('gray.600', text.tertiary);

  // Enhanced colors for blog/solutions pages in light mode
  const cardBg = useColorModeValue('rgba(255, 255, 255, 0.95)', bg.surface);
  const cardBorderColor = useColorModeValue('gray.300', border.default);
  const sectionBg = useColorModeValue('rgba(255, 255, 255, 0.95)', bg.elevated);
  const borderColor = useColorModeValue('gray.300', border.default);
  const tableHeaderBg = useColorModeValue('gray.100', bg.surfaceAlt);

  return {
    headingColor,
    textColor,
    subtleText,
    cardBg,
    cardBorderColor,
    cardTextColor: text.secondary,
    tableBorderColor: borderColor,
    tableHeaderBg,
    linkColor: interactive.link,
    sectionBg,
    borderColor,
  };
}

/**
 * Hook for landing/marketing pages
 */
export function useLandingColors() {
  const _text = useTextColors();
  const bg = useBackgroundColors();
  const border = useBorderColors();
  const brand = useBrandColors();

  // Use darker colors for better contrast on overlay
  const textColor = useColorModeValue('gray.900', 'gray.300');
  const headingColor = useColorModeValue('gray.900', 'white');
  const primaryColor = brand.primary;
  const cardBg = useColorModeValue(
    'rgba(255, 255, 255, 0.95)',
    'rgba(2, 6, 23, 0.46)'
  );
  const cardBorderColor = useColorModeValue('gray.400', 'gray.700');

  return {
    sectionBg: useColorModeValue('transparent', bg.elevated), // Transparent in light mode to avoid double opacity with LightModeOverlay
    sectionBgStrong: useColorModeValue(
      'rgba(255, 255, 255, 0.3)',
      bg.surfaceAlt
    ),
    sectionBorder: border.default,
    textColor,
    headingColor,
    primaryColor,
    cardBg,
    cardBorderColor,
  };
}

/**
 * Hook for pricing page specific colors
 */
export function usePricingColors() {
  const text = useTextColors();
  const bg = useBackgroundColors();
  const _brand = useBrandColors();

  const cardBg = bg.surface;
  const cardText = useColorModeValue(
    primitives.slate[900],
    primitives.slate[900]
  );
  const cardMuted = useColorModeValue(
    primitives.slate[900],
    primitives.slate[900]
  );
  const badgeBg = useColorModeValue(primitives.blue[950], primitives.blue[950]);
  const priceColor = primitives.blue[950];

  return {
    cardBg,
    cardText,
    cardMuted,
    badgeBg,
    pageText: text.primary,
    pageBodyText: text.secondary,
    priceColor,
  };
}

/**
 * Hook for card components
 */
export function useCardColors() {
  const bg = useBackgroundColors();
  const border = useBorderColors();
  const text = useTextColors();

  return {
    cardBg: bg.surface,
    cardBorderColor: border.default,
    cardText: text.secondary,
    cardHeading: text.primary,
  };
}

/**
 * Hook for section/panel components
 */
export function useSectionColors() {
  const bg = useBackgroundColors();
  const border = useBorderColors();

  return {
    sectionBg: bg.elevated,
    sectionBgStrong: bg.surfaceAlt,
    sectionBorder: border.default,
  };
}

/**
 * Hook for dashboard-specific colors
 * Provides colors used in the dashboard view - matches landing page aesthetic
 */
export function useDashboardColors() {
  const _bg = useBackgroundColors();
  const _border = useBorderColors();

  const bgColor = useColorModeValue('rgba(255, 255, 255, 0.95)', 'gray.800');
  const borderColor = useColorModeValue('gray.400', 'gray.600');
  const inputBg = useColorModeValue('rgba(255, 255, 255, 0.95)', 'gray.700');
  const inputBorder = useColorModeValue('gray.400', 'gray.600');
  const placeholderColor = useColorModeValue('gray.500', 'gray.500'); // More visible contrast
  const emptyTextColor = useColorModeValue('gray.900', 'gray.400');
  const hoverBgColor = useColorModeValue(
    'rgba(255, 255, 255, 0.98)',
    'gray.700'
  );
  const thHoverBg = useColorModeValue('rgba(255, 255, 255, 0.98)', 'gray.700');
  const filterLabelColor = useColorModeValue('gray.900', 'gray.300');
  const mobileCardBg = useColorModeValue(
    'rgba(255, 255, 255, 0.92)',
    'gray.700'
  );
  const secondaryTextColor = useColorModeValue('gray.900', 'gray.400');

  return {
    bgColor,
    borderColor,
    inputBg,
    inputBorder,
    placeholderColor,
    emptyTextColor,
    hoverBgColor,
    thHoverBg,
    filterLabelColor,
    mobileCardBg,
    secondaryTextColor,
  };
}

/**
 * Comprehensive hook that returns all color utilities
 * Use sparingly - prefer specific hooks for better performance
 */
export function useAllColors() {
  return {
    text: useTextColors(),
    bg: useBackgroundColors(),
    border: useBorderColors(),
    brand: useBrandColors(),
    status: useStatusColors(),
    interactive: useInteractiveColors(),
    integration: useIntegrationColors(),
    article: useArticleColors(),
    landing: useLandingColors(),
    pricing: usePricingColors(),
    card: useCardColors(),
    section: useSectionColors(),
  };
}

// Export individual hooks as default
export default {
  useTextColors,
  useBackgroundColors,
  useBorderColors,
  useBrandColors,
  useStatusColors,
  useInteractiveColors,
  useIntegrationColors,
  useArticleColors,
  useLandingColors,
  usePricingColors,
  useCardColors,
  useSectionColors,
  useDashboardColors,
  useAllColors,
};
