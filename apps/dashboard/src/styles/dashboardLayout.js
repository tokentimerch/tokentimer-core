/**
 * Fixed (not min) height shared by the sidebar's logo row and both header
 * bars (desktop + mobile), so their bottom borders always land on the exact
 * same horizontal line. Must stay a fixed `h`, not a `minH`: a `minH` lets
 * whichever row has the taller content (e.g. the page-title Heading) grow
 * past it, which is what caused the two borders to drift apart before.
 */
export const DASHBOARD_SHELL_HEADER_HEIGHT = '54px';

/** Shared horizontal rhythm for dashboard shell header and page content. */
export const DASHBOARD_PAGE_GUTTER_X = { base: 4, lg: 6, '2xl': 8 };

export const DASHBOARD_PAGE_GUTTER_Y = { base: 5, lg: 3 };

export const DASHBOARD_PAGE_CONTENT_PADDING = {
  px: DASHBOARD_PAGE_GUTTER_X,
  py: DASHBOARD_PAGE_GUTTER_Y,
};

/** Settings pages: section stack, panel padding, nested cards. */
export const SETTINGS_SECTION_GAP = 6;

export const SETTINGS_PANEL_PADDING = { base: 4, md: 5 };

export const SETTINGS_NESTED_RADIUS = 'md';
