import { Box } from '@chakra-ui/react';
import DashboardShell from './DashboardShell';
import { useDashboardShellProps } from '../hooks/useDashboardShellProps';

export const DASHBOARD_PAGE_VARIANTS = ['wide', 'standard', 'narrow', 'form'];

/**
 * Content max-widths per variant. `wide` is full-bleed (dashboard / control
 * center / audit); the others use a comfortable centered column so cards are
 * not stretched edge-to-edge on large displays.
 *
 * @type {Record<string, string | undefined>}
 */
export const DASHBOARD_PAGE_MAX_WIDTHS = {
  wide: undefined,
  standard: '1280px',
  narrow: '960px',
  form: '1120px',
};

const CONTENT_PADDING = {
  px: { base: 4, lg: 4, '2xl': 5 },
  py: { base: 5, lg: 3 },
};

/**
 * Dashboard page chrome: DashboardShell plus a width-constrained content area.
 *
 * @param {object} props
 * @param {object|null} [props.session]
 * @param {() => void} [props.onLogout]
 * @param {() => void} [props.onAccountClick]
 * @param {string} [props.pageTitle='']
 * @param {boolean} [props.isViewer=false]
 * @param {'wide'|'standard'|'narrow'|'form'} [props.variant='standard']
 * @param {boolean} [props.hideWorkspaceSelector=false]
 * @param {object[]} [props.dashboardWorkspaces]
 * @param {object|null} [props.dashboardWorkspace]
 * @param {(workspace: object) => void} [props.onWorkspaceSelect]
 * @param {object[]} [props.dashboardNotifications]
 * @param {boolean} [props.dashboardCanSeeManagerNav]
 * @param {object} [props.contentProps]
 * @param {import('react').ReactNode} props.children
 */
export default function DashboardPageLayout({
  session = null,
  onLogout,
  onAccountClick,
  pageTitle = '',
  isViewer = false,
  variant = 'standard',
  hideWorkspaceSelector = false,
  dashboardWorkspaces,
  dashboardWorkspace,
  onWorkspaceSelect,
  dashboardNotifications,
  dashboardCanSeeManagerNav,
  contentProps,
  children,
}) {
  const shellProps = useDashboardShellProps({
    session,
    onLogout,
    onAccountClick,
    pageTitle,
    isViewer,
    dashboardWorkspaces,
    dashboardWorkspace,
    onWorkspaceSelect,
    dashboardNotifications,
    dashboardCanSeeManagerNav,
  });

  const maxW =
    DASHBOARD_PAGE_MAX_WIDTHS[variant] ?? DASHBOARD_PAGE_MAX_WIDTHS.standard;
  const hideWorkspaceSelectorSx = hideWorkspaceSelector
    ? { '[data-tour="workspace-selector"]': { display: 'none !important' } }
    : undefined;

  return (
    <Box sx={hideWorkspaceSelectorSx}>
      <DashboardShell
        {...shellProps}
        dashboardWorkspaces={
          hideWorkspaceSelector ? [] : shellProps.dashboardWorkspaces
        }
      >
        <Box
          {...CONTENT_PADDING}
          maxW={maxW}
          mx={maxW ? 'auto' : undefined}
          w='full'
          {...contentProps}
        >
          {children}
        </Box>
      </DashboardShell>
    </Box>
  );
}
