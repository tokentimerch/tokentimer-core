import { DashboardPanel, DashboardPanelHeader } from './DashboardPrimitives';

/**
 * Card wrapper for SSO admin forms using shared dashboard panel styling.
 */
export default function SsoFormCard({ title, description, children, ...rest }) {
  return (
    <DashboardPanel {...rest}>
      {title || description ? (
        <DashboardPanelHeader title={title} description={description} />
      ) : null}
      {children}
    </DashboardPanel>
  );
}
