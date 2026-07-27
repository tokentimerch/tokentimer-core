import {
  DashboardPanel,
  DashboardPanelHeader,
  DashboardState,
} from '../../components/DashboardPrimitives';

/**
 * Certificates tab. The inventory list, its filters and the per-certificate
 * view land here; this is the route and the entry point they mount into.
 */
export default function CertOpsCertificates() {
  return (
    <DashboardPanel>
      <DashboardPanelHeader
        title='Certificates'
        description='Managed certificate inventory for this workspace'
      />
      <DashboardState
        title='The certificate list is not here yet'
        description='This tab is the home for the managed certificate inventory. Until it ships, certificate details remain reachable from the token inventory.'
        py={6}
      />
    </DashboardPanel>
  );
}
