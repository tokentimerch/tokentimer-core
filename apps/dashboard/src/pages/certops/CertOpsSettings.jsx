import { SimpleGrid } from '@chakra-ui/react';
import ApiTokenPanel from '../../components/certops/ApiTokenPanel.jsx';
import { DashboardPanel } from '../../components/DashboardPrimitives';

/**
 * Settings tab: workspace-level certificate operations configuration. The
 * kill switch lives in the banner above every tab, so what remains here is
 * the machine credential surface.
 */
export default function CertOpsSettings() {
  return (
    <SimpleGrid columns={{ base: 1 }} spacing={3}>
      <DashboardPanel>
        <ApiTokenPanel />
      </DashboardPanel>
    </SimpleGrid>
  );
}
