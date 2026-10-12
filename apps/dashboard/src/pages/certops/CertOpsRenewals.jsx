import { useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Box,
  Collapse,
  Flex,
  Icon,
  SimpleGrid,
  Text,
} from '@chakra-ui/react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { useOutletContext } from 'react-router';
import { DashboardPanel } from '../../components/DashboardPrimitives.jsx';
import RenewalProfilesPanel from '../../components/certops/RenewalProfilesPanel.jsx';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import CertOpsAdcs from './CertOpsAdcs.jsx';

function AdcsDisclosure() {
  const [open, setOpen] = useState(false);
  const { muted, dashboard } = useDashboardTheme();

  return (
    <Box>
      <Flex
        as='button'
        type='button'
        w='full'
        textAlign='left'
        align='flex-start'
        gap={2}
        py={1}
        onClick={() => setOpen(current => !current)}
        aria-expanded={open}
        aria-controls='certops-adcs-section'
      >
        <Icon
          as={open ? ChevronDown : ChevronRight}
          boxSize={4}
          mt='3px'
          color={muted}
        />
        <Box>
          <Text fontSize='md' fontWeight='bold' color={dashboard.text.primary}>
            AD CS issuers
          </Text>
          <Text fontSize='sm' color={muted}>
            For profiles that renew from Active Directory. Creating an issuer
            does not enable enrollment.
          </Text>
        </Box>
      </Flex>
      <Collapse in={open} animateOpacity unmountOnExit>
        <Box id='certops-adcs-section' mt={3}>
          <CertOpsAdcs />
        </Box>
      </Collapse>
    </Box>
  );
}

/**
 * Renewals tab.
 *
 * Profiles control whether agent-issued certificates renew. AD CS issuers and
 * enrollments sit below them. When each certificate renews is on that
 * certificate in the inventory.
 */
export default function CertOpsRenewals() {
  const { certOpsPaused } = useOutletContext() || {};

  return (
    <SimpleGrid columns={{ base: 1 }} spacing={3}>
      {certOpsPaused ? (
        // A per-profile badge can only say whether that profile renews; it
        // cannot say the whole workspace is paused.
        <Alert status='warning' variant='subtle' borderRadius='md'>
          <AlertIcon boxSize={4} />
          <AlertDescription fontSize='sm'>
            Certificate operations are paused for this workspace, so no renewal
            job is being created regardless of what a profile below says.
            Renewal timing is on each certificate in the inventory.
          </AlertDescription>
        </Alert>
      ) : null}
      <DashboardPanel>
        <RenewalProfilesPanel />
      </DashboardPanel>
      <AdcsDisclosure />
    </SimpleGrid>
  );
}
