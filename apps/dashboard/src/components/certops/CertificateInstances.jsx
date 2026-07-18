import {
  Badge,
  Table,
  TableContainer,
  Tbody,
  Td,
  Text,
  Th,
  Thead,
  Tr,
} from '@chakra-ui/react';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { DashboardState } from '../DashboardPrimitives.jsx';
import { formatDate, statusScheme } from './certopsFormat';

/**
 * Observation history for a managed certificate. Each instance is a
 * certificate location where the certificate was observed (an endpoint,
 * target, or other monitored location); monitors are observers.
 */
export default function CertificateInstances({ instances, available }) {
  const { muted, border } = useDashboardTheme();

  if (!available) {
    return (
      <DashboardState
        type='empty'
        title='History not available yet'
        description='Location history will appear here once instance tracking is enabled for this build.'
        py={6}
      />
    );
  }

  if (!instances || instances.length === 0) {
    return (
      <DashboardState
        type='empty'
        title='No locations recorded yet'
        description='This certificate has not been observed at any monitored location yet.'
        py={6}
      />
    );
  }

  return (
    <TableContainer>
      <Table size='sm' variant='simple'>
        <Thead>
          <Tr>
            <Th>Target</Th>
            <Th>Status</Th>
            <Th>Observed</Th>
            <Th>Source</Th>
          </Tr>
        </Thead>
        <Tbody>
          {instances.map(instance => (
            <Tr key={instance.id}>
              <Td borderColor={border}>
                <Text fontSize='sm' noOfLines={1}>
                  {instance.deploymentReference ||
                    instance.observedSubject ||
                    instance.targetId ||
                    '--'}
                </Text>
              </Td>
              <Td borderColor={border}>
                <Badge
                  colorScheme={statusScheme(instance.status)}
                  variant='subtle'
                  textTransform='none'
                >
                  {instance.status || 'unknown'}
                </Badge>
              </Td>
              <Td borderColor={border}>
                <Text fontSize='sm' color={muted}>
                  {formatDate(instance.observedAt)}
                </Text>
              </Td>
              <Td borderColor={border}>
                <Text fontSize='sm' color={muted} noOfLines={1}>
                  {instance.source || '--'}
                </Text>
              </Td>
            </Tr>
          ))}
        </Tbody>
      </Table>
    </TableContainer>
  );
}
