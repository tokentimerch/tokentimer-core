import { useMemo, useState, Fragment } from 'react';
import {
  Badge,
  Button,
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
import { formatDateTime, statusScheme } from './certopsFormat';

function targetLabel(instance) {
  return (
    instance.deploymentReference ||
    instance.observedSubject ||
    instance.targetId ||
    '--'
  );
}

function instanceTimestamp(instance) {
  return instance.observedAt || instance.updatedAt || instance.createdAt || null;
}

/**
 * Groups instances by target, newest observation first within each group.
 * A single target can have several rows because certificate_instances keeps
 * one row per distinct (target, managed certificate, fingerprint) ever
 * observed there (a rotation-history log, not a live-state pointer) - see
 * apps/api/services/certops/controllerObservations.js. The current/latest
 * observation per target is what operators care about day to day; older
 * fingerprints for the same target are rotation history, not separate
 * locations, so they are collapsed rather than shown as duplicate-looking
 * rows.
 */
function groupByTarget(instances) {
  const order = [];
  const byTarget = new Map();
  for (const instance of instances) {
    const key = instance.targetId || instance.id;
    if (!byTarget.has(key)) {
      byTarget.set(key, []);
      order.push(key);
    }
    byTarget.get(key).push(instance);
  }
  return order.map(key => {
    const group = [...byTarget.get(key)].sort((a, b) => {
      const at = instanceTimestamp(a);
      const bt = instanceTimestamp(b);
      if (!at && !bt) return 0;
      if (!at) return 1;
      if (!bt) return -1;
      return new Date(bt).getTime() - new Date(at).getTime();
    });
    const [current, ...history] = group;
    // Fingerprint is not always populated (only the cert-manager path
    // guarantees it on every row; other sources can leave it null), so a
    // "renewed" signal is only shown when it can be proven true, and never
    // used to decide whether rows exist at all.
    const rotated = history.some(
      entry =>
        entry.observedFingerprintSha256 &&
        current.observedFingerprintSha256 &&
        entry.observedFingerprintSha256 !== current.observedFingerprintSha256
    );
    return { key, current, history, rotated };
  });
}

function InstanceRow({ instance, border, muted, indent = false }) {
  return (
    <Tr>
      <Td borderColor={border} pl={indent ? 8 : undefined}>
        <Text fontSize='sm' noOfLines={1} color={indent ? muted : undefined}>
          {targetLabel(instance)}
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
          {formatDateTime(instanceTimestamp(instance))}
        </Text>
      </Td>
      <Td borderColor={border}>
        <Text fontSize='sm' color={muted} noOfLines={1}>
          {instance.source || '--'}
        </Text>
      </Td>
    </Tr>
  );
}

export default function CertificateInstances({ instances, available, error }) {
  const { muted, border } = useDashboardTheme();
  const [expanded, setExpanded] = useState(() => new Set());

  const groups = useMemo(() => groupByTarget(instances || []), [instances]);

  if (error) {
    return (
      <DashboardState
        type='error'
        title='Could not load locations'
        description={error}
        py={6}
      />
    );
  }

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

  function toggle(key) {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
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
          {groups.map(({ key, current, history, rotated }) => (
            <Fragment key={key}>
              <Tr>
                <Td borderColor={border}>
                  <Text fontSize='sm' noOfLines={1}>
                    {targetLabel(current)}
                  </Text>
                </Td>
                <Td borderColor={border}>
                  <Badge
                    colorScheme={statusScheme(current.status)}
                    variant='subtle'
                    textTransform='none'
                  >
                    {current.status || 'unknown'}
                  </Badge>
                  {rotated ? (
                    <Badge ml={2} colorScheme='purple' variant='outline'>
                      Renewed
                    </Badge>
                  ) : null}
                </Td>
                <Td borderColor={border}>
                  <Text fontSize='sm' color={muted}>
                    {formatDateTime(instanceTimestamp(current))}
                  </Text>
                </Td>
                <Td borderColor={border}>
                  <Text fontSize='sm' color={muted} noOfLines={1}>
                    {current.source || '--'}
                  </Text>
                </Td>
              </Tr>
              {history.length > 0 ? (
                <Tr key={`${key}-toggle`}>
                  <Td colSpan={4} borderColor={border} pt={0} pb={2}>
                    <Button
                      size='xs'
                      variant='link'
                      onClick={() => toggle(key)}
                    >
                      {expanded.has(key)
                        ? 'Hide earlier observations'
                        : `Show ${history.length} earlier observation${
                            history.length === 1 ? '' : 's'
                          } at this location`}
                    </Button>
                  </Td>
                </Tr>
              ) : null}
              {expanded.has(key)
                ? history.map(entry => (
                    <InstanceRow
                      key={entry.id}
                      instance={entry}
                      border={border}
                      muted={muted}
                      indent
                    />
                  ))
                : null}
            </Fragment>
          ))}
        </Tbody>
      </Table>
    </TableContainer>
  );
}
