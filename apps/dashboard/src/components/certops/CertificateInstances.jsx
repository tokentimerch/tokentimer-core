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
  Tooltip,
  Tr,
} from '@chakra-ui/react';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { DashboardState } from '../DashboardPrimitives.jsx';
import {
  formatDateTime,
  locationKindLabel,
  statusScheme,
} from './certopsFormat';
import { formatRelativeDateTime } from './certopsJobsFormat';

function targetLabel(instance) {
  return (
    instance.deploymentReference ||
    instance.observedSubject ||
    instance.targetId ||
    '--'
  );
}

function instanceTimestamp(instance) {
  return (
    instance.observedAt || instance.updatedAt || instance.createdAt || null
  );
}

/**
 * Connectivity is a SEPARATE fact from `instance.status` (certificate
 * presence, decided by a live agent's scan) - see the product note that
 * agent connectivity must never overload certificate_instances.status. A
 * location with no responsible agent (e.g. cert-manager/domain-checker
 * observations) has no connectivity concept at all, hence 'unknown' rather
 * than a misleading 'offline'.
 */
function connectivityDescriptor(instance) {
  const agent = instance.agent;
  if (!agent) {
    return { label: 'Unknown', scheme: 'gray', help: 'No agent is responsible for observing this location.' };
  }
  if (agent.livenessState === 'live') {
    return {
      label: 'Reachable',
      scheme: 'green',
      help: `${agent.name || agent.hostname || agent.agentId} last reported in.`,
    };
  }
  if (agent.livenessState === 'retired') {
    return {
      label: 'Agent retired',
      scheme: 'gray',
      help: `${agent.name || agent.hostname || agent.agentId} has been retired; this location can no longer be verified.`,
    };
  }
  return {
    label: 'Agent offline',
    scheme: 'orange',
    help: `${agent.name || agent.hostname || agent.agentId} has not reported in since ${formatDateTime(agent.lastSeenAt)}.`,
  };
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
  const connectivity = connectivityDescriptor(instance);
  return (
    <Tr>
      <Td borderColor={border} pl={indent ? 8 : undefined}>
        <Text fontSize='sm' noOfLines={1} color={indent ? muted : undefined}>
          {targetLabel(instance)}
        </Text>
      </Td>
      <Td borderColor={border}>
        <Text fontSize='sm' color={muted} noOfLines={1}>
          {locationKindLabel(instance.locationKind)}
        </Text>
      </Td>
      <Td borderColor={border}>
        <Text fontSize='sm' color={muted} noOfLines={1}>
          {instance.agent?.name || instance.agent?.hostname || instance.agent?.agentId || '--'}
        </Text>
      </Td>
      <Td borderColor={border}>
        <Tooltip label={connectivity.help} hasArrow placement='top' openDelay={250}>
          <Badge colorScheme={connectivity.scheme} variant='subtle' textTransform='none' fontSize='xs'>
            {connectivity.label}
          </Badge>
        </Tooltip>
      </Td>
      <Td borderColor={border}>
        <Text fontSize='sm' color={muted} title={formatDateTime(instanceTimestamp(instance))}>
          {formatRelativeDateTime(instanceTimestamp(instance))}
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
            <Th>Location</Th>
            <Th>Type</Th>
            <Th>Agent</Th>
            <Th>Connectivity</Th>
            <Th>Last observed</Th>
            <Th>Certificate state</Th>
          </Tr>
        </Thead>
        <Tbody>
          {groups.map(({ key, current, history, rotated }) => {
            const connectivity = connectivityDescriptor(current);
            return (
            <Fragment key={key}>
              <Tr>
                <Td borderColor={border}>
                  <Text fontSize='sm' noOfLines={1}>
                    {targetLabel(current)}
                  </Text>
                </Td>
                <Td borderColor={border}>
                  <Text fontSize='sm' color={muted} noOfLines={1}>
                    {locationKindLabel(current.locationKind)}
                  </Text>
                </Td>
                <Td borderColor={border}>
                  <Text fontSize='sm' color={muted} noOfLines={1}>
                    {current.agent?.name || current.agent?.hostname || current.agent?.agentId || '--'}
                  </Text>
                </Td>
                <Td borderColor={border}>
                  <Tooltip label={connectivity.help} hasArrow placement='top' openDelay={250}>
                    <Badge colorScheme={connectivity.scheme} variant='subtle' textTransform='none' fontSize='xs'>
                      {connectivity.label}
                    </Badge>
                  </Tooltip>
                </Td>
                <Td borderColor={border}>
                  <Text fontSize='sm' color={muted} title={formatDateTime(instanceTimestamp(current))}>
                    {formatRelativeDateTime(instanceTimestamp(current))}
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
              </Tr>
              {history.length > 0 ? (
                <Tr key={`${key}-toggle`}>
                  <Td colSpan={6} borderColor={border} pt={0} pb={2}>
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
            );
          })}
        </Tbody>
      </Table>
    </TableContainer>
  );
}

