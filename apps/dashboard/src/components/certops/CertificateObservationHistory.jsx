import { useEffect, useState } from 'react';
import {
  Box,
  Button,
  HStack,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalHeader,
  ModalOverlay,
  Spinner,
  Select,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Text,
  VStack,
} from '@chakra-ui/react';
import apiClient from '../../utils/apiClient';
import { formatDateTime } from './certopsJobsFormat';
import CertOpsBadge from './CertOpsBadge.jsx';
import {
  CertOpsSortableHeader,
  CertOpsMobileFieldLabel,
  useCertOpsResponsiveTableStyles,
} from './CertOpsResponsiveTable.jsx';
import { useCertOpsCanManage } from './useCertOps.js';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';

const PAGE_SIZE = 10;
const VERDICTS = {
  good: 'Not revoked',
  revoked: 'Revoked',
  issuer_revoked: 'CA revoked',
  unknown: 'Revocation unknown',
  not_configured: 'Revocation not configured',
  disabled: 'Revocation disabled',
  invalid_observation: 'Invalid revocation observation',
};

export default function CertificateObservationHistory({
  workspaceId,
  certificateId,
  fingerprintSha256,
  enabled = true,
  onAvailabilityChange,
}) {
  const {
    overlayProps,
    headerProps,
    bodyProps,
    closeButtonProps,
    outlineButtonProps,
  } = useDashboardModalProps();
  const tableStyles = useCertOpsResponsiveTableStyles();
  const canManage = useCertOpsCanManage();
  const { workspaceId: activeWorkspaceId } = useWorkspace();
  const canSortTopology = canManage && activeWorkspaceId === workspaceId;
  const [sortBy, setSortBy] = useState('');
  const [sortDirection, setSortDirection] = useState('desc');
  const [offset, setOffset] = useState(0);
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [hasHistory, setHasHistory] = useState(false);
  const [isOpen, setIsOpen] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const effectiveSortBy =
    !canSortTopology && ['source', 'location'].includes(sortBy) ? '' : sortBy;

  useEffect(() => {
    setOffset(0);
    setSortBy('');
    setSortDirection('desc');
    setHasHistory(false);
    setIsOpen(false);
  }, [workspaceId, certificateId, fingerprintSha256, enabled]);
  useEffect(() => {
    if (!canSortTopology && ['source', 'location'].includes(sortBy)) {
      setOffset(0);
      setSortBy('');
      setSortDirection('desc');
    }
  }, [canSortTopology, sortBy]);
  useEffect(() => {
    onAvailabilityChange?.(hasHistory);
  }, [hasHistory, onAvailabilityChange]);
  useEffect(() => {
    if (!enabled || !workspaceId || !certificateId || !fingerprintSha256)
      return undefined;
    const controller = new AbortController();
    setLoading(true);
    setError('');
    setItems([]);
    apiClient
      .get(
        `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/certops/certificates/${encodeURIComponent(certificateId)}/observations`,
        {
          params: {
            limit: PAGE_SIZE,
            offset,
            ...(effectiveSortBy
              ? { sortBy: effectiveSortBy, sortDirection }
              : {}),
            ...(fingerprintSha256 ? { fingerprint: fingerprintSha256 } : {}),
          },
          signal: controller.signal,
        }
      )
      .then(({ data }) => {
        if (controller.signal.aborted) return;
        const nextItems = Array.isArray(data?.items) ? data.items : [];
        setItems(nextItems);
        if (offset === 0) setHasHistory(nextItems.length > 0);
      })
      .catch(err => {
        if (!controller.signal.aborted)
          setError(
            err?.response?.status === 409
              ? 'Certificate changed. Reload its details.'
              : 'Could not load observation history.'
          );
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [
    workspaceId,
    certificateId,
    fingerprintSha256,
    offset,
    enabled,
    attempt,
    effectiveSortBy,
    sortDirection,
  ]);

  function changeSort(field) {
    setOffset(0);
    if (sortBy === field) {
      setSortDirection(direction => (direction === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortBy(field);
      setSortDirection(field === 'observedAt' ? 'desc' : 'asc');
    }
  }

  function sortHeader(label, field, allowed = true) {
    return allowed ? (
      <CertOpsSortableHeader
        label={label}
        sortKey={field}
        sort={{ key: sortBy, direction: sortDirection }}
        onSort={changeSort}
      />
    ) : (
      <Th scope='col'>{label}</Th>
    );
  }

  if (!hasHistory) return null;
  return (
    <>
      <Button {...outlineButtonProps} size='xs' onClick={() => setIsOpen(true)}>
        Observation history
      </Button>
      <Modal
        isOpen={isOpen}
        onClose={() => setIsOpen(false)}
        size='4xl'
        scrollBehavior='inside'
        isCentered
      >
        <ModalOverlay {...overlayProps} />
        <DashboardModalFrame>
          <ModalHeader {...headerProps}>
            <DashboardModalTitle>Observation history</DashboardModalTitle>
          </ModalHeader>
          <ModalCloseButton {...closeButtonProps} />
          <ModalBody {...bodyProps} pb={6}>
            <DashboardModalDescription mb={4}>
              Observations for this registration’s current fingerprint. Previous
              fingerprints are excluded.
            </DashboardModalDescription>
            {loading ? (
              <Spinner size='sm' aria-label='Loading observation history' />
            ) : error ? (
              <VStack align='start'>
                <Text role='alert'>{error}</Text>
                <Button
                  size='sm'
                  onClick={() => setAttempt(value => value + 1)}
                >
                  Retry
                </Button>
                {offset > 0 ? (
                  <Button
                    size='sm'
                    onClick={() =>
                      setOffset(value => Math.max(0, value - PAGE_SIZE))
                    }
                  >
                    Previous
                  </Button>
                ) : null}
              </VStack>
            ) : (
              <VStack align='stretch' spacing={3}>
                <HStack display={{ base: 'flex', lg: 'none' }}>
                  <Select
                    aria-label='Sort observations by'
                    size='sm'
                    value={effectiveSortBy}
                    onChange={event => {
                      setOffset(0);
                      setSortBy(event.target.value);
                      setSortDirection(
                        event.target.value === 'observedAt' ? 'desc' : 'asc'
                      );
                    }}
                  >
                    <option value=''>Recently recorded</option>
                    <option value='observedAt'>Observed</option>
                    {canSortTopology ? (
                      <option value='source'>Observer</option>
                    ) : null}
                    {canSortTopology ? (
                      <option value='location'>Location</option>
                    ) : null}
                  </Select>
                  <Select
                    aria-label='Observation sort direction'
                    size='sm'
                    value={sortDirection}
                    isDisabled={!effectiveSortBy}
                    onChange={event => {
                      setOffset(0);
                      setSortDirection(event.target.value);
                    }}
                  >
                    <option value='asc'>Ascending</option>
                    <option value='desc'>Descending</option>
                  </Select>
                </HStack>
                {!items.length ? (
                  <Text>No more observations.</Text>
                ) : (
                  <Box {...tableStyles.tableContainerProps}>
                    <Table {...tableStyles.tableProps}>
                      <Thead {...tableStyles.theadProps}>
                        <Tr>
                          {sortHeader(
                            'Observer / source',
                            'source',
                            canSortTopology
                          )}
                          {sortHeader('Observed', 'observedAt')}
                          {sortHeader('Location', 'location', canSortTopology)}
                          <Th scope='col'>Revocation</Th>
                          <Th scope='col'>Details</Th>
                        </Tr>
                      </Thead>
                      <Tbody {...tableStyles.tbodyProps}>
                        {items.map(item => {
                          const m = item.metadata || {};
                          const verdict =
                            m.observedRevocationVerdict ||
                            m.observedRevocationState;
                          return (
                            <Tr key={item.id} {...tableStyles.rowProps}>
                              <Td
                                {...tableStyles.primaryCellProps}
                                overflowWrap='anywhere'
                              >
                                <CertOpsMobileFieldLabel>
                                  Observer
                                </CertOpsMobileFieldLabel>
                                {m.agentId || m.source || 'Unavailable'}
                              </Td>
                              <Td {...tableStyles.cellProps}>
                                <CertOpsMobileFieldLabel>
                                  Observed
                                </CertOpsMobileFieldLabel>
                                {formatDateTime(
                                  item.observedAt || item.createdAt
                                )}
                              </Td>
                              <Td
                                {...tableStyles.cellProps}
                                overflowWrap='anywhere'
                              >
                                <CertOpsMobileFieldLabel>
                                  Location
                                </CertOpsMobileFieldLabel>
                                {m.targetHost ||
                                m.locationSlot ||
                                m.filePath ? (
                                  <>
                                    {m.targetHost || ''}
                                    {m.targetHost &&
                                    (m.locationSlot || m.filePath)
                                      ? ' / '
                                      : ''}
                                    {m.locationSlot || m.filePath || ''}
                                  </>
                                ) : (
                                  'Unavailable'
                                )}
                              </Td>
                              <Td {...tableStyles.cellProps}>
                                <CertOpsMobileFieldLabel>
                                  Revocation
                                </CertOpsMobileFieldLabel>
                                <CertOpsBadge
                                  colorScheme={
                                    ['revoked', 'issuer_revoked'].includes(
                                      verdict
                                    )
                                      ? 'red'
                                      : verdict === 'good'
                                        ? 'green'
                                        : 'gray'
                                  }
                                >
                                  {VERDICTS[verdict] ||
                                    'Revocation not reported'}
                                </CertOpsBadge>
                              </Td>
                              <Td {...tableStyles.actionCellProps}>
                                <Box as='details'>
                                  <Box as='summary' cursor='pointer'>
                                    View details
                                  </Box>
                                  <VStack align='start' spacing={1} mt={2}>
                                    {m.fingerprintSha256 ? (
                                      <Text
                                        fontSize='sm'
                                        overflowWrap='anywhere'
                                      >
                                        SHA-256: {m.fingerprintSha256}
                                      </Text>
                                    ) : null}
                                    {m.observedRevocationCheckedAt ? (
                                      <Text fontSize='sm'>
                                        Checked:{' '}
                                        {formatDateTime(
                                          m.observedRevocationCheckedAt
                                        )}
                                      </Text>
                                    ) : null}
                                    {m.observedRevocationValidUntil ? (
                                      <Text fontSize='sm'>
                                        Evidence valid until:{' '}
                                        {formatDateTime(
                                          m.observedRevocationValidUntil
                                        )}
                                      </Text>
                                    ) : null}
                                    {m.observedRevocationDetail ? (
                                      <Text fontSize='sm'>
                                        {m.observedRevocationDetail}
                                      </Text>
                                    ) : null}
                                    {!m.fingerprintSha256 &&
                                    !m.observedRevocationCheckedAt &&
                                    !m.observedRevocationValidUntil &&
                                    !m.observedRevocationDetail ? (
                                      <Text fontSize='sm'>
                                        No additional details.
                                      </Text>
                                    ) : null}
                                  </VStack>
                                </Box>
                              </Td>
                            </Tr>
                          );
                        })}
                      </Tbody>
                    </Table>
                  </Box>
                )}
                <HStack>
                  <Button
                    size='sm'
                    isDisabled={offset === 0}
                    onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
                  >
                    Previous
                  </Button>
                  <Button
                    size='sm'
                    isDisabled={items.length < PAGE_SIZE}
                    onClick={() => setOffset(offset + PAGE_SIZE)}
                  >
                    Next
                  </Button>
                </HStack>
              </VStack>
            )}
          </ModalBody>
        </DashboardModalFrame>
      </Modal>
    </>
  );
}
