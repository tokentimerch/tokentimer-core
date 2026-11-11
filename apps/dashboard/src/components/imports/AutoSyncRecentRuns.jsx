import { Fragment, useState } from 'react';
import {
  Badge,
  Box,
  Button,
  HStack,
  Table,
  TableContainer,
  Tbody,
  Td,
  Text,
  Th,
  Thead,
  Tr,
  useColorModeValue,
} from '@chakra-ui/react';
const states = {
  success: ['Succeeded', 'green'],
  partial: ['Partial', 'orange'],
  failed: ['Failed', 'red'],
  running: ['Running', 'blue'],
  superseded: ['Superseded', 'gray'],
  cancelled: ['Cancelled', 'gray'],
};
const count = value =>
  value === null ||
  value === undefined ||
  !Number.isFinite(Number(value)) ||
  Number(value) < 0
    ? '—'
    : Number(value);
function started(value) {
  const date = new Date(value);
  return value && !Number.isNaN(date.getTime())
    ? date.toLocaleString()
    : 'Unknown start';
}
export default function AutoSyncRecentRuns({
  runs = [],
  loading = false,
  error = false,
  onRetry,
  hasEarlier = false,
  loadingEarlier = false,
  onLoadEarlier,
}) {
  const muted = useColorModeValue('gray.600', 'gray.400');
  const [expandedRun, setExpandedRun] = useState(null);
  const [page, setPage] = useState(0);
  const [pageError, setPageError] = useState('');
  const [paging, setPaging] = useState(false);
  const pageSize = 5;
  const pageRuns = runs.slice(page * pageSize, (page + 1) * pageSize);
  const hasCachedEarlier = runs.length > (page + 1) * pageSize;
  async function earlier() {
    setPageError('');
    setExpandedRun(null);
    if (hasCachedEarlier) {
      setPage(value => value + 1);
      return;
    }
    setPaging(true);
    try {
      if (await onLoadEarlier?.()) setPage(value => value + 1);
    } catch {
      setPageError('Unable to load earlier runs. Please try again.');
    } finally {
      setPaging(false);
    }
  }

  return (
    <Box>
      <Text fontSize='sm' fontWeight='semibold' mb={3}>
        Recent runs
      </Text>
      {loading ? (
        <Text fontSize='sm' color={muted}>
          Loading run history…
        </Text>
      ) : error ? (
        <Box role='alert'>
          <Text fontSize='sm'>Run history could not be loaded.</Text>
          <Button size='sm' variant='outline' mt={2} onClick={onRetry}>
            Retry
          </Button>
        </Box>
      ) : runs.length === 0 ? (
        <Text fontSize='sm' color={muted}>
          No runs yet
        </Text>
      ) : (
        <TableContainer
          borderWidth='1px'
          borderRadius='md'
          sx={{
            '@media (max-width: 47.99em)': {
              table: { display: 'block', width: '100%' },
              thead: { display: 'none' },
              tbody: { display: 'block', width: '100%' },
              tr: { display: 'block', padding: 3, borderBottomWidth: '1px' },
              td: { display: 'block', padding: 1, textAlign: 'left' },
              'td[data-label]::before': {
                content: 'attr(data-label)',
                display: 'inline-block',
                fontWeight: 'semibold',
                marginRight: 2,
              },
            },
          }}
        >
          <Table size='sm' aria-label='Recent auto-sync runs' fontSize='sm'>
            <Thead>
              <Tr>
                <Th>Started</Th>
                <Th>Result</Th>
                {['Created', 'Updated', 'Detached', 'Deleted', 'Errors'].map(
                  title => (
                    <Th key={title} isNumeric>
                      {title}
                    </Th>
                  )
                )}
              </Tr>
            </Thead>
            <Tbody>
              {pageRuns.map(run => {
                const [label, color] = states[run.status] || [
                  run.status || 'Unknown',
                  'gray',
                ];
                return (
                  <Fragment key={run.run_id}>
                    <Tr>
                      <Td py={3} verticalAlign='top' data-label='Started'>
                        <Text fontSize='sm' as='span'>
                          {started(run.started_at)}
                        </Text>
                        <Text fontSize='xs' color={muted} mt={1}>
                          {run.trigger === 'manual'
                            ? 'Manual'
                            : run.trigger === 'scheduled'
                              ? 'Scheduled'
                              : run.trigger || 'Unknown trigger'}{' '}
                          · {count(run.discovered_count)} found
                        </Text>
                      </Td>
                      <Td py={3} verticalAlign='top' data-label='Result'>
                        <Badge colorScheme={color} textTransform='none'>
                          {label}
                        </Badge>
                        <Button
                          display='block'
                          size='xs'
                          variant='link'
                          fontSize='xs'
                          aria-label={`Details for ${started(run.started_at)}`}
                          aria-expanded={expandedRun === run.run_id}
                          onClick={() =>
                            setExpandedRun(previous =>
                              previous === run.run_id ? null : run.run_id
                            )
                          }
                          mt={2}
                        >
                          {expandedRun === run.run_id
                            ? 'Hide details'
                            : 'View details'}
                        </Button>
                      </Td>
                      {[
                        'created_count',
                        'updated_count',
                        'detached_count',
                        'deleted_count',
                        'error_count',
                      ].map(key => (
                        <Td
                          key={key}
                          py={3}
                          isNumeric
                          verticalAlign='top'
                          data-label={
                            {
                              created_count: 'Created',
                              updated_count: 'Updated',
                              detached_count: 'Detached',
                              deleted_count: 'Deleted',
                              error_count: 'Errors',
                            }[key]
                          }
                        >
                          {count(run[key])}
                        </Td>
                      ))}
                    </Tr>
                    {expandedRun === run.run_id ? (
                      <Tr>
                        <Td colSpan={7} py={3} whiteSpace='normal'>
                          <Text fontSize='sm' fontWeight='semibold'>
                            Run details
                          </Text>
                          {run.error ? (
                            <Text fontSize='sm' mt={2}>
                              <strong>Failure reason:</strong> {run.error}
                            </Text>
                          ) : null}
                          <Text fontSize='sm' mt={2}>
                            Run ID: {run.run_id}
                          </Text>
                          <Text fontSize='sm'>
                            Finished:{' '}
                            {run.finished_at
                              ? started(run.finished_at)
                              : 'Not recorded'}
                          </Text>
                          <Text fontSize='sm'>
                            Generation: {count(run.generation)} · Scan version:{' '}
                            {count(run.scan_version)}
                          </Text>
                          {run.settings_snapshot ? (
                            <Box mt={3}>
                              <Text fontSize='sm' fontWeight='semibold'>
                                Settings at run start
                              </Text>
                              {Object.entries(run.settings_snapshot)
                                .filter(
                                  ([, value]) =>
                                    value === null ||
                                    ['string', 'number', 'boolean'].includes(
                                      typeof value
                                    )
                                )
                                .map(([key, value]) => (
                                  <Text key={key} fontSize='sm'>
                                    {key.replace(/_/g, ' ')}:{' '}
                                    {value === null ? 'Not set' : String(value)}
                                  </Text>
                                ))}
                              <Box as='details' mt={2}>
                                <Box
                                  as='summary'
                                  fontSize='sm'
                                  fontWeight='semibold'
                                  cursor='pointer'
                                >
                                  Technical settings
                                </Box>
                                <Box
                                  as='pre'
                                  fontSize='xs'
                                  whiteSpace='pre-wrap'
                                  overflowWrap='anywhere'
                                  mt={2}
                                >
                                  {JSON.stringify(
                                    run.settings_snapshot,
                                    null,
                                    2
                                  )}
                                </Box>
                              </Box>
                            </Box>
                          ) : null}
                          <Text fontSize='xs' color={muted} mt={2}>
                            This saved summary does not contain an item-by-item
                            change log.
                          </Text>
                        </Td>
                      </Tr>
                    ) : null}
                  </Fragment>
                );
              })}
            </Tbody>
          </Table>
        </TableContainer>
      )}
      {!loading && runs.length > 0 ? (
        <HStack mt={3} justify='space-between'>
          <Button
            size='sm'
            variant='outline'
            isDisabled={page === 0 || paging || loadingEarlier}
            onClick={() => {
              setPage(value => value - 1);
              setExpandedRun(null);
              setPageError('');
            }}
          >
            Newer runs
          </Button>
          <Text fontSize='xs' color={muted}>
            Page {page + 1} · Up to 5 runs
          </Text>
          <Button
            size='sm'
            variant='outline'
            isDisabled={!hasCachedEarlier && !hasEarlier}
            isLoading={paging || loadingEarlier}
            onClick={earlier}
          >
            Earlier runs
          </Button>
        </HStack>
      ) : null}
      {pageError ? (
        <Text role='alert' fontSize='sm' mt={2}>
          {pageError}
        </Text>
      ) : null}
    </Box>
  );
}
