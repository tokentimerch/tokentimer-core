import { Fragment, useState } from 'react';
import {
  Badge,
  Box,
  Button,
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
  hasEarlier = false,
  loadingEarlier = false,
  onLoadEarlier,
}) {
  const muted = useColorModeValue('gray.600', 'gray.400');
  const [expandedRun, setExpandedRun] = useState(null);

  return (
    <Box>
      <Text fontSize='sm' fontWeight='semibold' mb={3}>
        Recent runs
      </Text>
      {loading ? (
        <Text fontSize='sm' color={muted}>
          Loading run history…
        </Text>
      ) : runs.length === 0 ? (
        <Text fontSize='sm' color={muted}>
          No runs yet
        </Text>
      ) : (
        <TableContainer borderWidth='1px' borderRadius='md'>
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
              {runs.map(run => {
                const [label, color] = states[run.status] || [
                  run.status || 'Unknown',
                  'gray',
                ];
                return (
                  <Fragment key={run.run_id}>
                    <Tr>
                      <Td py={3} verticalAlign='top'>
                        <Text fontSize='sm'>{started(run.started_at)}</Text>
                        <Text fontSize='xs' color={muted} mt={1}>
                          {run.trigger === 'manual'
                            ? 'Manual'
                            : run.trigger === 'scheduled'
                              ? 'Scheduled'
                              : run.trigger || 'Unknown trigger'}{' '}
                          · {count(run.discovered_count)} found
                        </Text>
                      </Td>
                      <Td py={3} verticalAlign='top'>
                        <Badge colorScheme={color} textTransform='none'>
                          {label}
                        </Badge>
                        {run.error ? (
                          <Button
                            display='block'
                            size='xs'
                            variant='link'
                            fontSize='xs'
                            aria-label={
                              'Details for ' + started(run.started_at)
                            }
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
                              : 'Details'}
                          </Button>
                        ) : null}
                      </Td>
                      {[
                        'created_count',
                        'updated_count',
                        'detached_count',
                        'deleted_count',
                        'error_count',
                      ].map(key => (
                        <Td key={key} py={3} isNumeric verticalAlign='top'>
                          {count(run[key])}
                        </Td>
                      ))}
                    </Tr>
                    {run.error && expandedRun === run.run_id ? (
                      <Tr>
                        <Td colSpan={7} py={3} whiteSpace='normal'>
                          <Text fontSize='sm' color={muted}>
                            {run.error}
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
      {!loading && hasEarlier ? (
        <Button
          size='sm'
          variant='outline'
          mt={3}
          isLoading={loadingEarlier}
          onClick={onLoadEarlier}
        >
          Earlier runs
        </Button>
      ) : null}
    </Box>
  );
}
