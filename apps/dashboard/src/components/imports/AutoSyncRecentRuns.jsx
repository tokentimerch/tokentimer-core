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
  return (
    <Box>
      <Text fontSize='sm' fontWeight='semibold' mb={3}>
        Recent runs
      </Text>
      {loading ? (
        <Text fontSize='sm' color='gray.500'>
          Loading run history…
        </Text>
      ) : runs.length === 0 ? (
        <Text fontSize='sm' color='gray.500'>
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
                  <Tr key={run.run_id}>
                    <Td py={3} verticalAlign='top'>
                      <Text fontSize='sm'>{started(run.started_at)}</Text>
                      <Text fontSize='xs' color='gray.500' mt={1}>
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
                        <Text
                          fontSize='xs'
                          color='red.500'
                          whiteSpace='normal'
                          maxW='xs'
                          mt={2}
                        >
                          {run.error}
                        </Text>
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
