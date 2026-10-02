import { useEffect, useRef, useState } from 'react';
import {
  Badge,
  Box,
  Button,
  Grid,
  Heading,
  HStack,
  Icon,
  Text,
  VStack,
} from '@chakra-ui/react';
import { RefreshCw } from 'lucide-react';
import apiClient from '../utils/apiClient.js';
import {
  DASHBOARD_MODAL_HEADING_FONT,
  useDashboardModalProps,
} from './DashboardModalFrame.jsx';
import { DashboardModalDetailRow } from './DashboardModalDetails.jsx';

export default function AutoSyncProvenance({ tokenId, ownership }) {
  const { tokens } = useDashboardModalProps();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const current = useRef(tokenId);
  current.current = tokenId;
  useEffect(() => {
    let cancelled = false;
    setData(null);
    setShowHistory(false);
    apiClient
      .get(`/api/tokens/${tokenId}/auto-sync-provenance`)
      .then(res => {
        if (!cancelled) setData(res.data);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [tokenId]);
  const configurations = data?.configurations || [];
  const events = data?.items || [];
  const ownershipLabel = data
    ? data.managed
      ? 'Managed'
      : configurations.length
        ? 'Observed'
        : 'Manual or legacy'
    : ownership;
  if (!ownershipLabel) return null;
  const loadMore = async () => {
    setLoading(true);
    try {
      const res = await apiClient.get(
        `/api/tokens/${tokenId}/auto-sync-provenance?before=${data.next_before}`
      );
      if (current.current === tokenId)
        setData(previous => ({
          ...res.data,
          items: [...previous.items, ...res.data.items],
        }));
    } finally {
      setLoading(false);
    }
  };
  return (
    <Box
      as='section'
      aria-label='Auto-sync'
      gridColumn='1 / -1'
      minW={0}
      mb={6}
      border='1px solid'
      borderColor={tokens.border}
      borderRadius='8px'
      overflow='hidden'
    >
      <HStack
        mx={3}
        pt={2.5}
        pb={2}
        spacing={2}
        borderBottom='1px solid'
        borderColor={tokens.border}
      >
        <Icon as={RefreshCw} boxSize={4} color={tokens.muted} aria-hidden />
        <Heading
          as='h3'
          fontFamily={DASHBOARD_MODAL_HEADING_FONT}
          fontSize='sm'
          color={tokens.text}
        >
          Auto-sync
        </Heading>
      </HStack>
      <Grid mx={3} minW={0}>
        <DashboardModalDetailRow label='Ownership' tokens={tokens}>
          <Badge colorScheme={ownershipLabel === 'Managed' ? 'blue' : 'gray'}>
            {ownershipLabel}
          </Badge>
        </DashboardModalDetailRow>
        {configurations.length || events.length ? (
          <DashboardModalDetailRow label='Configurations' tokens={tokens}>
            <VStack align='stretch' spacing={1}>
              {configurations.length ? (
                configurations.map(config => (
                  <Box key={config.config_id}>
                    <Text fontSize='sm' overflowWrap='anywhere'>
                      {config.name}
                    </Text>
                    <Text
                      fontSize='xs'
                      color={tokens.muted}
                      overflowWrap='anywhere'
                    >
                      ID: {config.config_id}
                    </Text>
                  </Box>
                ))
              ) : (
                <Text fontSize='sm'>None active</Text>
              )}
              {!configurations.length &&
              events.some(event => event.reason === 'configuration_deleted') ? (
                <Text fontSize='xs' color={tokens.muted}>
                  Configuration deleted; inventory retained.
                </Text>
              ) : null}
            </VStack>
          </DashboardModalDetailRow>
        ) : null}
        {events.length ? (
          <DashboardModalDetailRow label='History' tokens={tokens}>
            <VStack align='stretch' spacing={3}>
              <Button
                size='xs'
                variant='ghost'
                alignSelf='flex-start'
                aria-expanded={showHistory}
                onClick={() => setShowHistory(value => !value)}
              >
                {showHistory ? 'Hide history' : 'Show history'}
              </Button>
              {showHistory ? (
                <>
                  {events.map(event => (
                    <Box key={event.id}>
                      <Text fontSize='sm' overflowWrap='anywhere'>
                        {event.event === 'attached'
                          ? 'Added to'
                          : 'Removed from'}{' '}
                        {event.config_name}
                      </Text>
                      <Text fontSize='xs' color={tokens.muted}>
                        {new Date(event.occurred_at).toLocaleString()}
                      </Text>
                      {event.reason === 'configuration_deleted' ? (
                        <Text fontSize='xs' color={tokens.muted}>
                          Configuration deleted; inventory retained.
                        </Text>
                      ) : null}
                    </Box>
                  ))}
                  {data.next_before ? (
                    <Button
                      size='xs'
                      alignSelf='flex-start'
                      isLoading={loading}
                      onClick={() => {
                        void loadMore().catch(() => {});
                      }}
                    >
                      Earlier history
                    </Button>
                  ) : null}
                </>
              ) : null}
            </VStack>
          </DashboardModalDetailRow>
        ) : null}
      </Grid>
    </Box>
  );
}
