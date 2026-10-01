import { useEffect, useRef, useState } from 'react';
import { Button, Text, VStack } from '@chakra-ui/react';
import apiClient from '../utils/apiClient.js';

export default function AutoSyncProvenance({ tokenId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const current = useRef(tokenId);
  current.current = tokenId;
  useEffect(() => {
    let cancelled = false;
    setData(null);
    apiClient
      .get(`/api/v1/tokens/${tokenId}/auto-sync-provenance`)
      .then(res => {
        if (!cancelled) setData(res.data);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [tokenId]);
  if (!data || (!data.configurations?.length && !data.items?.length))
    return null;
  const loadMore = async () => {
    setLoading(true);
    try {
      const res = await apiClient.get(
        `/api/v1/tokens/${tokenId}/auto-sync-provenance?before=${data.next_before}`
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
    <VStack align='stretch' spacing={1}>
      {data.configurations.map(config => (
        <Text fontSize='xs' key={config.config_id}>
          Tracked by {config.name}
        </Text>
      ))}
      {data.items.map(event => (
        <Text fontSize='xs' key={event.id}>
          {new Date(event.occurred_at).toLocaleString()} · {event.config_name} ·{' '}
          {event.event}
          {event.reason === 'configuration_deleted'
            ? ' (configuration deleted; inventory retained)'
            : ''}
        </Text>
      ))}
      {data.next_before ? (
        <Button
          size='xs'
          isLoading={loading}
          onClick={() => {
            void loadMore().catch(() => {});
          }}
        >
          Earlier provenance
        </Button>
      ) : null}
    </VStack>
  );
}
