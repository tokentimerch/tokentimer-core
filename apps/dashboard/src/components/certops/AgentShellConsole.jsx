import { useEffect, useMemo, useState } from 'react';
import { Box, Text } from '@chakra-ui/react';
import { useDashboardThemeColors } from '../../hooks/useDashboardTheme';
import { listAgentJobLog } from './certopsJobsApi';

const COPY =
  'Agent output is filtered for sensitive information. Avoid including secrets in diagnostic messages.';
const PAGE_LIMIT = 200;
const MAX_PAGES_PER_TICK = 5;
const VISIBLE_POLL_MS = 1000;
const HIDDEN_POLL_MS = 5000;
const ERROR_POLL_MS = 10000;

export function deliveryLabel(payload, failed = false) {
  if (failed) return 'Could not load agent output. Retrying.';
  if (!payload) return 'Waiting for output';
  if (payload.storageEnabled === false) return 'Agent log storage is disabled';
  if (payload.linesVisible === false) {
    return 'You need manager access to view agent output';
  }
  const streams = payload.streams || [];
  if (streams.some(stream => stream.status === 'abandoned')) {
    return 'Agent stopped reporting';
  }
  if (
    streams.length > 0 &&
    streams.every(stream => stream.streamingEnabled === false)
  ) {
    return 'This agent did not stream logs for this attempt';
  }
  const dropped = streams.reduce(
    (sum, stream) =>
      sum + (stream.serverDroppedLines || 0) + (stream.agentGapLines || 0),
    0
  );
  if (dropped > 0) return `Output incomplete: ${dropped} lines dropped`;
  if (streams.some(stream => stream.truncated)) return 'Log limit reached';
  if (payload.logsComplete) return 'Stream complete';
  if (
    streams.length > 0 &&
    streams.every(stream =>
      ['final', 'abandoned', 'disabled'].includes(stream.status)
    )
  ) {
    return 'Waiting for the next attempt';
  }
  return 'Waiting for output';
}

function pollDelay() {
  return typeof document !== 'undefined' &&
    document.visibilityState === 'hidden'
    ? HIDDEN_POLL_MS
    : VISIBLE_POLL_MS;
}

export default function AgentShellConsole({
  workspaceId,
  jobId,
  fetcher = listAgentJobLog,
  active = true,
}) {
  const { muted, border } = useDashboardThemeColors();
  const [payload, setPayload] = useState(null);
  const [items, setItems] = useState([]);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    setPayload(null);
    setItems([]);
    setFailed(false);
    if (!active || !workspaceId || !jobId) return undefined;
    let cancelled = false;
    let timer;
    let cursor;
    const controller = new AbortController();

    // Each tick asks only for lines after the last cursor it was given.
    const tick = async () => {
      let delay = pollDelay();
      try {
        const fresh = [];
        let page;
        let pages = 0;
        do {
          page = await fetcher(workspaceId, jobId, {
            cursor,
            limit: PAGE_LIMIT,
            signal: controller.signal,
          });
          if (cancelled) return;
          fresh.push(...(page?.items || []));
          if (page?.nextCursor) cursor = page.nextCursor;
          pages += 1;
        } while (page?.hasMore && pages < MAX_PAGES_PER_TICK);
        if (fresh.length > 0) setItems(current => [...current, ...fresh]);
        setPayload(page);
        setFailed(false);
        if (page?.logsComplete) return;
        if (page?.hasMore) delay = 0;
      } catch (_error) {
        if (cancelled) return;
        setFailed(true);
        delay = ERROR_POLL_MS;
      }
      timer = setTimeout(tick, delay);
    };
    tick();
    return () => {
      cancelled = true;
      controller.abort();
      clearTimeout(timer);
    };
  }, [active, workspaceId, jobId, fetcher]);

  const groups = useMemo(() => {
    const byAttempt = new Map();
    for (const line of items) {
      const key = line.attempt ?? line.claimId ?? '1';
      const bucket = byAttempt.get(key) || [];
      bucket.push(line);
      byAttempt.set(key, bucket);
    }
    return [...byAttempt.entries()].map(([attempt, lines]) => ({
      attempt,
      lines: [...lines].sort((a, b) => a.seq - b.seq),
    }));
  }, [items]);

  return (
    <Box
      borderWidth='1px'
      borderColor={border}
      borderRadius='md'
      px={3}
      py={2}
      fontFamily='mono'
      fontSize='xs'
      data-testid='agent-shell-console'
    >
      <Text fontSize='xs' color={muted} mb={2} role='status'>
        {deliveryLabel(payload, failed)}
      </Text>
      {groups.map(group => (
        <Box key={group.attempt} mb={2}>
          <Text color={muted}>Attempt {group.attempt}</Text>
          {group.lines.map(line => (
            <Text key={`${line.claimId}-${line.seq}`} whiteSpace='pre-wrap'>
              {line.message}
            </Text>
          ))}
        </Box>
      ))}
      <Text fontSize='xs' color={muted} mt={2}>
        {COPY}
      </Text>
    </Box>
  );
}
