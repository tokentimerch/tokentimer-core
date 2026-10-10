import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Badge,
  Box,
  HStack,
  Text,
  VStack,
  useColorModeValue,
} from '@chakra-ui/react';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { listAgentJobLog } from './certopsJobsApi';

const PAGE_LIMIT = 200;
const MAX_PAGES_PER_TICK = 5;
const VISIBLE_POLL_MS = 700;
const HIDDEN_POLL_MS = 5000;
const ERROR_POLL_MS = 10000;

const STATUS_LABEL = {
  connecting: 'Connecting',
  streaming: 'Streaming',
  retrying: 'Reconnecting',
  succeeded: 'Succeeded',
  failed: 'Failed',
  cancelled: 'Cancelled',
  rejected: 'Rejected',
  pending: 'Queued',
  claimed: 'Claimed',
  running: 'Running',
  complete: 'Complete',
  incomplete: 'Incomplete',
  disabled: 'Disabled',
  forbidden: 'Restricted',
};

function toneForStatus(status) {
  const s = String(status || '').toLowerCase();
  if (
    s.includes('fail') ||
    s.includes('error') ||
    s.includes('reject') ||
    s.includes('abandon') ||
    s === 'forbidden'
  ) {
    return 'danger';
  }
  if (s === 'incomplete') {
    return 'warning';
  }
  if (
    s.includes('succeed') ||
    s === 'completed' ||
    s === 'complete' ||
    s === 'final'
  ) {
    return 'success';
  }
  if (
    s.includes('running') ||
    s.includes('stream') ||
    s === 'claimed' ||
    s === 'connecting'
  ) {
    return 'info';
  }
  return 'neutral';
}

/** Strip logger chrome so phase heuristics see the bare agent message. */
function lineBodyText(line) {
  const raw = String(line?.msg || line?.message || '').trim();
  return raw
    .replace(/^\d{4}-\d{2}-\d{2}T\S+\s+/i, '')
    .replace(/^tokentimer-agent:\s*/i, '')
    .trim();
}

/**
 * POC shell tones: start white, execution blue, success green, failure red.
 * Prefer level + message phase over the stream status string (almost always "info").
 */
export function toneForLine(line) {
  const level = String(line?.status || line?.level || '').toLowerCase();
  const body = lineBodyText(line);

  if (
    level === 'error' ||
    level === 'warn' ||
    /\b(fail(?:ed|ure)?|error|reject(?:ed)?|abandon(?:ed)?)\b/i.test(body)
  ) {
    if (!/\bsucceed(?:ed|s)?\b/i.test(body)) return 'danger';
  }
  if (
    /\b(succeed(?:ed|s)?|success|completed?|dry[_\s-]?run)\b/i.test(body) ||
    level === 'success'
  ) {
    return 'success';
  }
  if (
    /^(Starting\b|lease claimed\b|claiming\b|Waiting\b|Queued\b|Connecting\b)/i.test(
      body
    ) ||
    level === 'claim'
  ) {
    return 'neutral';
  }
  // Execution / progress lines (level info and anything else).
  return 'info';
}

function streamDroppedLines(streams) {
  return (streams || []).reduce(
    (sum, stream) =>
      sum + (stream.serverDroppedLines || 0) + (stream.agentGapLines || 0),
    0
  );
}

export function deliveryLabel(payload, failed = false) {
  if (failed) return 'Could not load agent output. Retrying.';
  if (!payload) return 'Waiting for output';
  if (payload.storageEnabled === false) return 'Agent log storage is disabled';
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
  const dropped = streamDroppedLines(streams);
  if (dropped > 0) return `Output incomplete: ${dropped} lines dropped`;
  if (streams.some(stream => stream.truncated)) return 'Log limit reached';
  if (payload.logsComplete) {
    return payload.linesVisible === false
      ? 'Stream complete (log text requires manager access)'
      : 'Stream complete';
  }
  if (
    streams.length > 0 &&
    streams.every(stream =>
      ['final', 'abandoned', 'disabled'].includes(stream.status)
    )
  ) {
    return 'Waiting for the next attempt';
  }
  if (payload.linesVisible === false) {
    return 'Output is streaming (log text requires manager access)';
  }
  return 'Waiting for output';
}

function statusHintFromPayload(payload, failed) {
  if (failed) return 'retrying';
  if (!payload) return 'connecting';
  if (payload.storageEnabled === false) return 'disabled';
  const streams = payload.streams || [];
  if (streams.some(stream => stream.status === 'abandoned')) return 'failed';
  const dropped = streamDroppedLines(streams);
  if (payload.logsComplete) {
    if (dropped > 0) return 'incomplete';
    const job = String(payload.jobStatus || '').toLowerCase();
    if (job === 'succeeded' || job === 'success') return 'succeeded';
    if (job === 'failed') return 'failed';
    if (job === 'cancelled') return 'cancelled';
    if (job === 'rejected') return 'rejected';
    return 'complete';
  }
  if (streams.some(stream => stream.status === 'streaming')) return 'streaming';
  if (streams.some(stream => stream.status === 'open')) return 'running';
  if (streams.length > 0) return 'streaming';
  return 'connecting';
}

function pollDelay() {
  return typeof document !== 'undefined' &&
    document.visibilityState === 'hidden'
    ? HIDDEN_POLL_MS
    : VISIBLE_POLL_MS;
}

function entryTimeMs(entry) {
  const raw = entry?.ts || entry?.createdAt;
  if (!raw) return 0;
  const ms = new Date(raw).getTime();
  return Number.isFinite(ms) ? ms : 0;
}

/**
 * Render one line in packages/agent createAgentLogger shape:
 *   2026-10-06T08:43:53.806Z tokentimer-agent: lease claimed {...}
 */
export function formatConsoleLine(entry) {
  const ms = entryTimeMs(entry);
  const iso =
    ms > 0 ? new Date(ms).toISOString() : new Date(0).toISOString();

  let raw = String(entry?.message || entry?.eventType || '').trim();
  const agentMatch = raw.match(/^\[agent:([^\]]+)\]\s*/i);
  const agent = agentMatch?.[1] || entry?.metadata?.executorId || null;
  if (agentMatch) raw = raw.slice(agentMatch[0].length).trim();

  const level = String(entry?.level || entry?.status || 'info').toLowerCase();
  const id =
    entry?.id ||
    (entry?.claimId != null && entry?.seq != null
      ? `${entry.claimId}-${entry.seq}`
      : `${iso}:${raw}`);

  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(raw)) {
    return { ts: iso, agent, status: level, msg: raw, id, sortMs: ms };
  }
  if (/^tokentimer-agent:\s*/i.test(raw)) {
    const msg = `${iso} ${raw}`;
    return { ts: iso, agent, status: level, msg, id, sortMs: ms };
  }
  const msg = `${iso} tokentimer-agent: ${raw}`;
  return { ts: iso, agent, status: level, msg, id, sortMs: ms };
}

/**
 * Operator-facing agent console. Visual design matches the Enterprise demo
 * POC (dark terminal shell, status badge, live cursor). Lines use the
 * tokentimer-agent stderr/stdout shape and stream from the production
 * agent-log API (cursor polling).
 */
export default function AgentShellConsole({
  workspaceId,
  jobId,
  title = 'Agent output',
  seedLines = [],
  staticEntries = null,
  fetcher = listAgentJobLog,
  active = true,
  pollMs,
  maxHeight = '280px',
  onComplete,
}) {
  const { muted, border, text, dashboard } = useDashboardTheme();
  const shellBg = useColorModeValue('#0f172a', '#020617');
  const shellBorder = useColorModeValue('rgba(15, 23, 42, 0.18)', border);
  const lineMuted = useColorModeValue('#64748b', '#94a3b8');
  const lineBody = useColorModeValue('#e2e8f0', '#f1f5f9');
  const lineSuccess = useColorModeValue('#4ade80', '#86efac');
  const lineDanger = useColorModeValue('#f87171', '#fca5a5');
  const lineInfo = useColorModeValue('#38bdf8', '#7dd3fc');
  const cursorColor = dashboard?.accent?.interactiveForeground || lineInfo;

  const [payload, setPayload] = useState(null);
  const [items, setItems] = useState([]);
  const [failed, setFailed] = useState(false);
  const bottomRef = useRef(null);
  const doneRef = useRef(false);
  const useStatic = Array.isArray(staticEntries);

  const statusHint = useStatic
    ? (() => {
        const last = staticEntries[staticEntries.length - 1];
        return last
          ? String(last.status || last.level || 'succeeded')
          : staticEntries.length
            ? 'streaming'
            : 'connecting';
      })()
    : statusHintFromPayload(payload, failed);

  const displayLines = useMemo(() => {
    if (useStatic) {
      return staticEntries
        .map(formatConsoleLine)
        .filter(line => line.msg)
        .sort((a, b) => {
          if (a.sortMs !== b.sortMs) return a.sortMs - b.sortMs;
          return String(a.id).localeCompare(String(b.id));
        });
    }
    const fromApi = [...items]
      .sort((a, b) => {
        const aSeq = Number(a.seq) || 0;
        const bSeq = Number(b.seq) || 0;
        if (a.attempt !== b.attempt) {
          return (Number(a.attempt) || 0) - (Number(b.attempt) || 0);
        }
        if (aSeq !== bSeq) return aSeq - bSeq;
        return entryTimeMs(a) - entryTimeMs(b);
      })
      .map(formatConsoleLine)
      .filter(line => line.msg);
    if (fromApi.length) return fromApi;
    return seedLines.map((msg, i) => {
      const iso = new Date(
        Date.now() - (seedLines.length - i) * 400
      ).toISOString();
      const line = /^\d{4}-\d{2}-\d{2}T/.test(msg)
        ? msg
        : `${iso} tokentimer-agent: ${msg}`;
      return {
        ts: iso,
        agent: null,
        status: 'info',
        msg: line,
        id: `seed-${i}`,
        sortMs: Date.parse(iso) || 0,
      };
    });
  }, [items, seedLines, staticEntries, useStatic]);

  useEffect(() => {
    if (useStatic) return undefined;
    setPayload(null);
    setItems([]);
    setFailed(false);
    doneRef.current = false;
    if (!active || !workspaceId || !jobId) return undefined;
    let cancelled = false;
    let timer;
    let cursor;
    const controller = new AbortController();

    const tick = async () => {
      let delay = pollMs ?? pollDelay();
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
        // Drain remaining pages even after the job finishes; logsComplete alone
        // must not stop while hasMore still points at unread ingest rows.
        if (page?.logsComplete && !page?.hasMore) {
          if (!doneRef.current) {
            doneRef.current = true;
            onComplete?.(page);
          }
          return;
        }
        if (page?.hasMore) delay = 0;
      } catch (_error) {
        if (cancelled) return;
        setFailed(true);
        delay = ERROR_POLL_MS;
      }
      if (!cancelled && !doneRef.current) {
        timer = setTimeout(tick, delay);
      }
    };
    tick();
    return () => {
      cancelled = true;
      controller.abort();
      clearTimeout(timer);
    };
  }, [active, workspaceId, jobId, fetcher, pollMs, onComplete, useStatic]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView?.({ behavior: 'smooth', block: 'end' });
  }, [displayLines.length, displayLines[displayLines.length - 1]?.id]);

  const badgeTone = toneForStatus(statusHint);
  const badgeScheme =
    badgeTone === 'success'
      ? 'green'
      : badgeTone === 'danger'
        ? 'red'
        : badgeTone === 'info'
          ? 'blue'
          : badgeTone === 'warning'
            ? 'orange'
            : 'gray';

  const colorForLine = line => {
    const tone = toneForLine(line);
    if (tone === 'success') return lineSuccess;
    if (tone === 'danger') return lineDanger;
    if (tone === 'info') return lineInfo;
    return lineBody;
  };

  const live =
    !useStatic &&
    ['streaming', 'running', 'connecting', 'claimed', 'pending'].includes(
      statusHint
    );

  return (
    <VStack
      align='stretch'
      spacing={2}
      w='100%'
      data-testid='agent-shell-console'
    >
      <HStack justify='space-between' align='center'>
        <HStack spacing={2} align='center'>
          <Box
            w='8px'
            h='8px'
            borderRadius='full'
            bg={
              badgeTone === 'success'
                ? lineSuccess
                : badgeTone === 'danger'
                  ? lineDanger
                  : cursorColor
            }
            boxShadow={
              live ? `0 0 0 3px ${cursorColor}33` : 'none'
            }
          />
          <Text fontSize='sm' fontWeight='semibold' color={text}>
            {title}
          </Text>
        </HStack>
        <Badge
          colorScheme={badgeScheme}
          variant='subtle'
          fontSize='0.7em'
          role='status'
        >
          {STATUS_LABEL[statusHint] || statusHint}
        </Badge>
      </HStack>
      <Box
        bg={shellBg}
        borderRadius='12px'
        border='1px solid'
        borderColor={shellBorder}
        fontFamily='ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace'
        fontSize='12px'
        lineHeight='1.7'
        px={3.5}
        py={3}
        maxH={maxHeight}
        overflowY='auto'
        whiteSpace='pre-wrap'
        position='relative'
      >
        <Text fontSize='10px' color={lineMuted} mb={2} letterSpacing='0.04em'>
          {displayLines[0]?.agent
            ? `HOST  ${displayLines[0].agent}`
            : 'HOST  tokentimer-agent'}
        </Text>
        {displayLines.length === 0 ? (
          <Text color={lineMuted} role='status'>
            {deliveryLabel(payload, failed) === 'Waiting for output'
              ? 'Waiting for agent output...'
              : deliveryLabel(payload, failed)}
          </Text>
        ) : (
          displayLines.map(line => (
            <Box
              key={line.id}
              as='div'
              color={colorForLine(line)}
              wordBreak='break-word'
            >
              {line.msg}
            </Box>
          ))
        )}
        {live ? (
          <Box as='span' color={cursorColor} aria-hidden>
            ▍
          </Box>
        ) : null}
        <div ref={bottomRef} />
      </Box>
      {payload &&
      (payload.storageEnabled === false || payload.linesVisible === false) ? (
        <Text fontSize='xs' color={muted}>
          {deliveryLabel(payload, false)}
        </Text>
      ) : null}
    </VStack>
  );
}
