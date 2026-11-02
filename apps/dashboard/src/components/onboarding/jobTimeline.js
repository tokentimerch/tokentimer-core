// Builds the operator-facing timeline of one CertOps job from what the server
// recorded: the job's own timestamps, its event log, its evidence and the
// agent output lines. Nothing here is guessed. A step that has no record is
// simply not listed.

import {
  evidenceTypeLabel,
  eventTypeLabel,
  jobStatusLabel,
} from '../certops/certopsJobsFormat.js';

export const FINAL_JOB_STATUSES = new Set([
  'succeeded',
  'failed',
  'rejected',
  'cancelled',
  'dry_run_complete',
  'orphaned_unknown_effect',
  'blocked',
]);

export const isJobFinal = status =>
  FINAL_JOB_STATUSES.has(String(status || '').toLowerCase());

const FAILED_STATUSES = new Set([
  'failed',
  'rejected',
  'orphaned_unknown_effect',
  'blocked',
]);

// Agent output milestones, matched on the message the agent really logged.
// Only the first matching line of each kind is listed, with its own time.
const AGENT_MILESTONES = [
  {
    id: 'dns',
    label: 'DNS challenge',
    test: /\b(dns|challenge|txt record)\b/i,
  },
  {
    id: 'order',
    label: 'Order validated',
    test: /\bACME order (succeeded|completed|finished)\b/i,
  },
  {
    id: 'written',
    label: 'Certificate written',
    test: /\bdeploy(?:ed)? succeeded\b|\bcertificate (?:written|stored|bound)\b/i,
  },
  {
    id: 'reload',
    label: 'Service reloaded',
    test: /\breload succeeded\b|\breloaded\b/i,
  },
  {
    id: 'verified',
    label: 'Certificate verified',
    test: /\bverify succeeded\b|\bverified\b/i,
  },
];

const ms = value => {
  const t = new Date(value).getTime();
  return Number.isFinite(t) ? t : 0;
};

function agentLineText(line) {
  return String(line?.message || line?.msg || '').trim();
}

function agentLineLevel(line) {
  return String(line?.level || line?.status || 'info').toLowerCase();
}

/**
 * @param {object} input
 * @param {object|null} input.job            job row from the API
 * @param {object[]} [input.logEntries]      /log items
 * @param {object[]} [input.evidence]        /evidence items
 * @param {object[]} [input.agentLines]      /agent-log items
 * @returns {Array<{id:string,at:string|null,label:string,detail:string,status:'done'|'failed'|'active'|'waiting'|'info',source:string}>}
 */
export function buildJobTimeline({
  job,
  logEntries = [],
  evidence = [],
  agentLines = [],
} = {}) {
  if (!job) return [];
  const events = [];
  const push = event => events.push({ detail: '', ...event });

  if (job.createdAt) {
    push({
      id: 'created',
      at: job.createdAt,
      label: 'Request created',
      status: 'done',
      source: 'job',
    });
  }
  if (job.approvedAt) {
    push({
      id: 'approved',
      at: job.approvedAt,
      label: 'Approved',
      detail: job.approvedByDisplayName
        ? `By ${job.approvedByDisplayName}`
        : '',
      status: 'done',
      source: 'job',
    });
  }
  if (job.startedAt) {
    push({
      id: 'picked-up',
      at: job.startedAt,
      label: 'Picked up by the agent',
      status: 'done',
      source: 'job',
    });
  }

  // Job events. The terminal event is covered by the finish row below.
  for (const entry of logEntries) {
    if (!entry?.createdAt) continue;
    if (/^job\.(completed|failed)$/.test(entry.eventType || '')) continue;
    push({
      id: `log-${entry.id}`,
      at: entry.createdAt,
      label: eventTypeLabel(entry.eventType),
      detail: entry.message || '',
      status: /rejected|cancelled|invalidated/.test(entry.eventType || '')
        ? 'failed'
        : 'info',
      source: 'event',
    });
  }

  const seen = new Set();
  for (const line of agentLines) {
    const message = agentLineText(line);
    if (!message) continue;
    if (agentLineLevel(line) === 'error') {
      push({
        id: `agent-error-${line.seq ?? message}`,
        at: line.ts || line.createdAt || null,
        label: 'Agent reported an error',
        detail: message,
        status: 'failed',
        source: 'agent',
      });
      continue;
    }
    for (const milestone of AGENT_MILESTONES) {
      if (seen.has(milestone.id) || !milestone.test.test(message)) continue;
      seen.add(milestone.id);
      push({
        id: `agent-${milestone.id}`,
        at: line.ts || line.createdAt || null,
        label: milestone.label,
        detail: message,
        status: 'done',
        source: 'agent',
      });
    }
  }

  for (const item of evidence) {
    const at = item?.observedAt || item?.createdAt;
    if (!at) continue;
    push({
      id: `evidence-${item.id}`,
      at,
      label: evidenceTypeLabel(item.evidenceType),
      detail:
        (typeof item.metadata?.summary === 'string' && item.metadata.summary) ||
        '',
      status: /failed|denied|rejected/.test(item.evidenceType || '')
        ? 'failed'
        : 'info',
      source: 'evidence',
    });
  }

  const status = String(job.status || '').toLowerCase();
  if (isJobFinal(status)) {
    push({
      id: 'finished',
      at: job.completedAt || job.updatedAt || null,
      label: `Finished: ${jobStatusLabel(status)}`,
      detail: job.errorMessage || '',
      status: FAILED_STATUSES.has(status) ? 'failed' : 'done',
      source: 'job',
    });
  } else {
    const waiting =
      status === 'pending_approval'
        ? 'Waiting for approval'
        : status === 'approved' || status === 'pending'
          ? 'Waiting for an agent to pick it up'
          : 'Running on the agent';
    push({
      id: 'now',
      at: null,
      label: waiting,
      status:
        status === 'running' || status === 'claimed' ? 'active' : 'waiting',
      source: 'job',
    });
  }

  // Oldest first; rows without a time (the live row) stay last.
  return events
    .map((event, index) => ({ event, index }))
    .sort((a, b) => {
      const at = a.event.at ? ms(a.event.at) : Infinity;
      const bt = b.event.at ? ms(b.event.at) : Infinity;
      if (at !== bt) return at - bt;
      return a.index - b.index;
    })
    .map(entry => entry.event);
}

/** HH:MM:SS in the viewer's locale, for a compact per-row time. */
export function formatClock(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

/** Full date and time for the row's tooltip and screen readers. */
export function formatStamp(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}
