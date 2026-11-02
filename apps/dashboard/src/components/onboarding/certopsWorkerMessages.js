// Renewals, AD CS enrollment polling and rollout requests are all driven by
// the CertOps worker. Nothing else reports whether it is running, so the
// summary carries two derived signals and the guide says what they mean.

export const WORKER_NOTE =
  'Renewals and pending enrollments need the CertOps worker to be running (the worker-certops service in Compose, the certops cron job in Helm).';

const count = value => {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
};

/** Text for the AD CS step, or null when nothing is overdue (or an older API). */
export function overdueEnrollmentsMessage(certops, now = Date.now()) {
  const overdue = certops?.adcs?.enrollments?.overdue;
  const n = count(overdue?.count);
  if (n === 0) return null;
  const since = Date.parse(overdue.oldestDueAt || '');
  const minutes = Number.isFinite(since)
    ? Math.max(1, Math.floor((now - since) / 60000))
    : null;
  const subject = n === 1 ? '1 enrollment is' : `${n} enrollments are`;
  const age = minutes === null ? '' : ` by ${minutes} min`;
  const pronoun = n === 1 ? 'It' : 'They';
  return `${subject} overdue${age}. ${pronoun} will not progress without a running CertOps worker.`;
}

/** Text for the distribution and verify steps, or null when nothing waits. */
export function outboxBacklogMessage(certops) {
  const n = count(certops?.distribution?.outboxBacklog?.count);
  if (n === 0) return null;
  return n === 1
    ? '1 CertOps notification or rollout request is waiting for the worker.'
    : `${n} CertOps notifications or rollout requests are waiting for the worker.`;
}
