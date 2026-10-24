// Turns a preflight job the agent refused or failed into one sentence the
// issuer wizard can show, so the dialog does not wait for a verdict that will
// never come.

const FAILED = new Set(['rejected', 'failed', 'blocked', 'cancelled']);

export function failedPreflightMessage(job) {
  if (!job || !FAILED.has(job.status)) return '';
  const code = job.errorCode || job.resultMetadata?.rejectionReason || '';
  if (code === 'issuer_not_allowlisted') {
    return 'The agent refused the check before it contacted the CA, because its enrollment rule does not name this CA config and template. Add the rule, restart TokenTimerAgent, then run the check again.';
  }
  const detail = job.errorMessage ? ` ${job.errorMessage}` : '';
  return `The agent could not run the check${code ? ` (${code})` : ''}.${detail}`;
}
