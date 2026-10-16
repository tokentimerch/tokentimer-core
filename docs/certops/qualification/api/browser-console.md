# Browser execution-console qualification

The `browser-agent-console` suite runs Chromium against the actual dashboard, authenticated API and PostgreSQL fixture. A genuinely registered protocol agent claims a noop and submits public diagnostic lines plus generated secret sentinels. It does not run an installed agent or execute a certificate operation.

Five mandatory cases cover authorized text and server redaction, actual browser offline/reconnect with a newly appended line and no duplicate history, viewer routing and status-only API access, withdrawal of cached text after an already-open session loses manager authority, and owned cleanup. Membership changes are explicit fixture prerequisites. Network failures use Chromium's offline state; responses are never intercepted or fabricated.

All CertOps UI routes currently require manager authority. A viewer browser must be redirected and receives only stream metadata through its authenticated API session. An already-open console must clear cached text on an authoritative status-only response or HTTP401/403. Ordinary transport failures preserve permitted history while reconnecting.

The existing browser workflow runs this suite separately from the certificate settings journeys and verifies its named report. Configure `CERTOPS_BROWSER_CONSOLE_REPORT` to select a report path. Native process stdout/stderr, fleet load and Windows service behavior require their own qualification.
