# Completed console authorization

The `browser-agent-console` suite keeps the real dashboard console mounted after a registered protocol agent finalizes its diagnostic stream and submits a claim-bound successful noop result. Finalizing a stream alone must leave the job claimed. Only the authenticated result establishes the job's terminal state; this suite does not execute a native certificate operation.

Completed consoles retain their last cursor and schedule an authenticated revalidation every 15 seconds while mounted. Live output keeps its existing faster polling cadence. An authoritative status-only response or HTTP 401/403 discards cached lines and resets the cursor. Restoring permission reloads retained history without reopening the console or duplicating its completion callback. Unmounting cancels pending requests and timers. Browser background throttling or network outages can delay successful revalidation; the foreground qualification uses a 30-second observation bound and does not claim instantaneous permission revocation.

Three mandatory scenarios extend the existing live-console privacy checks:

- `browser-console-completed-stream-job` finalizes an actual stream, independently verifies the still-claimed job, then submits its genuine claim-bound result and observes the succeeded console.
- `browser-console-completed-viewer-withdrawal` changes a non-owner manager's real workspace membership to viewer, observes the actual status-only response, and requires cached text to disappear from the same mounted DOM node. Restoring manager membership reloads each retained line once.
- `browser-console-completed-membership-withdrawal` removes the membership, observes the actual HTTP 403, and requires cached text to disappear while the independent database oracle confirms the four retained diagnostic lines and successful noop are unchanged.

Membership edits are explicit fixture prerequisites. The browser operator is distinct from the workspace owner, whose implicit administrator authority would survive deletion of its membership row. Job, stream, result and diagnostic rows are created through authenticated public/protocol APIs. Generated secret sentinels must remain absent from rendered text, and cleanup removes only run-owned identities.

Reports bind the producer, console component, dashboard API client, API route, log service and both fixture helpers through SHA-256 source fingerprints. The bounded `completedConsolePrivacy` object records only boolean outcomes; it contains no diagnostic text, cookies, credentials, raw database rows or screenshots. A local Windows browser run is supporting local evidence and cannot fill the separate Ubuntu release qualification slot.

Focused dashboard tests cover completed status-only, HTTP 401 and HTTP 403 withdrawal, restoration from a reset cursor, unchanged failed/succeeded status, one completion callback, and cancellation of further revalidation after unmount. These tests support the actual Chromium/API/PostgreSQL scenarios and do not replace them.
