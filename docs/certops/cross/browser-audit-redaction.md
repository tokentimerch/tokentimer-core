# Browser lifecycle, audit, and diagnostic redaction

Redaction removes a private-key block, a bearer token, and a password field before a diagnostic is stored. Completed-console authorization refuses an anonymous replay. An owner or admin replay is still not browser qualification.

Accessibility checks the named labels `Issue certificate`, `Renew certificate`, `Audit history`, and `Job evidence` in the local fixture. No live browser is started. A missing browser fails closed, and `browserQualified` stays false.

The catalog rows `experience.browser-lifecycle`, `experience.ui-layout`, `experience.log-access`, `experience.log-secret-sentinel`, and `experience.audit-target` are annotated only. This file does not promote them.
