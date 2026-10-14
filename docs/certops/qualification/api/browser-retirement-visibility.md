# Retired certificate visibility in the dashboard

The `browser-retirement-visibility` suite runs actual Chromium against a disposable dashboard, API and PostgreSQL stack. Two owned TLS endpoints provide independently trusted public certificate fingerprints. Public monitoring and retirement requests establish revoked and decommissioned identities; no observation rows or successful jobs are seeded.

Seven mandatory scenarios cover active observed rows, public retirement followed by actual TLS rescanning, default hiding, the **Show retired** toggle and reload, explicit retired-status filters, factual observed-location details without renewal controls, and owned cleanup. The decommission fixture first removes its actual monitor through the public API so it respects the refusal to decommission a certificate still known to be serving. Recreating monitoring afterward proves that factual rediscovery preserves the terminal identity and audit history. It does not claim certificate removal or CA revocation.

Dispatch **CertOps / Real certificate dashboard qualification** from trusted `main`. The lane executes this suite after the existing browser navigation and console suites, independently verifies `qualification-results/browser-retirement.json`, and uploads only the sanitized JSON reports. Its release slot requires native Ubuntu 24.04 host measurements, the exact candidate, all seven cases and current source hashes. An individual browser run cannot qualify the complete release matrix.

For a focused disposable stack, set `CERTOPS_CSR_API_URL`, `CERTOPS_BROWSER_URL`, `CERTOPS_CSR_DISPOSABLE_STACK=1` and `CERTOPS_BROWSER_RETIREMENT_REPORT`, then run `node scripts/certops-browser-retirement.js`. Chromium and OpenSSL are mandatory prerequisites. Browser/session state, screenshots, raw TLS key files and raw browser logs are excluded from artifacts; fixture cleanup closes the browser and TLS listeners and removes owned files, users and workspaces.

This is browser/API/real-observation coverage. Windows Certificate Store/CNG, IIS, installed-agent mutations and enterprise CA execution require their separate native qualification lanes.

Focused local execution passed all seven cases in Chromium on Windows against the real disposable API/PostgreSQL fixture, including owned cleanup and strict current-source report verification. The required hosted Ubuntu 24.04 browser environment has not yet run.
