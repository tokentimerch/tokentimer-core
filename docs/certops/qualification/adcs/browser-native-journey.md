# Native AD CS browser journey

This source exercises the product's supported browser path: create an issuer, run the real Windows agent's CA/template preflight, pin a returned CA public key, create an AD CS renewal profile, attach it to an existing native certificate and enable automation. One actual default SQL-NOW renewal scheduler sweep then creates a genuine native enrollment. The browser finally reloads and displays that exact installed enrollment.

The issuer/profile wizards do not provide first issuance. `AdcsProfileWizard` explicitly requires a certificate already in inventory, and `CreateManualJobModal` refuses generic manual renewal for AD CS profiles. This qualification respects those product boundaries. It does not add a first-issue feature or substitute an API request for an alleged browser enrollment button.

The six mandatory cases are exported by `tests/e2e/helpers/certops-adcs-browser-journey.js`:

- `adcs-real-browser-issuer-native-preflight`
- `adcs-real-browser-confirmed-ca-pin`
- `adcs-real-browser-profile-attachment`
- `adcs-real-browser-automation-native-enrollment`
- `adcs-real-browser-installed-enrollment-visible`
- `adcs-real-browser-owned-cleanup`

The parent comprehensive domain journey supplies its already owned RSA2048 IIS target, actual registered LocalSystem agent, PostgreSQL fixture and native cleanup registries. The browser issues six genuine authenticated public mutations: issuer creation, initial preflight dispatch, key confirmation, a second native preflight after confirmation, profile creation and management-period replacement. Responses are observed without interception or substitution. Native preflight must finish through the installed agent before the confirmation button becomes available. The second check must be created after confirmation, because the production admission gate requires a preflight at least as recent as the confirmed issuer version. Both actual job IDs remain in the parent cleanup inventory.

To isolate the default sweep, the helper temporarily disables other profiles in its own fixture workspace through the public profile policy API and restores their exact enabled policy afterward. The due scanner uses actual SQL `NOW()` and the stored certificate expiry. The complete production `runRenewalSchedulerSweep` creates exactly one enrollment; this is the production sweep routine, not a continuously running background worker loop, a targeted admission substitute or a manufactured expiry. No result, journal phase, preflight verdict or successful state is seeded.

Independent oracles require a new CA-issued leaf and SPKI, matching native CA request, nonexportable machine CNG key, owned enrollment journal and issuance receipt, exact IIS/HTTP.sys SNI binding, trusted TLS, persisted installed state and claim-bound verification evidence. The final dashboard `Show finished` row must identify the same enrollment. This source covers one RSA2048 existing-inventory renewal and does not imply every algorithm, first issuance, manual AD CS renewal or UI interruption variant.

The optional full-lane add-ons reuse existing disposable lab hosts. `browser-control-plane.sh` builds the existing candidate dashboard Dockerfile, binds it only to control-plane loopback and serves it alongside the API through the existing private HTTPS origin. It updates the fresh test API's actual application/API origin before jobs start. `browser-windows-tools.ps1` installs root dependencies from the frozen lockfile and the Playwright-selected Chromium revision. It uses the existing pnpm 11.13.0, Playwright 1.63.0 and candidate runtime; it does not introduce another VM or permanent browser service.

Chromium validates HTTPS normally. `browser-api-trust.ps1` temporarily adds only the exact owned public API certificate to SYSTEM's CurrentUser Root store. Its receipt is published before mutation; existing identical trust is preserved. Cleanup first drains Chromium, then removes only trust added by this helper and restores changed profile policies. The parent registers the browser resource before trust mutation, retries drainage after failure and preserves its owned state directory whenever a child or trust receipt remains. The parent retains ownership of newly created enrollments and native certificates, including when the sweep commits before a later failure. Browser traces, screenshots, cookies, credentials, raw responses and private keys are excluded from reports, and browser exceptions are reduced to bounded stage/code diagnostics.

The source and pure proof checks can be reviewed without provisioning. Actual native browser execution remains pending until the protected comprehensive root/hierarchy workflows run. The elapsed-pending lane does not execute these cases. Fault experiments that also emit the comprehensive base suite execute the same mandatory browser cases; their existing experimental and not-qualified report status still prevents release qualification. Missing Chromium, dashboard, native agent or domain prerequisites must fail a selected comprehensive browser lane rather than produce skipped green coverage.
