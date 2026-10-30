# Product media

Capture assets and their [manifest](../../docs/assets/media-manifest.json)
remain in `docs/assets/`; the instructions below are for maintainers.

Base captures were made October 28, 2026 from Core 0.18.2 (`3c209435`). The audit and expanded-job screenshots and dark workflow GIF were recaptured from the audit-layout fix (`9ffa8102`), based on released main. Per-asset source revisions are recorded in `media-manifest.json`. All images show the actual dashboard with illustrative in-memory sample data. Provider discovery, certificate data, endpoint monitors, imports, roles and notification settings are simulated. These assets do not establish live certificate renewal or alert delivery.

## Screenshots

PNG screenshots are 1920 × 1080, except the expanded job timeline and complete shell output at 1920 × 1440. Unsuffixed README images use dark mode; existing light and dark overview, preferences and system-settings variants are retained. Capture the control center, inventory, managed certificates, expanded renewal profiles, completed-job details, agent fleet, workspace alerting, preferences, system settings and audit pages. Wait for data, fonts and transient notifications to settle.

## Animated workflows

The workflow GIF uses dark theme. The overview GIF and existing light-theme PNG variants are retained. Both GIFs demonstrate actions and outcomes. Both are 1600 × 900 at 12 fps, silent and looped, with a visible pointer following actual browser mouse events. Only initial loading is trimmed; there are no internal cuts or speed changes.

- `dashboard-workflow.gif`: discover subdomains; select results and a section; import 14 SSL certificate tokens and create 14 endpoint monitors; scan Vault KV and PKI; select 15 items and assign a section; import them; filter the inventory to those 15 assets.
- `dashboard-overview.gif`: edit and save asset notes; inspect the control center and audit events; change a sample member's workspace role; save the delivery window and inspect webhook channels; visit the certificate inventory, expanded renewal profiles and agent fleet.

## Reproduction and qualification

Run the current dashboard against a fresh disposable sample API. Sign in to a sample workspace using an isolated Chromium-family browser at device scale 1. Capture PNGs at 1920 × 1080 and record GIF sources at 1600 × 900 (workflow: dark mode; overview: light mode). Perform the actions above through the product controls, preserve the final saved/imported result on screen, and encode with FFmpeg using a generated palette. Keep real credentials and customer records out of the fixture.

The local sample API's older Vault scan summary was adapted to the current contract: counts are computed from the returned sample items, grouped by mount, rather than changing the UI. Two optional onboarding summary endpoints are absent from the sample API; initial capture waits for their notifications to dismiss naturally. No product controls, data labels or result messages are painted over or replaced. The pointer is a capture aid.

Every screenshot was inspected in a contact sheet and principal views at native resolution. Both final GIFs were sampled across their full encoded duration, their opening and closing states inspected, and their complete streams decoded. Source-state checks confirm imported counts, the filtered inventory, saved asset notes, role-update feedback and delivery-window feedback. `media-manifest.json` records delivered dimensions, durations, sizes and SHA-256 hashes.

## Audit-name regression

Audit action names wrap in their available width without the extra tooltip wrapper that could overflow and be clipped by the table cell. `scripts/check-audit-action-layout.cjs` checks real glyph and clipping-ancestor bounds at 1920, 1280 and 390 pixels. Run it against the signed-in edition URLs using `AUDIT_URLS`; `AUDIT_SAMPLE_API` enables the disposable localhost sample login. The fix is verified in Core, the Cloud override, and the composed Enterprise dashboard, which inherits Core’s Audit page.
