# PagerDuty migration compatibility

## Migration 92 and preview version compatibility

Migration 92 preserves PagerDuty history for cross-feature compatibility. Unpublished previews recorded as migration 79 or 81 require explicit recovery. **Operator action:** Stop all writers and back up the database, then run the check below with the normal `DB_*` environment. After it passes, rerun with `--apply`, then run standard migrations. The tool refuses unknown schemas, unrecorded telemetry, and altered functions or triggers. This branch does not enable PagerDuty delivery; see [Core #496](https://github.com/tokentimerch/tokentimer-core/pull/496) for runtime guidance.

```sh
node scripts/reconcile-pagerduty-v79.cjs --check
```
