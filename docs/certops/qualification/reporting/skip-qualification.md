# Skip qualification ownership

`skip-qualification.generated.json` joins every site found by the existing skip scanner to a candidate prerequisite environment and a maintainer responsibility. It preserves scanner names, reason tags and source locations. The scanner is heuristic; an unknown title or a misleading classification still needs source review.

Run `node scripts/certops-skip-qualification.js` to check drift. New sites, removed sites, changed reasons and changed source locations fail until the mapping is regenerated with `--write`. Review the resulting diff and source skip condition before accepting it. Regeneration cannot demonstrate that any test ran.

All entries explicitly remain `not-qualified`. A configured workflow means infrastructure exists; it does not prove that this exact skip site executes there. Platform permission tests, OpenSSL fixtures, protocol stack tests and PostgreSQL/worker integration tests use separate candidate cells. Entries that cannot be classified have an explicit prerequisite review owner and no execution environment claim.

Windows native qualification requires an elevated disposable host. Domain-backed AD CS qualification additionally requires a domain, CA, template permissions, service identity and the required operating system/language matrix. A standalone CA smoke or an AD CS unit test never supplies that evidence. No generated skip entry is promoted to domain qualification by its filename.

This mapping complements the scenario catalog and runtime reports. Skip inventory records where tests may skip; scenario specifications record desired outcomes; qualified runtime evidence proves mandatory scenarios actually ran on a candidate artifact. Their counts are deliberately independent.
