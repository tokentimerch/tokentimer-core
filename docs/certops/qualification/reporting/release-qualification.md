# Certificate release qualification

The committed `release-qualification-matrix.json` defines mandatory environment evidence. A passing individual workflow qualifies its selected environment; it does not qualify the entire release.

Run the aggregator from a clean checkout of the candidate after downloading every required workflow report:

```sh
node scripts/certops-release-qualification.js <40-character-candidate-sha> <report.json> <report.jsonl> ...
```

Alternatively dispatch **Collect Certificate release qualification** from `main` with the exact candidate SHA and a JSON array of successful qualification run IDs. It checks trusted main history, the source repository, run event, exact head SHA, workflow allowlist, completion and success before downloading bounded artifacts. Archive paths cannot escape extraction. Only qualification fields are retained, and the uploaded consolidated artifact contains counts and the verdict without raw logs or credentials. Collection starts no host tests and provisions no resources.

The matrix currently requires hosted Windows Server 2022 and 2025 native tests, every Windows ACME key profile on both versions, domain-backed AD CS on Server 2019/2022/2025 with native English/German/French environments, both supported Ubuntu systemd environments, Linux real ACME and protocol tests, browser tests, Kubernetes host and API controller tests, every mandatory authenticated API suite, and every committed supporting database integration group.

Reports must identify the actual OS and language where required, current test source digest, exact candidate commit, and workflow checkout provenance. The aggregator independently validates mandatory scenario IDs and capability evidence using committed suite metadata. JSONL protocol reports must contain every committed required test and the specific real agent journey for their scope. Failed, skipped, incomplete, mismatched, duplicate, or missing environment artifacts fail release qualification. Local reports remain useful debugging evidence but cannot satisfy this release gate.

Database integration reports retain their supporting classification. Every required named case must pass without pending tests, and each selected source file must match its current digest. They cannot substitute for the domain or native host scenarios.

New host-gate reports automatically record native platform/OS build observations. Enterprise reports additionally prove the service identity and installed native language. OS/language selection inputs alone are insufficient. The matrix schema guard requires every mandatory suite to retain a release environment when scenarios expand.

This tool never changes AD CS feature flags or production configuration. It verifies evidence only. Native host scenarios that have not yet executed remain unqualified, even when their test implementation exists and local supporting tests pass.

The consolidated result is explicitly scoped to `committed-mandatory-matrix` and always reports `allFeaturesQualified: false`. Its catalog summary separately counts planned, partial and implemented behavior specifications, with execution evidence tracked separately. Passing every current matrix slot cannot silently promote an incomplete behavior catalog to full project completion or enable a guarded feature.
