# Finding a qualification harness

Start with the [CI selection guide](ci-selection.md) to choose an iteration lane, or the [release qualification guide](release-qualification.md) to collect the complete candidate matrix. Each new harness has a source header describing its purpose, prerequisites, resource ownership and evidence limits.

- `.github/workflows/certops-*.yml` are the trusted workflow entry points. Native and infrastructure workflows require explicit selection. Their topic guides describe required environments and cleanup identities.
- `scripts/certops-*.js` orchestrate a selected fixture or verify its evidence. Report verifiers provision nothing. Cleanup entry points validate ownership before touching resources.
- `tests/e2e/` contains public API, browser and actual agent journeys. Its `helpers/` directory holds scoped prerequisites, protocol clients and explicit fault injection. A registered protocol fixture sends real authenticated requests but does not run a native agent.
- `packages/agent/scripts/host/` holds native Windows fixtures. These require capability probes, elevation and an explicitly disposable host; ordinary report regressions do not establish host qualification.
- `infra/certops-adcs/` provisions and removes the isolated domain-backed AD CS lab. Its scripts distinguish read-only observations, owned officer actions and infrastructure mutation.
- `scripts/ci-guards/` checks source inventories, workflow trust, documentation boundaries and scenario registrations. The standard stack also parses native Windows and AD CS read-only SQL oracles against the actual migrated schema with `EXPLAIN` inside read-only transactions, without executing those native cases. This checks SQL validity; the separate enrollment-policy regression checks the semantic distinction between a CA-reported request ID and an operator's reconciliation hint.

The stable files in `docs/certops/` serve different purposes: the scenario catalog describes coverage and remaining gaps; `qualification-suites.json` defines mandatory named cases and capabilities; `release-qualification-matrix.json` assigns environments; and the generated skip mapping tracks prerequisite ownership. These files contain requirements, not passing execution results.

Reports live in ignored `qualification-results/` directories. A valid qualification report binds mandatory case execution to the candidate, current harness source, measured environment and successful cleanup. Adding comments changes a source digest, so an older report cannot qualify the updated source. Local focused results retain local provenance and cannot satisfy the hosted release gate.
