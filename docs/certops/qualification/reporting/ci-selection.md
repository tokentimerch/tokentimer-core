# Selecting CertOps CI work

The standard Core qualification workflow runs only on trusted `main` pushes and manual requests. It first verifies that the checkout matches the exact candidate SHA, then selects affected lanes from that push's actual Git diff. It does not dispatch Azure labs, DNS-provider qualification, native ACME, Kubernetes or any other expensive manual workflow.

- Documentation, qualification reports, Python collector code and security-guard changes run the cheap tooling lane.
- API, worker, Compose and integration/E2E changes select the migrated API/PostgreSQL stack, without Windows feature installation.
- Agent runtime changes select Windows host checks and the supporting stack. Shared contracts and dependency changes conservatively select all standard lanes.
- Missing history, a new branch or a forced push selects all standard lanes rather than silently omitting coverage.

The tooling lane automatically discovers every `scripts/certops-*.test.js` framework regression, also runs the host-gate tests and Python collector tests, and validates current qualification/security inventories. It provisions no lab or stack. Adding a framework test no longer requires editing a second filename list.

For an iteration, use **Run workflow** and choose `tooling`, `windows` or `stack`. The default is `tooling`; choose `all` explicitly for all standard lanes. Re-running failed jobs retains the original run's selected lanes; dispatch a new run to choose a different lane. The separate native/paid workflows remain deliberate manual operations with their existing protected environments and ownership safeguards.

Selection is a cost-control decision, not release qualification. A selected run does not establish that omitted suites passed. The release collector still requires the complete mandatory environment matrix, matching candidate SHA and current source hashes; partial iteration evidence cannot satisfy missing cells. Full hosted/native execution remains a separate pre-release decision.
