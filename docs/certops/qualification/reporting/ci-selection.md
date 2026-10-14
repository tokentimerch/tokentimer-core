# Selecting CertOps CI work

The standard Core qualification workflow runs only on trusted `main` pushes and manual requests. It first verifies that the checkout matches the exact candidate SHA, then selects affected lanes from that push's actual Git diff. It does not dispatch Azure labs, DNS-provider qualification, native ACME, Kubernetes or any other expensive manual workflow.

- Documentation, qualification reports, Python collector code and security-guard changes run the cheap tooling lane.
- API, worker, their shared server packages, Compose and integration/E2E changes select the migrated API/PostgreSQL stack, without Windows feature installation.
- Agent runtime changes select Windows host checks and the supporting stack. Shared contracts and dependency changes conservatively select all standard lanes.
- Missing history, a new branch or a forced push selects all standard lanes rather than silently omitting coverage.

The tooling lane automatically discovers every `scripts/certops-*.test.js` framework regression, also runs the host-gate tests and Python collector tests, and validates current qualification/security inventories. It provisions no lab or stack. Adding a framework test no longer requires editing a second filename list.

For an iteration, use **Run workflow** and choose `tooling`, `windows` or `stack`. The default is `tooling`; choose `all` explicitly for all standard lanes. Re-running failed jobs retains the original run's selected lanes; dispatch a new run to choose a different lane. The separate native/paid workflows remain deliberate manual operations with their existing protected environments and ownership safeguards.

GitHub also supports rerunning a specific failed job; reruns retain the original commit and ref. See [GitHub's rerun documentation](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs).

Selection is a cost-control decision, not release qualification. A selected run does not establish that omitted suites passed. The release collector still requires the complete mandatory environment matrix, matching candidate SHA and current source hashes; partial iteration evidence cannot satisfy missing cells. Full hosted/native execution remains a separate pre-release decision.

Each release matrix cell is a required report/environment combination. One job can produce several cells: the API stack runs multiple supporting suites, and a Windows job produces both its certificate journey and child-output privacy evidence. The cell count is not a count of provisioned machines or workflow jobs.

The tooling job installs the official Actionlint `1.7.12` binary from its fixed release URL and checks its committed SHA256 before execution. Framework regressions then validate actual GitHub Actions contexts and expressions in every Core qualification workflow. Valid YAML alone is insufficient: for example, a service's allocated port must be resolved in a step where the `job` context exists, rather than job-level `env`.

Three larger manual matrices now also start with one selected cell:

- Supporting integration: one `group`, default `adcs`; `all` enumerates every committed integration group.
- Linux ACME: one `client` and one `eab` mode, default `certbot` and `none`; explicitly choose `all` for both dimensions to run the complete four-cell matrix.
- Consuming servers: one Ubuntu `os` and one `service`, default `ubuntu-24.04` and `nginx`; explicitly choose `all` for both dimensions to run all six cells.

A trusted candidate selection job validates these values against committed allowlists before constructing runner matrices. Arbitrary runner names, commands or extra dimensions are rejected. UI choices and defaults are regression-checked against the same definitions. The full release matrix is unchanged, so selecting one cell never qualifies its omitted environments.
