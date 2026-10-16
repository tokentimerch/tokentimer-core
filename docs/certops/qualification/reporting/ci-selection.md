# Selecting CertOps CI work

The standard Core qualification workflow runs only on trusted `main` pushes and manual requests. It first verifies that the checkout matches the exact candidate SHA, then selects affected lanes from that push's actual Git diff. It does not dispatch Azure labs, DNS-provider qualification, native ACME, Kubernetes or any other expensive manual workflow.

- Documentation, qualification reports, Python collector code and security-guard changes run the cheap tooling lane.
- API, worker, their shared server packages, Compose and integration/E2E changes select the migrated API/PostgreSQL stack, without Windows feature installation.
- Agent runtime changes select Windows host checks and the supporting stack. Shared contracts and dependency changes conservatively select all standard lanes.
- Missing history, a new branch or a forced push selects all standard lanes rather than silently omitting coverage.

The tooling lane automatically discovers every `scripts/certops-*.test.js` framework regression, also runs the host-gate tests and Python collector tests, and validates current qualification/security inventories. It provisions no lab or stack. Adding a framework test no longer requires editing a second filename list.

For an iteration, use **Run workflow** and choose `tooling`, `windows` or `stack`. The default is `tooling`; choose `all` explicitly for all standard lanes. Re-running failed jobs retains the original run's selected lanes; dispatch a new run to choose a different lane. The separate native/paid workflows remain deliberate manual operations with their existing protected environments and ownership safeguards.

GitHub also supports rerunning a specific failed job; reruns retain the original commit and ref. See [GitHub's rerun documentation](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs).

Selection is a cost-control decision, not release qualification. A selected run does not establish that omitted suites passed. The release collector defaults to the complete mandatory environment matrix, matching candidate SHA and current source hashes. Explicit declared profiles still require every selected cell, disclose exact omitted IDs and cannot claim full matrix qualification; partial iteration evidence cannot satisfy missing selected cells. Follow the [Azure-free first-run sequence](first-qualification.md) before opting into domain-backed or elapsed campaigns. Full hosted/native execution remains a separate pre-release decision.

Each release matrix cell is a required report/environment combination. One job can produce several cells: the API stack runs multiple supporting suites, and a Windows job produces both its certificate journey and child-output privacy evidence. The cell count is not a count of provisioned machines or workflow jobs.

The tooling job installs the official Actionlint `1.7.12` binary from its fixed release URL and checks its committed SHA256 before execution. Framework regressions then validate actual GitHub Actions contexts and expressions in every Core qualification workflow. Valid YAML alone is insufficient: for example, a service's allocated port must be resolved in a step where the `job` context exists, rather than job-level `env`.

Three larger manual matrices now also start with one selected cell:

- Supporting integration: one `group`, default `adcs`; `all` enumerates every committed integration group.
- Linux ACME: one `client` and one `eab` mode, default `certbot` and `none`; explicitly choose `all` for both dimensions to run the complete four-cell matrix.
- Consuming servers: one Ubuntu `os` and one `service`, default `ubuntu-24.04` and `nginx`; explicitly choose `all` for both dimensions to run all six cells.

A trusted candidate selection job validates these values against committed allowlists before constructing runner matrices. Arbitrary runner names, commands or extra dimensions are rejected. UI choices and defaults are regression-checked against the same definitions. The full release matrix is unchanged, so selecting one cell never qualifies its omitted environments.


CertOps dashboard component/page changes and their route, workspace and API-client dependencies also select the cheap tooling lane. That lane runs the actual console, manager-route, workspace-context and CertOps URL-state component tests, including cached-text withdrawal after authority changes. These frontend-only paths do not select Windows hosts or the API stack. The real authenticated browser journeys remain manual qualification and mandatory release evidence; unrelated dashboard pages do not trigger CertOps qualification.

The manual browser lane also requires [retired certificate visibility and factual details](../api/browser-retirement-visibility.md). Its producer and wiring regressions use the existing `scripts/certops-*` path selection; changing the certificate list or detail components continues to select cheap tooling without automatically launching Chromium, PostgreSQL or Windows hosts. The release matrix requires the separate browser retirement report even when navigation and console reports pass.

The exact shared `apps/dashboard/src/pages/Audit.jsx` path also selects tooling for [certificate audit attribution and filtering](../api/browser-certificate-audit.md). Its source-bound Chromium report remains a separate manual/release requirement; changing that page does not automatically launch Chromium, a database stack or Windows hosts.

The separate ARM64 desktop packaged-SCM/mock-child workflow is manual on trusted main. Changes to its script, proof, native adapter or workflow select cheap supporting tooling; they do not dispatch ARM64 hosts, AMD64 hosts or paid labs automatically. Agent runtime/service-host source changes retain the existing conservative Windows/stack selection. The historical unsupported full ARM64 host entry fails explicitly and cannot fill any release cell.

The separate `certops-windows-arm64-agent.yml` workflow is trusted-main manual only. Its dedicated helper, runtime and PostgreSQL-lock changes select supporting tooling without dispatching the AMD64 suite or a paid lab. Product agent/API/contracts dependency changes retain the broader existing selectors. This bounded ARM64 scope covers real installed-agent/API signed noop and file dry-run planning plus native My discovery; it does not fill the full Windows certificate/Server/IIS cells.
