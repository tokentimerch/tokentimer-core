# Material-store and consumer onboarding lab

Use a disposable Docker lab to exercise the existing onboarding journey with a real Vault or OpenBao store, registered agents, a test CA and local TLS consumers. Choose a unique project name and free port range; never attach the lab to a production database. See the [lab README](../../tests/wildcard-vault/ux-lab/README.md) for prerequisites, ownership and cleanup.

```powershell
$project = 'tt-wildcard-ux-my-test'
./tests/wildcard-vault/ux-lab/run.ps1 -Action Up -Project $project -BasePort 60800 -MaterialProvider openbao-kv2 -BuildImages
./tests/wildcard-vault/ux-lab/run.ps1 -Action Test -Project $project -Phase functional
./tests/wildcard-vault/ux-lab/run.ps1 -Action Stop -Project $project
```

For Vault, use a fresh project and port range with MaterialProvider set to vault-kv2. After a successful Up, stop the owned project even if a test fails. Stop removes its containers but retains volumes and local reports; use the lab README for complete cleanup. The store is volatile, so a new run needs a fresh project.

Open onboarding and choose **Share one certificate across servers**. Configure the store and consumers, then distinguish publication from installed and served verification. Approval follows workspace policy; verification-only never deploys material. For customer setup and recovery, use the [distribution guide](vault-first-distribution.md). Azure material storage and shared Windows/IIS deployment remain capability-gated; a lab or mock does not enable them.
