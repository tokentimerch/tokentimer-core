"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");

// Isolated processes evaluate real platform capability candidates with a fully
// qualified test manifest. Production manifests and process globals stay intact.
const child = `
const fs = require('node:fs');
const options = JSON.parse(process.argv[1]);
Object.defineProperty(process, 'platform', { value: options.platform });
const capabilities = require(options.capabilities);
capabilities._setManifestModulePathForTests(options.manifest);
const { executeJob, AGENT_DECLARED_CAPABILITIES } = require(options.entrypoint);
if (!AGENT_DECLARED_CAPABILITIES.includes('deploy-from-store-v1')) throw Error('unqualified test fixture');
executeJob({ job: options.job, jobId: 'platform-policy', claimId: 'claim-platform',
  client: {}, policyEngine: { checkPath: () => ({ allowed: true }), checkTargetScope: () => ({ allowed: true }) },
  executionContext: { execution: { dryRun: false }, stateDir: options.stateDir,
    materialStores: options.stores, materialBindings: options.bindings }, log: () => {},
}).then(result => process.stdout.write(JSON.stringify(result))).catch(error => { console.error(error); process.exitCode = 1; });
`;

for (const platform of ["linux", "win32"]) {
  for (const type of ["endpoint", "windows-iis"]) {
    for (const policy of ["installed", "served", "trust"]) {
      for (const mode of ["dry_run", "real"]) {
        const platformAllowed =
          (platform === "linux") === (type === "endpoint");
        const supported =
          platformAllowed && !(platform === "win32" && policy === "installed");
        if (mode === "real" && supported) continue;
        test(`qualified ${platform} ${mode} ${policy} enforces shared target ${type}`, (t) => {
          const directory = fs.mkdtempSync(
            path.join(os.tmpdir(), "tt-material-platform-"),
          );
          t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
          const manifest = path.join(directory, "manifest.cjs");
          const gated =
            require("../capabilities/gated-capabilities").GATED_CAPABILITIES;
          fs.writeFileSync(
            manifest,
            `module.exports = ${JSON.stringify({ qualified: gated })};`,
          );
          const workspaceId = crypto.randomUUID(),
            groupId = crypto.randomUUID(),
            bindingId = crypto.randomUUID();
          const deployment = {
            groupId,
            bindingId,
            materialVersionId: crypto.randomUUID(),
            materialStoreRef: "customer",
            providerVersion: 1,
            generation: 1,
            deploymentProfileRef: "site",
            profileRevision: 1,
            authorizationRevision: 1,
            verificationPolicy: policy,
          };
          const binding = {
            ...deployment,
            workspaceId,
            agentId: "consumer",
            connector: "windows-material-iis-v1",
            serviceAccountSids: [],
            probes:
              policy === "installed"
                ? []
                : [
                    {
                      dialAddress: "127.0.0.1",
                      port: 443,
                      sni: "review.invalid",
                    },
                  ],
            target:
              type === "endpoint"
                ? {
                    type,
                    certPath: path.join(directory, "leaf.pem"),
                    keyPath: path.join(directory, "key.pem"),
                  }
                : {
                    type,
                    reference: "site",
                    store: "My",
                    binding: {
                      site: "Review",
                      address: "127.0.0.1",
                      port: 443,
                      sniHost: "review.invalid",
                      store: "My",
                    },
                  },
          };
          const options = {
            platform,
            manifest,
            entrypoint: path.resolve(__dirname, "../index.js"),
            capabilities: path.resolve(__dirname, "../capabilities"),
            stateDir: path.join(directory, "state"),
            job: {
              action: "deploy-from-store",
              mode,
              workspaceId,
              agentId: "consumer",
              materialDeployment: deployment,
            },
            stores: {
              customer: {
                address: "https://vault.fixture.invalid",
                mount: "secret",
                tokenFile: path.join(directory, "token"),
                groups: {
                  [groupId]: {
                    workspaceId,
                    prefix: `${workspaceId}/${groupId}`,
                    sans: ["review.invalid"],
                    keyAlgorithm: "rsa",
                  },
                },
              },
            },
            bindings: { [bindingId]: binding },
          };
          const result = JSON.parse(
            execFileSync(
              process.execPath,
              ["-e", child, JSON.stringify(options)],
              { encoding: "utf8", windowsHide: true, timeout: 30000 },
            ),
          );
          if (supported) assert.equal(result.status, "dry_run_complete");
          else {
            assert.equal(result.status, "blocked");
            assert.equal(
              result.errorMessage,
              platformAllowed
                ? "material_windows_policy_denied"
                : "material_platform_unqualified",
            );
          }
          assert.deepEqual(fs.readdirSync(directory), ["manifest.cjs"]);
        });
      }
    }
  }
}
