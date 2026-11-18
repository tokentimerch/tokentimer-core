"use strict";
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { createBroker } = require("./azure-role-token-broker.cjs");
const { describeRoles, assertRoleMounts } = require("./azure-isolated-role.cjs");
const { createDataPlane } = require("./azure-operator-data-plane.cjs");
const { exercise } = require("./azure-operator-public-journey.cjs");
const { withControl } = require("./isolated-journey-run.cjs");
const { inspectCandidateImages } = require("./candidate-images.cjs");
const { requireFresh } = require("./project-freshness.cjs");
const { stage } = require("./stage-supplied-package.cjs");
const { createDockerTransport } = require("./docker-transport.cjs");
const { cleanup } = require("./owned-teardown.cjs");
const { runOperatorQualification } = require("./final-evidence-bridge.cjs");
const { OperatorStageError, requireCleanup } = require("./azure-operator-diagnostics.cjs");
const { PROFILES } = require("../../../../scripts/certops-final-package-evidence.cjs");

const PROFILE = "azure-operator-http-real-ca";
const WORKFLOW = "tokentimerch/tokentimer-core/.github/workflows/certops-azure-operator-qualification.yml@refs/heads/main";
const lab = path.resolve(__dirname, "..");
const harness = path.resolve(lab, "../../..");
const runCommand = (name, args, env = process.env) =>
  execFileSync(name, args, { env, encoding: "utf8", timeout: 300000, maxBuffer: 1024 * 1024 });
const inside = (parent, child) => parent === child || parent === "/" || child.startsWith(parent + "/");

function trustedBinding(env) {
  assert.equal(process.platform, "linux");
  assert.equal(process.geteuid(), 0, "owned role sinks require the lab host supervisor");
  assert.equal(env.GITHUB_ACTIONS, "true");
  assert.equal(env.RUNNER_ENVIRONMENT, "github-hosted");
  assert.equal(env.GITHUB_REPOSITORY, "tokentimerch/tokentimer-core");
  assert.equal(env.GITHUB_WORKFLOW_REF, WORKFLOW);
  assert.equal(env.GITHUB_REF, "refs/heads/main");
  assert.equal(env.GITHUB_EVENT_NAME, "workflow_dispatch");
  assert.equal(env.GITHUB_RUN_ATTEMPT, "1");
  return {
    runId: env.GITHUB_RUN_ID, sourceSha: env.GITHUB_SHA, workflowRef: WORKFLOW,
    repositoryId: env.GITHUB_REPOSITORY_ID, ownerId: env.GITHUB_REPOSITORY_OWNER_ID, subjectFormat: "legacy",
  };
}

function write(file, value) { fs.writeFileSync(file, JSON.stringify(value) + "\n", { mode: 0o600, flag: "wx" }); }
function hostEnvironment(env) {
  const names = ["PATH", "HOME", "LANG", "DOCKER_CONFIG", "XDG_RUNTIME_DIR"];
  return Object.fromEntries(names.filter(name => env[name] !== undefined).map(name => [name, env[name]]));
}
function dockerCli(env) {
  return (args, options = {}) => execFileSync("docker", args, { env: hostEnvironment(env), encoding: "utf8",
    timeout: 30000, maxBuffer: 1024 * 1024, ...options });
}

async function cleanupLocal(owner, env = process.env) {
  const { runId, sourceSha } = trustedBinding(env);
  assert.equal(owner.runId, runId);
  assert.equal(owner.sourceSha, sourceSha);
  assert.equal(owner.project, "tt-wildcard-ux-qual-azure-" + runId);
  const project = owner.project;
  const root = path.join(fs.realpathSync(env.RUNNER_TEMP), project);
  const receipt = path.join(root, "owned.json");
  if (!fs.existsSync(receipt)) return;
  assert.equal(fs.realpathSync(root), root);
  const stat = fs.lstatSync(receipt);
  assert.ok(stat.isFile() && stat.uid === 0 && (stat.mode & 0o777) === 0o600 && stat.size < 8192);
  assert.deepEqual(JSON.parse(fs.readFileSync(receipt, "utf8")), owner);
  await cleanup({ project, transport: createDockerTransport({ project, execute: dockerCli(env) }) });
  const output = path.join(root, project);
  runCommand(process.execPath, [path.join(lab, "operator-ca-setup.cjs"), "dispose",
    output + "-operator-ca-private", path.join(output, "operator-ca")], hostEnvironment(env));
  for (const role of ["issuer", "consumer"]) {
    const directory = path.join(root, role);
    fs.rmSync(path.join(directory, "token.json"), { force: true });
    if (fs.existsSync(directory)) fs.rmdirSync(directory);
  }
}

async function runProtected({ approved, packageDirectory, candidateRepo, images, evidenceDirectory, credentialRoot, authority, env = process.env }) {
  const binding = trustedBinding(env);
  const { runId, sourceSha } = binding;
  assert.match(runId || "", /^[1-9][0-9]{0,15}$/);
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  const { packageArtifact, vaultHost, issuer, consumer, deadlineMs } = approved;
  const project = "tt-wildcard-ux-qual-azure-" + runId;
  const context = { runId, sourceSha, packageIdentity: packageArtifact };
  const owner = { project, runId, sourceSha, packageArtifact, vaultHost };
  for (const method of ["assertRun", "assertLease", "journal", "grantExactRead", "removeAndVerify"])
    assert.equal(typeof authority?.[method], "function");
  // The protected job authenticates the producer artifact, run approval and
  // run-owned vault/app lease before handing authority to this driver.
  await authority.assertRun({ ...owner, issuer, consumer, deadlineMs });
  const runRoot = path.join(fs.realpathSync(env.RUNNER_TEMP), project);
  const roleDescriptor = describeRoles({ vaultHost, issuerClientId: issuer.clientId, consumerClientId: consumer.clientId });
  const candidate = fs.realpathSync(candidateRepo);
  const certificateRoot = fs.realpathSync(credentialRoot);
  for (const root of [candidate, harness]) {
    assert.ok(!inside(root, runRoot) && !inside(root, certificateRoot), "protected inputs cannot live in a mounted checkout");
  }
  assert.ok(!inside(runRoot, certificateRoot) && !inside(certificateRoot, runRoot), "work and certificate roots overlap");
  assert.equal(runCommand("git", ["-c", "safe.directory=" + candidate, "-C", candidate, "rev-parse", "HEAD"], hostEnvironment(env)).trim(),
    packageArtifact.candidateSha);
  assert.ok(fs.statSync(path.join(candidate, "apps/dashboard/dist/index.html")).isFile(), "candidate dashboard must be built");
  const { apiImage, workerImage, roleImage } = images;
  const docker = dockerCli(env);
  const inspect = id => JSON.parse(docker(["image", "inspect", id]));
  inspectCandidateImages({ candidateSha: packageArtifact.candidateSha, apiImage, workerImage, inspect });
  const [roleBuild] = inspect(roleImage);
  assert.match(roleImage, /^sha256:[a-f0-9]{64}$/);
  assert.equal(roleBuild.Id, roleImage);
  assert.equal(roleBuild.Config.Labels["io.tokentimer.certops.source-sha"], packageArtifact.candidateSha);
  const output = path.join(runRoot, project);
  const caOutput = path.join(output, "operator-ca"), caPrivate = output + "-operator-ca-private";
  const issuerSink = path.join(runRoot, "issuer"), consumerSink = path.join(runRoot, "consumer");
  const packageInput = path.join(output, "agent-package");
  const composeEnv = {
    ...hostEnvironment(env),
    TT_UX_CANDIDATE_REPO: candidate, TT_UX_REVIEW_HARNESS: harness, TT_WILDCARD_UX_OUTPUT: output,
    TT_UX_CORE_COMMIT: packageArtifact.candidateSha, TT_UX_OPERATOR_CA: "openbao-pki",
    TT_UX_PACKAGE_ACCEPTANCE: "1", TT_UX_CERTIFICATE_MODE: "ordinary", TT_UX_MATERIAL_PROVIDER: "azure-key-vault",
    TT_UX_API_IMAGE: apiImage, TT_UX_WORKER_IMAGE: workerImage, TT_UX_CUSTOMER_IMAGE: roleImage, TT_UX_ROLE_IMAGE: roleImage,
    TT_UX_PUBLIC_PACKAGE_INPUT: packageInput, TT_UX_OPERATOR_CA_PRIVATE: caPrivate, TT_UX_OPERATOR_CA_OUTPUT: caOutput,
    TT_UX_ISSUER_DESCRIPTOR: path.join(runRoot, "issuer.json"), TT_UX_CONSUMER_DESCRIPTOR: path.join(runRoot, "consumer.json"),
    TT_UX_ISSUER_SINK: issuerSink, TT_UX_CONSUMER_SINK: consumerSink, TT_UX_PROJECT: project,
    TT_UX_API_PORT: "60800", TT_UX_WEB_PORT: "60801", TT_UX_MAIL_PORT: "60803", TT_UX_NGINX_PORT: "60843", TT_UX_HAPROXY_PORT: "60943",
  };
  const compose = (...args) => runCommand("docker", ["compose", "--project-name", project,
    "-f", path.join(lab, "compose.yaml"), "-f", path.join(lab, "operator-ca.compose.yaml"),
    "-f", path.join(__dirname, "compose.azure.isolated.yaml"), "--profile", "worker", ...args], composeEnv);
  const ca = (action) => runCommand(process.execPath, [path.join(lab, "operator-ca-setup.cjs"), action, caPrivate, caOutput],
    hostEnvironment(env));
  const roleMounts = { image: roleImage, issuerSink, consumerSink, certificateRoot, dnsCredential: path.join(caOutput, "dns.json") };
  let broker, prepared = false, observationStage = "lab-staging";
  const observe = async () => {
    await requireFresh(project, createDockerTransport({ project, execute: docker }));
    fs.mkdirSync(runRoot, { mode: 0o700 });
    prepared = true;
    write(path.join(runRoot, "owned.json"), owner);
    fs.mkdirSync(output, { mode: 0o700 });
    const staged = stage({
      directory: packageDirectory, archiveSha256: packageArtifact.packageSha256, candidateSha: packageArtifact.candidateSha,
      destination: packageInput, producerRunId: packageArtifact.runId, artifactId: packageArtifact.artifactId,
    });
    assert.deepEqual(staged.packageArtifact, packageArtifact);
    for (const [role, directory, uid] of [["issuer", issuerSink, 10001], ["consumer", consumerSink, 10002]]) {
      fs.mkdirSync(directory, { mode: 0o700 });
      fs.chownSync(directory, uid, uid);
      write(composeEnv["TT_UX_" + role.toUpperCase() + "_DESCRIPTOR"], roleDescriptor[role]);
    }
    observationStage = "broker-admission";
    broker = createBroker({ binding, certificateRoot, deadlineMs,
      issuer: { ...issuer, directory: issuerSink }, consumer: { ...consumer, directory: consumerSink },
    });
    const provider = createDataPlane({ vaultHost, issuerSink, consumerSink, deadlineMs,
      assertLease: () => authority.assertLease(owner),
      journal: row => authority.journal(owner, row),
      grantExactRead: objectName => authority.grantExactRead(owner, objectName, consumer),
    });
    await broker.start();
    observationStage = "ca-preparation";
    ca("create");
    observationStage = "ca-bootstrap";
    compose("up", "-d", "operator-ca", "operator-dns");
    const [network] = JSON.parse(docker(["network", "inspect", project + "_operator-ca"]));
    assert.equal(network.Internal, true);
    assert.equal(network.Labels["com.docker.compose.project"], project);
    for (const service of ["operator-ca", "operator-dns"]) {
      const id = compose("ps", "-q", service).trim();
      assert.match(id, /^[a-f0-9]{64}$/);
      const [container] = JSON.parse(docker(["inspect", id]));
      assert.ok(!Object.values(container.NetworkSettings.Ports || {}).some(Boolean), "private CA endpoint published");
    }
    compose("run", "--rm", "--no-deps", "operator-ca-init");
    observationStage = "role-containers";
    compose("up", "-d", "api", "worker", "issuer", "consumer");
    const roleIds = Object.fromEntries(["issuer", "consumer"].map(role => {
      const id = compose("ps", "-q", role).trim();
      assert.match(id, /^[a-f0-9]{64}$/);
      const [record] = JSON.parse(docker(["inspect", id]));
      assertRoleMounts({ ...roleMounts, record, project, role });
      return [role, id];
    }));
    observationStage = "public-journey";
    const results = await withControl({ project, issuerContainerId: roleIds.issuer, consumerContainerId: roleIds.consumer, roleMounts, execute: docker },
      async ({ port, token }) => {
        const config = Object.fromEntries(Object.entries(composeEnv).filter(([name]) => name.startsWith("TT_UX_")));
        Object.assign(config, { TT_WILDCARD_UX_OUTPUT: output, TT_UX_CONTROL_PORT: port, TT_UX_CONTROL_TOKEN: token });
        const previous = Object.fromEntries(Object.keys(config).map(name => [name, process.env[name]]));
        try {
          Object.assign(process.env, config);
          const { context } = require("../journey.cjs");
          return await exercise({ context, provider, broker, ports: [60843, 60943] });
        } finally {
          for (const [name, value] of Object.entries(previous)) {
            if (value === undefined) delete process.env[name];
            else process.env[name] = value;
          }
        }
      });
    observationStage = "package-proof";
    assert.equal(results.packageProof.packageSha256, packageArtifact.packageSha256);
    assert.equal(results.packageProof.candidateSha, packageArtifact.candidateSha);
    assert.equal(results.packageProof.packageFilesUnmodified, true);
    return { packageArtifact, nativeService: null, facts: results.facts,
      scenarios: PROFILES[PROFILE].scenarios.slice(0, -1).map(id => ({ id, status: "passed" })),
    };
  };
  return runOperatorQualification({ profile: PROFILE, context, outputDirectory: evidenceDirectory,
    observe: () => observe().catch(cause => { throw new OperatorStageError(observationStage, cause); }),
    async teardown() {
      const stopped = await Promise.allSettled([broker?.stop()]);
      const results = await Promise.allSettled([
        Promise.resolve().then(() => authority.removeAndVerify(owner)),
        prepared ? cleanupLocal(owner, env) : Promise.resolve(),
      ]);
      requireCleanup([["broker-stop", stopped[0]], ["provider-cleanup", results[0]], ["local-cleanup", results[1]]]);
      try {
        const removed = results[0].value;
        assert.ok(removed.vaultAbsent && removed.roleAssignmentsAbsent && removed.appsAndCredentialsAbsent,
          "independent provider cleanup verification incomplete");
        assert.equal(fs.existsSync(certificateRoot), false, "operator app certificate material remains on the host");
      } catch (cause) { throw new OperatorStageError("teardown-proof", cause); }
      return { ...context, packageArtifact,
        cleanup: { database: "completed", provider: "completed", agent: "completed", credentials: "completed", resources: "completed" },
      };
    },
  });
}

module.exports = { runProtected, cleanupLocal };
