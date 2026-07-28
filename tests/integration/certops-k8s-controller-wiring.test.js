"use strict";

const { expect } = require("chai");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "../..");

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

describe("CertOps Kubernetes controller wiring", () => {
  it("keeps the controller package and default image tag aligned with Chart.appVersion", () => {
    const controllerPackage = JSON.parse(read("apps/k8s-controller/package.json"));
    const chart = read("deploy/helm/Chart.yaml");
    const values = read("deploy/helm/values.yaml");
    const appVersion = chart.match(/^appVersion:\s*"([^"]+)"$/m)?.[1];
    const controllerTag = values.match(
      /^certops:\r?\n  controller:[\s\S]*?^    image:\r?\n[\s\S]*?^      tag:\s*"([^"]+)"/m,
    )?.[1];

    expect(controllerPackage.version).to.equal(appVersion);
    expect(controllerTag).to.equal(appVersion);
  });

  it("keeps the fourth image non-root, locked, and independently executable", () => {
    const dockerfile = read("apps/k8s-controller/Dockerfile");
    const logScrubber = read("packages/log-scrub/index.js");
    const apiDetectorShim = read("apps/api/utils/secretMaterial.js");
    expect(dockerfile).to.include("FROM node:22.23.0-alpine3.23");
    expect(dockerfile).to.include("pnpm install --prod --frozen-lockfile");
    expect(dockerfile).to.include("corepack disable");
    expect(dockerfile).to.include("/usr/local/lib/node_modules/corepack");
    expect(dockerfile).to.include("/usr/local/lib/node_modules/npm");
    expect(dockerfile).to.include("packages/log-scrub ./packages/log-scrub");
    expect(dockerfile).to.not.include("packages ./packages");
    expect(dockerfile).to.include("rm -f package.json pnpm-workspace.yaml pnpm-lock.yaml .npmrc");
    expect(dockerfile).to.include("USER tokentimer");
    expect(dockerfile).to.include('CMD ["node", "src/index.js"]');
    expect(dockerfile).to.include("apps/api/services/certops/parser.js");
    expect(dockerfile).to.include("apps/api/services/certops/identitySafety.js");
    expect(dockerfile).to.include("apps/api/services/certops/controllerObservationLimits.js");
    expect(dockerfile).to.include("process.env.CERTOPS_HEALTH_PORT || 8080");
    expect(dockerfile).to.include("Number.isInteger(port)");
    expect(dockerfile).to.include("path:'/healthz'");
    expect(dockerfile).to.not.include("127.0.0.1:8080/healthz");
    expect(dockerfile).to.not.match(/kubeconfig|tls\.key/i);
    expect(logScrubber).to.not.match(/apps[\\/]api/);
    expect(apiDetectorShim).to.include("packages/log-scrub/secret-material");
  });

  it("publishes the in-cluster image without advertising an unsupported Compose runtime", () => {
    const compose = read("deploy/compose/docker-compose.yml");
    const imageCompose = read("deploy/compose/docker-compose.images.yml");
    const ci = read(".github/workflows/ci.yml");
    const publish = read(".github/workflows/publish.yml");
    const release = read(".github/workflows/release.yml");

    expect(compose).to.not.include("certops-controller:");
    expect(imageCompose).to.not.include("tokentimer-core-k8s-controller");
    expect(ci).to.include("Kubernetes Controller Quality Checks");
    expect(ci).to.include("Build Kubernetes controller image");
    expect(ci).to.include("Scan Kubernetes controller image with Grype");
    expect(publish).to.include("Build and push Kubernetes controller");
    expect(publish).to.include("platforms: linux/amd64");
    expect(release).to.include("component: k8s-controller");
    expect(release).to.include("repository: tokentimer-core-k8s-controller\\$");
    expect(release).to.include('tag: \\"$VER\\"');
  });

  it("uses a bounded streaming tls.crt reader instead of deserializing Secret objects", () => {
    const clientSource = read("apps/k8s-controller/src/cert-manager-client.js");
    const source = [
      "apps/k8s-controller/src/cert-manager-client.js",
      "apps/k8s-controller/src/cert-manager-observer.js",
      "apps/k8s-controller/src/public-certificate-parser.js",
      "apps/k8s-controller/src/ports.js",
      "apps/k8s-controller/src/runtime.js",
      "apps/k8s-controller/src/tls-certificate-fallback.js",
      "apps/k8s-controller/src/tls-crt-secret-reader.js",
      "apps/k8s-controller/src/index.js",
    ]
      .map(read)
      .join("\n");

    expect(source).to.include('@kubernetes/client-node');
    expect(source).to.include("loadFromCluster()");
    expect(source).to.match(/listNamespacedCustomObject\(\s*\{/);
    expect(source).to.match(/listClusterCustomObject\(\s*\{/);
    expect(source).to.not.match(/\.loadFromDefault\s*\(/);
    expect(clientSource).to.not.match(/CoreV1Api/);
    expect(clientSource).to.not.match(/readNamespacedSecret/);
    expect(source).to.include("extractTlsCertificateFromSecretJson");
    expect(source).to.not.match(/response\.(?:json|text)\s*\(/);
    expect(source).to.not.match(/JSON\.parse\s*\(/);
    expect(clientSource).to.not.match(/return\s+secret\b/);
    expect(source).to.not.match(/(?:list|watch|create|update|patch|delete)(?:Namespaced|Cluster)?Secret\b/);
    expect(source).to.not.match(/data\s*\[\s*["']tls\.key["']\s*\]/);
    expect(source).to.not.match(/\.spec\.request|\.status\.certificate/i);
    expect(source).to.not.match(/\.reconcile\s*\(/);
    expect(source).to.match(/https\s*:\s*http\)\.request|https\s*:\s*http/);
    expect(source).to.not.match(/\bfetch\s*\(|\baxios\b/);
    expect(source).to.not.match(/certificate_jobs|certificate_evidence|managed_certificates/i);
  });
});
