"use strict";

const { expect } = require("chai");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "../..");

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

describe("CertOps Kubernetes controller wiring", () => {
  it("keeps the fourth image non-root, locked, and independently executable", () => {
    const dockerfile = read("apps/k8s-controller/Dockerfile");
    expect(dockerfile).to.include("FROM node:22.23.0-alpine3.23");
    expect(dockerfile).to.include("pnpm install --prod --frozen-lockfile");
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
  });

  it("keeps controller deployment opt-in while wiring Compose and image metadata", () => {
    const compose = read("deploy/compose/docker-compose.yml");
    const imageCompose = read("deploy/compose/docker-compose.images.yml");
    const ci = read(".github/workflows/ci.yml");
    const publish = read(".github/workflows/publish.yml");
    const release = read(".github/workflows/release.yml");

    expect(compose).to.include('profiles: ["certops-controller"]');
    expect(compose).to.include("apps/k8s-controller/Dockerfile");
    expect(imageCompose).to.include("tokentimer-core-k8s-controller");
    expect(ci).to.include("Kubernetes Controller Quality Checks");
    expect(ci).to.include("Build Kubernetes controller image");
    expect(publish).to.include("Build and push Kubernetes controller");
    expect(release).to.include("component: k8s-controller");
  });

  it("keeps CoreV1Api limited to the narrow tls.crt fallback without reporting access", () => {
    const clientSource = read("apps/k8s-controller/src/cert-manager-client.js");
    const source = [
      "apps/k8s-controller/src/cert-manager-client.js",
      "apps/k8s-controller/src/cert-manager-observer.js",
      "apps/k8s-controller/src/public-certificate-parser.js",
      "apps/k8s-controller/src/ports.js",
      "apps/k8s-controller/src/runtime.js",
      "apps/k8s-controller/src/tls-certificate-fallback.js",
      "apps/k8s-controller/src/index.js",
    ]
      .map(read)
      .join("\n");

    expect(source).to.include('@kubernetes/client-node');
    expect(source).to.include("loadFromCluster()");
    expect(source).to.match(/listNamespacedCustomObject\(\s*\{/);
    expect(source).to.match(/listClusterCustomObject\(\s*\{/);
    expect(source).to.not.match(/\.loadFromDefault\s*\(/);
    expect(clientSource).to.match(/CoreV1Api/);
    expect(clientSource).to.match(/readNamespacedSecret\(\s*\{/);
    expect(clientSource).to.match(/data\s*\[\s*["']tls\.crt["']\s*\]/);
    expect(clientSource).to.not.match(/return\s+secret\b/);
    expect(source).to.not.match(/(?:list|watch|create|update|patch|delete)(?:Namespaced|Cluster)?Secret\b/);
    expect(source).to.not.match(/data\s*\[\s*["']tls\.key["']\s*\]/);
    expect(source).to.not.match(/\.spec\.request|\.status\.certificate/i);
    expect(source).to.not.match(/\.reconcile\s*\(/);
    expect(source).to.not.match(/https?\.request\s*\(|\bfetch\s*\(|\baxios\b/);
    expect(source).to.not.match(/certificate_jobs|certificate_evidence|managed_certificates/i);
  });
});
