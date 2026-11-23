"use strict";

const { createHash } = require("node:crypto");

const registry = "ghcr.io";
const digestPattern = /^sha256:[a-f0-9]{64}$/;
const repositoryPattern = /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?(?:\/[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?)+$/;
const versionPattern = /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}$/;
const chartLayer = "application/vnd.cncf.helm.chart.content.v1.tar+gzip";
const accept = [
  "application/vnd.oci.image.index.v1+json",
  "application/vnd.oci.image.manifest.v1+json",
  "application/vnd.docker.distribution.manifest.list.v2+json",
  "application/vnd.docker.distribution.manifest.v2+json",
].join(", ");

async function inspectVersion({ repository, version, username, token }, request = fetch) {
  const authUrl = new URL(`https://${registry}/token`);
  authUrl.searchParams.set("service", registry);
  authUrl.searchParams.set("scope", `repository:${repository}:pull`);
  const headers = username && token
    ? { authorization: `Basic ${Buffer.from(`${username}:${token}`).toString("base64")}` }
    : {};
  const response = await request(authUrl, {
    headers, redirect: "error", signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error(`Unable to authenticate for registry inspection (HTTP ${response.status}).`);
  const { token: accessToken } = await response.json();
  if (typeof accessToken !== "string" || !accessToken) {
    throw new Error("Registry inspection authorization was missing.");
  }
  const manifest = await request(`https://${registry}/v2/${repository}/manifests/${version}`, {
    headers: { authorization: `Bearer ${accessToken}`, accept },
    redirect: "error",
    signal: AbortSignal.timeout(15_000),
  });
  if (manifest.status === 404) {
    const { errors } = await manifest.json();
    if (Array.isArray(errors) && errors.length > 0 &&
        errors.every(error => ["MANIFEST_UNKNOWN", "NAME_UNKNOWN"].includes(error?.code))) {
      return null;
    }
  }
  if (!manifest.ok) throw new Error(`Unable to inspect the current registry version (HTTP ${manifest.status}).`);
  return Buffer.from(await manifest.arrayBuffer());
}

async function planPublication(options, request) {
  const { kind, repository, version, expectedDigest } = options;
  if (!["image", "chart"].includes(kind) || !repositoryPattern.test(repository) ||
      !versionPattern.test(version) || !digestPattern.test(expectedDigest)) {
    throw new Error("Registry version check requires a release image or chart, version and SHA-256 digest.");
  }
  const manifest = await inspectVersion(options, request);
  if (!manifest) return { action: "publish" };

  const manifestDigest = "sha256:" + createHash("sha256").update(manifest).digest("hex");
  let previousDigest = manifestDigest;
  if (kind === "chart") {
    const { schemaVersion, layers } = JSON.parse(manifest);
    const chartLayers = Array.isArray(layers) ? layers.filter(layer => layer?.mediaType === chartLayer) : [];
    if (schemaVersion !== 2 || chartLayers.length !== 1 || !digestPattern.test(chartLayers[0].digest)) {
      throw new Error("The existing chart version has no unique Helm archive digest.");
    }
    previousDigest = chartLayers[0].digest;
  }
  if (previousDigest !== expectedDigest) {
    throw new Error(
      `The published ${kind} version has digest ${previousDigest}, but the candidate has ${expectedDigest}. Preserve the existing version and qualify a new version.`,
    );
  }
  return { action: "reuse", manifestDigest };
}

if (require.main === module) {
  const [kind, repository, version, expectedDigest] = process.argv.slice(2);
  const { GITHUB_ACTOR: username, REGISTRY_TOKEN: token } = process.env;
  const credentialsReady = process.env.GITHUB_ACTIONS !== "true" || (username && token);
  (credentialsReady
    ? planPublication({ kind, repository, version, expectedDigest, username, token })
    : Promise.reject(new Error("Registry inspection credentials are required in Actions.")))
    .then(({ action, manifestDigest }) => {
      if (manifestDigest) console.error(`Reusing verified registry manifest ${manifestDigest}.`);
      console.log(action);
    })
    .catch(error => {
      console.error(error instanceof SyntaxError ? "The registry returned invalid JSON." : error.message);
      process.exitCode = 1;
    });
}

module.exports = { planPublication };
