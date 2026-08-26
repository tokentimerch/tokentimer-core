const { expect } = require("chai");
const Module = require("module");
const path = require("path");

function resolveGithubModule() {
  const candidates = [
    path.join(__dirname, "..", "..", "apps", "api", "services", "githubIntegration"),
    path.join(__dirname, "..", "..", "apps", "saas", "integrations", "githubIntegration"),
  ];
  for (const candidate of candidates) {
    try {
      return require.resolve(candidate);
    } catch (_) {}
  }
  throw new Error("Unable to resolve githubIntegration module");
}

function requireWithMocks(modulePath, mocks) {
  const resolved = require.resolve(modulePath);
  delete require.cache[resolved];
  const originalLoad = Module._load;
  const originalNodeEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = "test";
  Module._load = function patchedLoad(request, parent, isMain) {
    if (Object.prototype.hasOwnProperty.call(mocks, request)) {
      return mocks[request];
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  try {
    return require(modulePath);
  } finally {
    Module._load = originalLoad;
    process.env.NODE_ENV = originalNodeEnv;
  }
}

// Builds a mocked GitHub API responder for a single authenticated user with
// one SSH key, one repo secret, and one deploy key -- enough to exercise
// every sourceKind the scan produces.
function buildAxiosMock({ userId, sshKeyId = 501, repoId = 900 }) {
  return async (config) => {
    const { pathname } = new URL(config.url);
    if (pathname === "/user") {
      return { data: { id: userId, login: `user-${userId}` } };
    }
    if (pathname === "/user/keys") {
      return { data: [{ id: sshKeyId, title: "laptop" }] };
    }
    if (pathname === "/user/repos") {
      return {
        data: [
          {
            id: repoId,
            name: "repo",
            full_name: `user-${userId}/repo`,
            owner: { login: `user-${userId}` },
          },
        ],
      };
    }
    if (pathname === `/repos/user-${userId}/repo/actions/secrets`) {
      return { data: { secrets: [{ name: "DEPLOY_SECRET" }] } };
    }
    if (pathname === `/repos/user-${userId}/repo/keys`) {
      return { data: [{ id: 700, title: "ci-deploy-key" }] };
    }
    return { data: [] };
  };
}

describe("GitHub integration host and owner attribution", () => {
  // Regression guard: two GitHub Enterprise instances can easily assign the
  // same numeric user/repo ids to unrelated accounts. If the scan's
  // provenance only carried the owner id (not the host), a cleanup driven
  // by a scan against instance A could delete tokens that were actually
  // imported from instance B. scanGitHub must return a `host` that reflects
  // which server was actually scanned, independent of the numeric owner id.
  it("returns a distinct host per GitHub Enterprise instance even when owner/repo ids collide", async () => {
    const github = requireWithMocks(resolveGithubModule(), {
      axios: buildAxiosMock({ userId: 42, repoId: 900 }),
    });
    const resultA = await github.scanGitHub({
      baseUrl: "https://ghe-a.example.com/api/v3",
      token: "token-a",
      include: { tokens: false, sshKeys: true, deployKeys: true, secrets: true },
    });

    const githubB = requireWithMocks(resolveGithubModule(), {
      axios: buildAxiosMock({ userId: 42, repoId: 900 }),
    });
    const resultB = await githubB.scanGitHub({
      baseUrl: "https://ghe-b.example.com/api/v3",
      token: "token-b",
      include: { tokens: false, sshKeys: true, deployKeys: true, secrets: true },
    });

    expect(resultA.host).to.equal("ghe-a.example.com");
    expect(resultB.host).to.equal("ghe-b.example.com");
    expect(resultA.host).to.not.equal(resultB.host);
    // Same colliding numeric owner id on both instances -- host is what
    // must keep their cleanup scopes apart.
    expect(resultA.ownerKey).to.equal(resultB.ownerKey);
  });

  it("uses the authenticated user's immutable numeric id as ownerKey, not the mutable login", async () => {
    const github = requireWithMocks(resolveGithubModule(), {
      axios: buildAxiosMock({ userId: 4242 }),
    });
    const result = await github.scanGitHub({
      baseUrl: "https://api.github.com",
      token: "token",
      include: { tokens: false, sshKeys: true, deployKeys: false, secrets: false },
    });
    expect(result.ownerKey).to.equal("4242");
  });

  it("tags every scanned item with an explicit sourceKind and sourceObjectId", async () => {
    const github = requireWithMocks(resolveGithubModule(), {
      axios: buildAxiosMock({ userId: 7, repoId: 900 }),
    });
    const result = await github.scanGitHub({
      baseUrl: "https://api.github.com",
      token: "token",
      include: { tokens: false, sshKeys: true, deployKeys: true, secrets: true },
    });

    const sshKey = result.items.find((i) => i.source === "github-ssh-key");
    const secret = result.items.find((i) => i.source === "github-secret");
    const deployKey = result.items.find((i) => i.source === "github-deploy-key");

    expect(sshKey.sourceKind).to.equal("github-ssh-key");
    expect(sshKey.sourceObjectId).to.equal("501");
    expect(secret.sourceKind).to.equal("github-secret");
    expect(secret.sourceObjectId).to.equal("900:DEPLOY_SECRET");
    expect(deployKey.sourceKind).to.equal("github-deploy-key");
    expect(deployKey.sourceObjectId).to.equal("900:700");
  });
});
