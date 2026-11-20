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
function githubApiPathname(url) {
  const { pathname } = new URL(url);
  return pathname.replace(/^\/api\/v3(?=\/)/, "");
}

function buildAxiosMock({ userId, sshKeyId = 501, repoId = 900 }) {
  return async (config) => {
    const pathname = githubApiPathname(config.url);
    if (pathname === "/user") {
      return { data: { id: userId, login: `user-${userId}` } };
    }
    if (config.params?.page > 1) return { data: [] };
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
      return { data: { total_count: 1, secrets: [{ name: "DEPLOY_SECRET" }] } };
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

  it("keeps GitHub Enterprise /api/v3 on API requests", async () => {
    const seen = [];
    const github = requireWithMocks(resolveGithubModule(), {
      axios: async (config) => {
        expect(Object.keys(config.headers).map((name) => name.toLowerCase())).not.to.include("x-github-api-version");
        seen.push(new URL(config.url).pathname);
        return { data: { id: 1, login: "octo" } };
      },
    });
    await github._test.githubRequest({
      baseUrl: "https://ghe.example.com/api/v3",
      token: "token",
      path: "/user",
    });
    expect(seen).to.deep.equal(["/api/v3/user"]);
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
    const requestHeaders = [];
    const respond = buildAxiosMock({ userId: 7, repoId: 900 });
    const github = requireWithMocks(resolveGithubModule(), {
      axios: async (config) => {
        requestHeaders.push(config.headers);
        return respond(config);
      },
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
    expect(requestHeaders.length).to.be.at.least(5);
    for (const headers of requestHeaders) {
      expect(headers.Accept).to.equal("application/vnd.github+json");
      expect(Object.keys(headers).map((name) => name.toLowerCase())).not.to.include("x-github-api-version");
    }
  });

  it("rewrites github.com and www.github.com scans onto api.github.com", async () => {
    const seenHosts = [];
    const github = requireWithMocks(resolveGithubModule(), {
      axios: async (config) => {
        seenHosts.push(new URL(config.url).host);
        const pathname = new URL(config.url).pathname;
        if (pathname === "/user") {
          return { data: { id: 1, login: "octo" } };
        }
        return { data: [] };
      },
    });
    const result = await github.scanGitHub({
      baseUrl: "https://www.github.com",
      token: "token",
      include: {
        tokens: false,
        sshKeys: true,
        deployKeys: false,
        secrets: false,
      },
    });
    expect(seenHosts.length).to.be.greaterThan(1);
    expect(seenHosts.every((host) => host === "api.github.com")).to.equal(true);
    expect(result.host).to.equal("api.github.com");
  });

  it("does not treat a path substring as GitHub cloud", async () => {
    const seenHosts = [];
    const github = requireWithMocks(resolveGithubModule(), {
      axios: async (config) => {
        seenHosts.push(new URL(config.url).host);
        return { data: { id: 1, login: "octo" } };
      },
    });
    await github.scanGitHub({
      baseUrl: "https://evil.example/api.github.com",
      token: "token",
      include: {
        tokens: false,
        sshKeys: false,
        deployKeys: false,
        secrets: false,
      },
    });
    expect(seenHosts.length).to.be.greaterThan(0);
    expect(seenHosts.every((host) => host === "evil.example")).to.equal(true);
  });

  it("prefixes every GitHub Enterprise scan request with /api/v3", async () => {
    const seen = [];
    const github = requireWithMocks(resolveGithubModule(), {
      axios: async (config) => {
        const { pathname } = new URL(config.url);
        seen.push(pathname);
        const apiPath = pathname.replace(/^\/api\/v3(?=\/)/, "");
        if (apiPath === "/user") {
          return { data: { id: 1, login: "octo" } };
        }
        if (apiPath === "/user/keys") {
          return { data: [{ id: 501, title: "laptop" }] };
        }
        return { data: [] };
      },
    });
    await github.scanGitHub({
      baseUrl: "https://ghe.example.com/api/v3",
      token: "token",
      include: {
        tokens: false,
        sshKeys: true,
        deployKeys: false,
        secrets: false,
      },
    });
    expect(seen.length).to.be.greaterThan(1);
    expect(seen.every((pathname) => pathname.startsWith("/api/v3/"))).to.equal(
      true,
    );
    expect(seen).to.include("/api/v3/user");
    expect(seen).to.include("/api/v3/user/keys");
  });
});

describe("GitHub paginated scan coverage", () => {
  const firstRepo = { id: 100, name: "alpha", full_name: "octo/alpha", owner: { login: "octo" } };
  const nextRepo = { id: 200, name: "beta", full_name: "octo/beta", owner: { login: "octo" } };
  const options = {
    baseUrl: "https://ghe.example.com/api/v3",
    token: "synthetic-scan-token",
    include: { tokens: false, sshKeys: true, deployKeys: true, secrets: true },
  };
  const next = { link: '<?page=2>; rel="next"' };
  const prev = { link: '<?page=1>; rel="prev"' };
  const secretsPath = "/repos/octo/alpha/actions/secrets";
  const keysPath = "/repos/octo/alpha/keys";
  const getScope = (result, sourceKind) => result.summary.find(entry => entry.sourceKind === sourceKind);
  const httpError = status => Object.assign(new Error(`HTTP ${status}`), { response: { status, data: {} } });

  function scanner(respond) {
    return requireWithMocks(resolveGithubModule(), { axios: async config => {
      const apiPath = githubApiPathname(config.url);
      if (apiPath === "/user") return { data: { id: 7, login: "octo" } };
      return respond(apiPath, config.params.page, config);
    } });
  }

  it("visits subsequent repository, secret, deploy-key and user-key pages on the original endpoint", async () => {
    const calls = [];
    const github = scanner((apiPath, page, config) => {
      calls.push({ apiPath, page });
      expect(new URL(config.url).origin).to.equal("https://ghe.example.com");
      expect(new URL(config.url).pathname).to.equal(`/api/v3${apiPath}`);
      expect(config.headers.Authorization).to.equal(`token ${options.token}`);
      expect(config.params.per_page).to.equal(100);
      if (apiPath === "/user/repos") {
        expect(config.params.sort).to.equal("updated");
        expect(config.params.direction).to.equal("desc");
        return { data: page === 1 ? [firstRepo] : [nextRepo], headers: page === 1
          ? { link: '<?page=2>; rel="next", <?page=2>; rel="last"' } : prev };
      }
      if (apiPath === "/user/keys") return { data: [{ id: page + 20 }], headers: page === 1 ? next : prev };
      if (apiPath === secretsPath) {
        return { data: { total_count: 2, secrets: [{ name: `SECRET_${page}` }] }, headers: page === 1
          ? { Link: '<https://other.example/repositories/100/actions/secrets?per_page=1&page=2>; rel="next"' }
          : prev };
      }
      if (apiPath === keysPath) return { data: [{ id: page + 30 }], headers: page === 1 ? next : prev };
      if (apiPath === "/repos/octo/beta/actions/secrets") return { data: { total_count: 1, secrets: [{ name: "BETA" }] } };
      if (apiPath === "/repos/octo/beta/keys") return { data: [] };
      throw new Error(`Unexpected fixture path ${apiPath}`);
    });
    const result = await github.scanGitHub(options);
    expect(result.items.map(item => item.sourceObjectId)).to.have.members([
      "21", "22", "100:SECRET_1", "100:SECRET_2", "200:BETA", "100:31", "100:32",
    ]);
    expect(result.summary.every(scope => scope.complete)).to.equal(true);
    expect(calls.filter(call => call.apiPath === "/user/repos").map(call => call.page)).to.deep.equal([1, 2]);
    expect(calls.some(call => call.apiPath === secretsPath && call.page === 2)).to.equal(true);
  });

  for (const [failedPage, status] of [[1, 403], [2, 404], [2, 503]]) {
    it(`preserves observations and reports incomplete when secret page ${failedPage} returns HTTP ${status}`, async () => {
      const github = scanner((apiPath, page) => {
        if (apiPath === "/user/repos") return { data: page === 1 ? [firstRepo] : [] };
        if (apiPath === "/user/keys" || apiPath === keysPath) return { data: [] };
        if (apiPath !== secretsPath || page === failedPage) throw httpError(status);
        return { data: { total_count: 2, secrets: [{ name: "OBSERVED" }] }, headers: next };
      });
      const result = await github.scanGitHub(options);
      expect(result.items.map(item => item.sourceObjectId)).to.deep.equal(failedPage === 1 ? [] : ["100:OBSERVED"]);
      expect(getScope(result, "github-secret")).to.include({ complete: false, status });
      expect(getScope(result, "github-deploy-key").complete).to.equal(true);
    });
  }

  it("retains nested results from a partial repository list while blocking both repo scopes", async () => {
    const github = scanner((apiPath, page) => {
      if (apiPath === "/user/repos") {
        if (page === 2) throw httpError(403);
        return { data: [firstRepo], headers: next };
      }
      if (apiPath === secretsPath) return { data: { total_count: 1, secrets: [{ name: "OBSERVED" }] } };
      if (apiPath === keysPath) return { data: page === 1 ? [{ id: 31 }] : [] };
      return { data: [] };
    });
    const result = await github.scanGitHub(options);
    expect(result.items.map(item => item.sourceObjectId)).to.have.members(["100:OBSERVED", "100:31"]);
    for (const kind of ["github-secret", "github-deploy-key"]) {
      expect(getScope(result, kind)).to.include({ complete: false, status: 403 });
    }
  });

  for (const [label, secondPage] of [
    ["a duplicate secret", { data: { total_count: 2, secrets: [{ name: "OBSERVED" }] } }],
    ["an empty page contradicting total_count", { data: { total_count: 2, secrets: [] } }],
    ["a malformed list", { data: { total_count: 2, secrets: {} } }],
    ["conflicting next links", { data: { total_count: 3, secrets: [{ name: "FIRST" }] },
      headers: { link: '<?page=3>; rel="next", <?page=4>; rel="next"' } }],
  ]) {
    it(`retains observed secrets and blocks completeness after ${label}`, async () => {
      const github = scanner((apiPath, page) => {
        if (apiPath === "/user/repos") return { data: page === 1 ? [firstRepo] : [] };
        if (apiPath === secretsPath) return page === 1
          ? { data: { total_count: 2, secrets: [{ name: "OBSERVED" }] } } : secondPage;
        return { data: [] };
      });
      const result = await github.scanGitHub(options);
      expect(result.items.map(item => item.sourceObjectId)).to.include("100:OBSERVED");
      const coverage = getScope(result, "github-secret");
      expect(coverage.complete).to.equal(false);
      if (label === "conflicting next links") expect(coverage.error).to.match(/conflicting pagination links/);
    });
  }

  it("stops at the SSH item limit while a subsequent page is still advertised", async () => {
    const pages = [];
    const github = scanner((apiPath, page, config) => {
      expect(apiPath).to.equal("/user/keys");
      expect(config.params.per_page).to.equal(1);
      pages.push(page);
      return { data: [{ id: 1 }], headers: next };
    });
    const result = await github.scanGitHub({ ...options, maxItems: 1,
      include: { sshKeys: true, secrets: false, deployKeys: false } });
    expect(result.items.map(item => item.sourceObjectId)).to.deep.equal(["1"]);
    expect(getScope(result, "github-ssh-key")).to.include({ complete: false, truncated: true });
    expect(pages).to.deep.equal([1]);
  });
});
