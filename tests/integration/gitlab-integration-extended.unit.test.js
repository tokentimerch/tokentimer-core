const { expect } = require("chai");
const Module = require("module");
const path = require("path");

function resolveGitlabModule() {
  const candidates = [
    path.join(
      __dirname,
      "..",
      "..",
      "apps",
      "api",
      "services",
      "gitlabIntegration",
    ),
    path.join(
      __dirname,
      "..",
      "..",
      "apps",
      "saas",
      "integrations",
      "gitlabIntegration",
    ),
  ];
  for (const candidate of candidates) {
    try {
      return require.resolve(candidate);
    } catch (_) {}
  }
  throw new Error("Unable to resolve gitlabIntegration module");
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

async function expectReject(promiseFactory, pattern) {
  try {
    await promiseFactory();
    throw new Error("Expected promise to reject");
  } catch (err) {
    expect(String(err && err.message)).to.match(pattern);
  }
}

describe("GitLab integration helper coverage", () => {
  it("maps status and network errors in gitlabRequest", async () => {
    const axios401 = async () => {
      const err = new Error("unauthorized");
      err.response = { status: 401, data: {} };
      throw err;
    };
    const gitlab401 = requireWithMocks(resolveGitlabModule(), {
      axios: axios401,
    });
    await expectReject(
      () =>
        gitlab401._test.gitlabRequest({
          baseUrl: "https://gitlab.example.com",
          token: "token",
          path: "/api/v4/projects",
        }),
      /(Authentication failed|GitLab|Unauthorized|401)/i,
    );

    const axiosConnRefused = async () => {
      const err = new Error("connect ECONNREFUSED");
      err.code = "ECONNREFUSED";
      throw err;
    };
    const gitlabConn = requireWithMocks(resolveGitlabModule(), {
      axios: axiosConnRefused,
    });
    await expectReject(
      () =>
        gitlabConn._test.gitlabRequest({
          baseUrl: "https://gitlab.example.com",
          token: "token",
          path: "/api/v4/projects",
        }),
      /ECONNREFUSED|connection/i,
    );
  });

  it("paginates listProjects and respects maxItems", async () => {
    let call = 0;
    const axiosMock = async () => {
      call += 1;
      if (call === 1) {
        return {
          data: [{ id: 1 }, { id: 2 }, { id: 3 }],
          headers: {},
        };
      }
      return {
        data: [{ id: 3 }, { id: 4 }],
        headers: {},
      };
    };
    const gitlab = requireWithMocks(resolveGitlabModule(), {
      axios: axiosMock,
    });
    const projects = await gitlab._test.listProjects({
      baseUrl: "https://gitlab.example.com",
      token: "token",
      maxItems: 3,
    });
    expect(projects.map((p) => p.id)).to.deep.equal([1, 2, 3]);
  });

  it("does not filter listProjects by owned, so group projects with Maintainer-only access are included", async () => {
    const seenParams = [];
    const axiosMock = async (config) => {
      seenParams.push(config.params);
      return { data: [], headers: {} };
    };
    const gitlab = requireWithMocks(resolveGitlabModule(), {
      axios: axiosMock,
    });
    await gitlab._test.listProjects({
      baseUrl: "https://gitlab.example.com",
      token: "token",
      maxItems: 100,
    });
    expect(seenParams).to.have.length(1);
    expect(seenParams[0]).to.not.have.property("owned");
    expect(seenParams[0].membership).to.equal(true);
    expect(seenParams[0].min_access_level).to.equal(40);
  });

  it("paginates listPipelineTriggers across multiple pages", async () => {
    let page = 0;
    const axiosMock = async () => {
      page += 1;
      if (page === 1) {
        return {
          data: Array.from({ length: 100 }, (_, idx) => ({ id: idx + 1 })),
          headers: {},
        };
      }
      if (page === 2) return { data: [{ id: 101 }], headers: {} };
      return { data: [], headers: {} };
    };
    const gitlab = requireWithMocks(resolveGitlabModule(), {
      axios: axiosMock,
    });
    const triggers = await gitlab._test.listPipelineTriggers({
      baseUrl: "https://gitlab.example.com",
      token: "token",
      projectId: 7,
      maxItems: 101,
    });
    expect(triggers).to.have.length(101);
    expect(triggers[0].id).to.equal(1);
    expect(triggers[100].id).to.equal(101);
  });

  it("propagates 403 from listPipelineTriggers so callers can distinguish permission errors from empty results", async () => {
    const axiosMock = async () => {
      const err = new Error("forbidden");
      err.response = { status: 403, data: {} };
      throw err;
    };
    const gitlab = requireWithMocks(resolveGitlabModule(), {
      axios: axiosMock,
    });
    await expectReject(
      () =>
        gitlab._test.listPipelineTriggers({
          baseUrl: "https://gitlab.example.com",
          token: "token",
          projectId: 7,
        }),
      /Permission denied|Forbidden|403/i,
    );
  });

  it("returns empty arrays for 404 token listing helpers", async () => {
    const axiosMock = async () => {
      const err = new Error("not found");
      err.response = { status: 404, data: {} };
      throw err;
    };
    const gitlab = requireWithMocks(resolveGitlabModule(), {
      axios: axiosMock,
    });

    const projectTokens = await gitlab._test.listProjectAccessTokens({
      baseUrl: "https://gitlab.example.com",
      token: "token",
      projectId: 123,
      state: "active",
    });
    const deployTokens = await gitlab._test.listDeployTokens({
      baseUrl: "https://gitlab.example.com",
      token: "token",
      projectId: 123,
    });

    expect(projectTokens).to.deep.equal([]);
    expect(deployTokens).to.deep.equal([]);
  });

  it("returns empty list for SSH keys when endpoint is unsupported", async () => {
    const axiosMock = async () => {
      const err = new Error("forbidden");
      err.response = { status: 403, data: {} };
      throw err;
    };
    const gitlab = requireWithMocks(resolveGitlabModule(), {
      axios: axiosMock,
    });
    const keys = await gitlab._test.listSSHKeys({
      baseUrl: "https://gitlab.example.com",
      token: "token",
      userId: 42,
    });
    expect(keys).to.deep.equal([]);
  });

  it("carries GitLab's real description field through to scan items for PATs, project tokens, and group tokens (issue: filter rules on the 'description' field always fell back to name, because the scan never copied GitLab's own description into the item)", async () => {
    const axiosMock = async (config) => {
      const { pathname } = new URL(config.url);
      if (pathname === "/api/v4/user") {
        return { data: { id: 1, username: "alice", is_admin: false } };
      }
      if (pathname === "/api/v4/projects") {
        return { data: [{ id: 10, name: "proj", path_with_namespace: "g/proj" }] };
      }
      if (pathname === "/api/v4/projects/10/access_tokens") {
        return {
          data: [
            {
              id: 100,
              name: "proj-token",
              description: "real project token description",
              active: true,
              scopes: ["api"],
            },
          ],
        };
      }
      if (pathname === "/api/v4/groups") {
        return { data: [{ id: 20, name: "grp", full_path: "grp" }] };
      }
      if (pathname === "/api/v4/groups/20/access_tokens") {
        return {
          data: [
            {
              id: 200,
              name: "group-token",
              description: "real group token description",
              active: true,
              scopes: ["api"],
            },
          ],
        };
      }
      if (pathname === "/api/v4/personal_access_tokens") {
        return {
          data: [
            {
              id: 300,
              name: "pat-name",
              description:
                "To be renewed and put back in tokentimer for auto-sync to work. Only requires read_api",
              active: true,
              scopes: ["read_api"],
            },
          ],
        };
      }
      return { data: [] };
    };
    const gitlab = requireWithMocks(resolveGitlabModule(), {
      axios: axiosMock,
    });
    const { items } = await gitlab.scanGitLab({
      baseUrl: "https://gitlab.example.com",
      token: "token",
      include: { tokens: true, keys: false },
      filters: {
        includePATs: true,
        includeProjectTokens: true,
        includeGroupTokens: true,
        includeDeployTokens: false,
        includeTriggerTokens: false,
        includeSSHKeys: false,
        excludeUserPATs: false,
        includeExpired: false,
        includeRevoked: false,
      },
    });

    const pat = items.find((i) => i.source === "gitlab-pat");
    const projectToken = items.find((i) => i.source === "gitlab-project-token");
    const groupToken = items.find((i) => i.source === "gitlab-group-token");

    expect(pat).to.exist;
    expect(pat.description).to.equal(
      "To be renewed and put back in tokentimer for auto-sync to work. Only requires read_api",
    );
    expect(projectToken).to.exist;
    expect(projectToken.description).to.equal(
      "real project token description",
    );
    expect(groupToken).to.exist;
    expect(groupToken.description).to.equal("real group token description");
  });
});
