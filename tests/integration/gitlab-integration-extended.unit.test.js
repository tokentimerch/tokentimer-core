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
});
