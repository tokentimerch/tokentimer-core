"use strict";

const axios = require("axios");
const { logger } = require("../utils/logger");

async function githubRequest({
  baseUrl,
  token,
  method = "GET",
  path,
  params = {},
  timeout = 120000, // Default 120s for regular requests (after initial connection)
}) {
  const url = new URL(path.startsWith("/") ? path : `/${path}`, baseUrl);
  const headers = {
    Authorization: `token ${token}`,
    Accept: "application/vnd.github.v3+json",
    "User-Agent": "TokenTimer-Integration",
  };

  const config = {
    method,
    url: url.toString(),
    headers,
    params: method === "GET" ? params : undefined,
    data: method !== "GET" ? params : undefined,
    timeout, // Use provided timeout (allows shorter timeout for initial connection check)
  };

  try {
    const response = await axios(config);
    return response.data;
  } catch (error) {
    if (error.response) {
      const status = error.response.status;
      const responseData = error.response.data;

      // Build a user-friendly error message based on status code
      let userMessage;
      if (status === 401) {
        userMessage =
          responseData?.message ||
          "Authentication failed. Token is invalid or expired. Generate a new Personal Access Token with required scopes.";
      } else if (status === 403) {
        userMessage =
          responseData?.message ||
          "Permission denied. Ensure your token has the required scopes and you have access to the requested resources.";
      } else if (status === 404) {
        userMessage =
          responseData?.message ||
          "Not a valid GitHub instance. Ensure the URL points to GitHub.com or your GitHub Enterprise server.";
      } else if (status === 429) {
        userMessage =
          responseData?.message ||
          "Rate limit exceeded. Please wait and try again.";
      } else if (status >= 500) {
        userMessage =
          responseData?.message ||
          "GitHub server error. Please try again later.";
      } else {
        userMessage =
          responseData?.message ||
          responseData?.error ||
          `Request failed with status ${status}`;
      }

      const err = new Error(userMessage);
      err.status = status;
      err.body = responseData;

      logger.warn("GitHub API request failed", {
        method,
        path,
        status,
      });
      throw err;
    }

    // Network/connection errors - provide more context
    logger.error("GitHub API request error", {
      method,
      path,
      error: error.message,
      code: error.code,
    });

    // Enhance error with better user-facing message
    if (error.code === "ECONNREFUSED") {
      const err = new Error(
        "Connection refused: GitHub instance actively rejected the connection. This typically means:\n• Wrong URL or port\n• GitHub service is not running\n• Firewall blocking the specific port\n\nPlease verify the URL (including protocol and port) and ensure GitHub is running.",
      );
      err.code = "ECONNREFUSED";
      throw err;
    }
    if (error.code === "ENOTFOUND") {
      const err = new Error(
        "DNS resolution failed: Cannot find the GitHub instance. This could mean:\n• Invalid hostname or domain\n• DNS server issues\n• Network connectivity problems\n\nPlease verify the URL is correct and that DNS is properly configured.",
      );
      err.code = "ENOTFOUND";
      throw err;
    }
    if (error.code === "ETIMEDOUT" || error.code === "ECONNABORTED") {
      const err = new Error(
        "Connection timeout: GitHub instance is not responding. This usually indicates:\n• Firewall blocking the connection\n• GitHub instance is unreachable or down\n• Network routing issues\n\nPlease verify the URL, check firewall rules, and ensure the instance is accessible from this server.",
      );
      err.code = error.code;
      throw err;
    }
    if (error.code === "ECONNRESET" || error.code === "EPIPE") {
      const err = new Error(
        "Connection reset: The network connection was interrupted. This may indicate:\n• Firewall dropping connections\n• Network instability\n• Proxy or load balancer issues\n\nPlease check network stability and firewall configuration.",
      );
      err.code = error.code;
      throw err;
    }
    if (error.code === "EAI_AGAIN") {
      const err = new Error(
        "DNS resolution failed: Temporary DNS lookup failure. This could mean:\n• DNS server temporarily unavailable\n• Network connectivity issues\n• DNS resolver overloaded\n\nPlease retry in a moment or check your DNS configuration.",
      );
      err.code = "EAI_AGAIN";
      throw err;
    }

    throw error;
  }
}

async function listRepositories({ baseUrl, token, maxItems = 100 }) {
  const repos = [];
  let page = 1;
  const perPage = Math.min(100, maxItems);

  while (repos.length < maxItems) {
    try {
      const data = await githubRequest({
        baseUrl,
        token,
        method: "GET",
        path: "/user/repos",
        params: { page, per_page: perPage, sort: "updated", direction: "desc" },
      });

      if (!Array.isArray(data)) break;
      if (data.length === 0) break;

      repos.push(...data);
      if (data.length < perPage) break;
      page++;
    } catch (e) {
      if (e.status === 404 || e.status === 403) break;
      throw e;
    }
  }

  return repos.slice(0, maxItems);
}

async function listRepoSecrets({ baseUrl, token, owner, repo }) {
  try {
    const data = await githubRequest({
      baseUrl,
      token,
      method: "GET",
      path: `/repos/${owner}/${repo}/actions/secrets`,
    });
    return Array.isArray(data.secrets) ? data.secrets : [];
  } catch (e) {
    if (e.status === 404 || e.status === 403) return [];
    throw e;
  }
}

async function listRepoDeployKeys({ baseUrl, token, owner, repo }) {
  try {
    const data = await githubRequest({
      baseUrl,
      token,
      method: "GET",
      path: `/repos/${owner}/${repo}/keys`,
    });
    return Array.isArray(data) ? data : [];
  } catch (e) {
    if (e.status === 404 || e.status === 403) return [];
    throw e;
  }
}

async function listSSHKeys({ baseUrl, token }) {
  const data = await githubRequest({
    baseUrl,
    token,
    method: "GET",
    path: "/user/keys",
  });
  return Array.isArray(data) ? data : [];
}

async function scanGitHub({
  baseUrl,
  token,
  include = { tokens: true, sshKeys: true, deployKeys: true, secrets: true },
  maxItems = 500,
}) {
  if (!baseUrl || !token) throw new Error("baseUrl and token are required");

  // Validate inputs
  if (typeof baseUrl !== "string" || baseUrl.length > 500) {
    throw new Error("Invalid baseUrl format");
  }
  if (typeof token !== "string" || token.length > 500) {
    throw new Error("Invalid token format");
  }
  if (!Number.isInteger(maxItems) || maxItems < 1 || maxItems > 2000) {
    throw new Error("maxItems must be between 1 and 2000");
  }

  logger.info("Starting GitHub scan", { maxItems });

  const items = [];
  const summary = [];

  try {
    // Normalize baseUrl (default to github.com if not provided)
    const normalizedUrl = baseUrl.endsWith("/")
      ? baseUrl.slice(0, -1)
      : baseUrl;
    const apiBase = normalizedUrl.includes("api.github.com")
      ? normalizedUrl
      : normalizedUrl === "https://github.com" ||
          normalizedUrl === "http://github.com"
        ? "https://api.github.com"
        : normalizedUrl;

    // Get current user info
    // Use short timeout (15s) for initial connection check - fail fast if unreachable
    try {
      await githubRequest({
        baseUrl: apiBase,
        token,
        method: "GET",
        path: "/user",
        timeout: 15000, // 15 second timeout for initial connection/auth check
      });
      logger.info("GitHub user authenticated");
    } catch (e) {
      logger.error("Failed to fetch GitHub user info", { error: e.message });

      // If initial connection fails with a network error, fail immediately
      // Don't waste time trying other scans if we can't even connect
      const isNetworkError =
        e.code === "ECONNABORTED" ||
        e.code === "ETIMEDOUT" ||
        e.code === "ECONNREFUSED" ||
        e.code === "ENOTFOUND" ||
        e.code === "ECONNRESET" ||
        e.code === "EPIPE" ||
        e.message?.includes("timeout") ||
        e.message?.includes("Connection");

      if (isNetworkError) {
        // Throw immediately with the detailed error message
        const err = new Error(e.message);
        err.code = e.code;
        throw err;
      }

      // For auth/404 errors on initial user check, fail immediately
      // If the token is invalid or URL is wrong, all subsequent scans will fail anyway
      const isAuthOrInvalidUrl =
        e.status === 401 ||
        e.status === 403 ||
        e.status === 404 ||
        e.message?.includes("Authentication failed") ||
        e.message?.includes("Unauthorized") ||
        e.message?.includes("Permission denied") ||
        e.message?.includes("Forbidden") ||
        e.message?.includes("Not a valid GitHub instance") ||
        e.message?.includes("Endpoint not found");

      if (isAuthOrInvalidUrl) {
        throw e;
      }

      // Initial user check failed for other reasons - this indicates wrong URL
      // Fail immediately rather than continuing with likely-invalid URL
      const userFriendlyError = new Error(
        "GitHub user authentication failed: " +
          (e.message || "Unable to verify GitHub credentials") +
          "\n\nPlease verify:\n• URL points to GitHub.com or GitHub Enterprise\n• Token is valid\n• Token has required scopes",
      );
      userFriendlyError.status = e.status || 400;
      throw userFriendlyError;
    }

    // Scan SSH Keys (user's personal SSH keys)
    if (include.sshKeys) {
      try {
        const sshKeys = await listSSHKeys({ baseUrl: apiBase, token });
        logger.info("GitHub SSH keys retrieved", { count: sshKeys.length });
        for (const key of sshKeys) {
          if (items.length >= maxItems) break;
          // GitHub SSH keys don't have expiration dates in the API
          items.push({
            source: "github-ssh-key",
            name: key.title || `SSH Key (${key.id})`,
            category: "key_secret",
            type: "ssh_key",
            expiration: null, // GitHub doesn't expose expiration for SSH keys
            location: `github:user/keys/${key.id}`,
            created_at: key.created_at || null,
            last_used_at: key.last_used_at || null,
          });
        }
        summary.push({ type: "ssh_keys", found: sshKeys.length });
      } catch (e) {
        logger.error("GitHub SSH keys scan failed", {
          error: e.message,
          status: e.status,
        });
        // 404 on SSH keys endpoint usually means wrong API base URL - fail immediately
        if (e.status === 404) {
          const err = new Error(
            "Invalid GitHub API URL: The SSH keys endpoint was not found. This usually means:\n• Wrong API base URL\n• Not a valid GitHub instance\n• URL points to GitHub website instead of API\n\nPlease ensure the URL is correct (e.g., https://api.github.com for GitHub.com or https://github.example.com/api/v3 for Enterprise).",
          );
          err.status = 404;
          throw err;
        }
        if (e.status === 403) {
          summary.push({
            type: "ssh_keys",
            error:
              "Your PAT needs 'read:public_key' or 'admin:public_key' scope",
          });
        } else {
          summary.push({
            type: "ssh_keys",
            error: e.message || "Unknown error",
          });
        }
      }
    }

    // Scan Repository Secrets (Actions secrets)
    if (include.secrets) {
      try {
        const repos = await listRepositories({
          baseUrl: apiBase,
          token,
          maxItems: 100,
        });
        let secretsCount = 0;
        const BATCH_SIZE = 10;

        for (let i = 0; i < repos.length; i += BATCH_SIZE) {
          if (items.length >= maxItems) break;
          const batch = repos.slice(i, i + BATCH_SIZE);

          await Promise.all(
            batch.map(async (repo) => {
              if (items.length >= maxItems) return;
              try {
                const secrets = await listRepoSecrets({
                  baseUrl: apiBase,
                  token,
                  owner: repo.owner.login,
                  repo: repo.name,
                });
                for (const secret of secrets) {
                  if (items.length >= maxItems) break;
                  // GitHub secrets don't expose expiration dates in the API
                  items.push({
                    source: "github-secret",
                    name: secret.name || `Secret (${secret.name})`,
                    category: "key_secret",
                    type: "secret",
                    expiration: null, // GitHub doesn't expose expiration for secrets
                    location: `github:repos/${repo.owner.login}/${repo.name}/actions/secrets/${secret.name}`,
                    repository: repo.full_name,
                    created_at: secret.created_at || null,
                    updated_at: secret.updated_at || null,
                    last_used_at: null, // GitHub Secrets don't expose last used in this API
                  });
                  secretsCount++;
                }
              } catch (_e) {
                // Skip repos we can't access
              }
            }),
          );
        }
        summary.push({ type: "repository_secrets", found: secretsCount });
      } catch (e) {
        if (e.status === 403) {
          summary.push({
            type: "repository_secrets",
            error: "Your PAT needs 'repo' scope",
          });
        } else {
          summary.push({ type: "repository_secrets", error: e.message });
        }
      }
    }

    // Scan Deploy Keys (repository-scoped keys)
    if (include.deployKeys) {
      try {
        const repos = await listRepositories({
          baseUrl: apiBase,
          token,
          maxItems: 100,
        });
        let deployKeysCount = 0;
        const BATCH_SIZE = 10;

        for (let i = 0; i < repos.length; i += BATCH_SIZE) {
          if (items.length >= maxItems) break;
          const batch = repos.slice(i, i + BATCH_SIZE);

          await Promise.all(
            batch.map(async (repo) => {
              if (items.length >= maxItems) return;
              try {
                const deployKeys = await listRepoDeployKeys({
                  baseUrl: apiBase,
                  token,
                  owner: repo.owner.login,
                  repo: repo.name,
                });
                for (const key of deployKeys) {
                  if (items.length >= maxItems) break;
                  items.push({
                    source: "github-deploy-key",
                    name: key.title || `Deploy Key (${key.id})`,
                    category: "key_secret",
                    type: "ssh_key",
                    expiration: null, // GitHub doesn't expose expiration for deploy keys
                    location: `github:repos/${repo.owner.login}/${repo.name}/keys/${key.id}`,
                    repository: repo.full_name,
                    read_only: key.read_only || false,
                    created_at: key.created_at || null,
                  });
                  deployKeysCount++;
                }
              } catch (_e) {
                // Skip repos we can't access
              }
            }),
          );
        }
        summary.push({ type: "deploy_keys", found: deployKeysCount });
      } catch (e) {
        summary.push({ type: "deploy_keys", error: e.message });
      }
    }

    // Note: GitHub Personal Access Tokens cannot be enumerated via API
    // Users would need to manually track them or use GitHub's token management UI
    if (include.tokens) {
      summary.push({
        type: "personal_access_tokens",
        note: "GitHub PATs cannot be enumerated via API. Please track manually.",
      });
    }
  } catch (e) {
    logger.error("GitHub scan failed", { error: e.message });
    summary.push({ type: "scan", error: e.message });
  }

  // If all scan types failed, throw instead of returning partial results
  const allFailed = summary.every((s) => s.error || s.note);
  const hasAuthError = summary.some(
    (s) =>
      s.error &&
      (s.error.includes("401") ||
        s.error.includes("403") ||
        s.error.includes("Unauthorized") ||
        s.error.includes("Forbidden")),
  );
  const hasNetworkError = summary.some(
    (s) =>
      s.error &&
      (s.error.includes("timeout") ||
        s.error.includes("Connection") ||
        s.error.includes("ECONNREFUSED") ||
        s.error.includes("ENOTFOUND") ||
        s.error.includes("ECONNRESET") ||
        s.error.includes("GETADDRINFO") ||
        s.error.includes("EAI_AGAIN") ||
        s.error.includes("network")),
  );

  if (allFailed && hasAuthError && items.length === 0) {
    const err = new Error("Authentication failed");
    err.status = 401;
    throw err;
  }

  // Throw network errors with user-friendly messages
  if (allFailed && hasNetworkError && items.length === 0) {
    // Find the first network error to provide context
    const networkErrorSummary = summary.find(
      (s) =>
        s.error &&
        (s.error.includes("timeout") ||
          s.error.includes("Connection") ||
          s.error.includes("ECONNREFUSED") ||
          s.error.includes("ENOTFOUND") ||
          s.error.includes("ECONNRESET") ||
          s.error.includes("GETADDRINFO") ||
          s.error.includes("EAI_AGAIN")),
    );

    const originalError = networkErrorSummary?.error || "";
    let userMessage = "";
    let errorCode = null;

    // Provide specific, actionable error messages based on the error type
    if (
      originalError.includes("timeout") ||
      originalError.includes("ETIMEDOUT") ||
      originalError.includes("ECONNABORTED")
    ) {
      userMessage =
        "Connection timeout: GitHub instance is not responding. This usually indicates:\n• Firewall blocking the connection\n• GitHub instance is unreachable or down\n• Network routing issues\n\nPlease verify the URL, check firewall rules, and ensure the instance is accessible from this server.";
      errorCode = "ECONNABORTED";
    } else if (
      originalError.includes("refused") ||
      originalError.includes("ECONNREFUSED")
    ) {
      userMessage =
        "Connection refused: GitHub instance actively rejected the connection. This typically means:\n• Wrong URL or port\n• GitHub service is not running\n• Firewall blocking the specific port\n\nPlease verify the URL (including protocol and port) and ensure GitHub is running.";
      errorCode = "ECONNREFUSED";
    } else if (
      originalError.includes("GETADDRINFO") ||
      originalError.includes("EAI_AGAIN") ||
      originalError.includes("ENOTFOUND")
    ) {
      userMessage =
        "DNS resolution failed: Cannot find the GitHub instance. This could mean:\n• Invalid hostname or domain\n• DNS server issues\n• Network connectivity problems\n\nPlease verify the URL is correct and that DNS is properly configured.";
      errorCode = "ENOTFOUND";
    } else if (
      originalError.includes("reset") ||
      originalError.includes("ECONNRESET")
    ) {
      userMessage =
        "Connection reset: The network connection was interrupted. This may indicate:\n• Firewall dropping connections\n• Network instability\n• Proxy or load balancer issues\n\nPlease check network stability and firewall configuration.";
      errorCode = "ECONNRESET";
    } else {
      userMessage = `Network error: ${originalError}\n\nPlease check your network connection, firewall rules, and verify the GitHub URL is correct and accessible.`;
    }

    const err = new Error(userMessage);
    if (errorCode) err.code = errorCode;
    throw err;
  }

  // If all scans failed with no items found, throw the first error
  // This prevents returning successful responses with error-filled summaries
  if (allFailed && items.length === 0) {
    const firstError = summary.find((s) => s.error);
    if (firstError) {
      const err = new Error(firstError.error);
      throw err;
    }
  }

  logger.info("GitHub scan completed", { itemsFound: items.length });
  return { items, summary };
}

module.exports = {
  scanGitHub,
};

// Test-only exports for unit coverage of helpers
if (process.env.NODE_ENV === "test") {
  module.exports._test = {
    githubRequest,
    listRepositories,
    listRepoSecrets,
    listRepoDeployKeys,
    listSSHKeys,
  };
}
