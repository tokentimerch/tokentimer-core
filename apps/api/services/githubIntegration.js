"use strict";

const { assertOutboundUrl } = require("@tokentimer/config/network");
const axios = require("axios");
const {
  CREDENTIALED_AXIOS_REDIRECTS,
  joinIntegrationApiUrl,
} = require("./integrationUtils");
const { logger } = require("../utils/logger");

function resolveGitHubApiBase(normalizedUrl) {
  let parsedBase;
  try {
    parsedBase = new URL(normalizedUrl);
  } catch {
    throw new Error("Invalid baseUrl format");
  }
  const githubHost = parsedBase.hostname.toLowerCase();
  if (githubHost === "api.github.com") return normalizedUrl;
  if (githubHost === "github.com" || githubHost === "www.github.com") {
    return "https://api.github.com";
  }
  return normalizedUrl;
}

async function githubRequest({
  baseUrl,
  token,
  method = "GET",
  path,
  params = {},
  timeout = 120000, // Default 120s for regular requests (after initial connection)
  includeResponse = false,
}) {
  const url = joinIntegrationApiUrl(
    baseUrl,
    path.startsWith("/") ? path : `/${path}`,
  );
  const headers = {
    Authorization: `token ${token}`,
    Accept: "application/vnd.github+json",
    "User-Agent": "TokenTimer-Integration",
  };

  const config = {
    method,
    url,
    headers,
    params: method === "GET" ? params : undefined,
    data: method !== "GET" ? params : undefined,
    timeout, // Use provided timeout (allows shorter timeout for initial connection check)
    ...CREDENTIALED_AXIOS_REDIRECTS,
  };

  try {
    assertOutboundUrl(url, { proxyMode: "axios" });
    const response = await axios(config);
    return includeResponse ? response : response.data;
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

function githubPageLinks(headers) {
  const link = headers?.get?.("link") ?? Object.entries(headers || {})
    .find(([key]) => key.toLowerCase() === "link")?.[1];
  if (!link) return {};
  if (typeof link !== "string" || !link.trimStart().startsWith("<")) {
    throw new Error("GitHub returned an invalid pagination link");
  }

  const links = [...link.trimStart().matchAll(/<([^<>]+)>([^<>]*)/g)];
  if (links.map(([part]) => part).join("") !== link.trimStart()) {
    throw new Error("GitHub returned an invalid pagination link");
  }
  const pages = {};
  let recognized = false;
  for (const [, target, attributes] of links) {
    const relations = [...attributes.matchAll(/;\s*rel\s*=\s*(?:"([^"]+)"|([^\s;,]+))/gi)];
    if (relations.length !== 1) throw new Error("GitHub returned an invalid pagination link");
    const [, quoted, bare] = relations[0];
    const rel = (quoted || bare).toLowerCase();
    if (!["first", "prev", "next", "last"].includes(rel)) continue;
    recognized = true;
    if (rel === "first") continue;

    // GitHub may use a canonical repository-ID URL in Link. Retain only its
    // offset, and request the original endpoint with the same host and filters.
    const values = new URL(target, "https://github.invalid").searchParams.getAll("page");
    const page = Number(values[0]);
    if (values.length !== 1 || !/^[1-9]\d*$/.test(values[0]) || !Number.isSafeInteger(page) ||
        (pages[rel] != null && pages[rel] !== page)) {
      throw new Error("GitHub returned invalid or conflicting pagination links");
    }
    pages[rel] = page;
  }
  if (!recognized) throw new Error("GitHub returned an invalid pagination link");
  return pages;
}

function numericItemId(item) {
  const id = item?.id;
  return (typeof id === "string" || Number.isSafeInteger(id)) && /^[1-9]\d*$/.test(String(id))
    ? String(id) : null;
}

function isRepositorySegment(value) {
  return typeof value === "string" && value.trim() === value &&
    !!value && value !== "." && value !== ".." && !/[/\\]/.test(value);
}

function repositoryId(repo) {
  return isRepositorySegment(repo?.owner?.login) && isRepositorySegment(repo?.name)
    ? numericItemId(repo) : null;
}

// GitHub supplies Link pagination on repository, key and secret lists. The
// Actions secrets response also carries a total count. An absent Link on a
// nonempty page alone is not proof of exhaustion when an intermediary strips
// headers. Retain trustworthy rows and check another page within the budget.
async function collectGitHubList({
  baseUrl, token, path, params = {}, maxItems = 2000, getId = numericItemId, wrappedSecrets = false,
}) {
  const items = [];
  const seen = new Set();
  const perPage = Math.min(100, maxItems);
  let expectedLast;
  let expectedTotal;
  let promisedThrough = 0;
  try {
    for (let page = 1; page <= 100; page++) {
      const { data, headers } = await githubRequest({ baseUrl, token, path,
        params: { ...params, page, per_page: perPage }, includeResponse: true });
      const entries = wrappedSecrets ? data?.secrets : data;
      if (!Array.isArray(entries)) throw new Error("GitHub listing returned an invalid page");

      let invalidItems = false;
      for (const entry of entries.slice(0, perPage)) {
        const id = getId(entry);
        if (!id || seen.has(id)) {
          invalidItems = true;
          continue;
        }
        seen.add(id);
        if (items.length < maxItems) items.push(entry);
      }

      const { next, prev, last } = githubPageLinks(headers);
      const total = wrappedSecrets ? data.total_count : undefined;
      const inconsistentMetadata =
        (last != null && expectedLast != null && expectedLast !== last) ||
        (total !== undefined && (!Number.isSafeInteger(total) || total < 0 ||
          (expectedTotal != null && expectedTotal !== total)));
      expectedLast ??= last;
      expectedTotal ??= total;
      const hasNext = next != null || page < expectedLast || seen.size < expectedTotal;
      const endConfirmed = page === expectedLast || seen.size === expectedTotal || (prev != null && !hasNext);
      if (
        invalidItems || inconsistentMetadata || entries.length > perPage ||
        (next != null && next !== page + 1) || (prev != null && prev !== page - 1) ||
        (hasNext && endConfirmed) ||
        (!entries.length && (hasNext || page <= promisedThrough)) ||
        (entries.length && page > expectedLast) || seen.size > expectedTotal
      ) {
        throw new Error("GitHub pagination did not advance reliably");
      }
      if (!hasNext && (endConfirmed || !entries.length)) {
        return { items, truncated: seen.size > items.length };
      }
      if (hasNext) promisedThrough = page + 1;
      if (items.length === maxItems && (hasNext || seen.size > items.length)) return { items, truncated: true };
    }
    return { items, truncated: true };
  } catch (error) {
    return { items, truncated: false, error };
  }
}

async function listRepositories({ baseUrl, token, maxItems = 2000 }) {
  const { items: repos, ...coverage } = await collectGitHubList({
    baseUrl, token, path: "/user/repos", maxItems, getId: repositoryId,
    params: { sort: "updated", direction: "desc" },
  });
  return { repos, ...coverage };
}

function listRepoSecrets({ baseUrl, token, owner, repo, maxItems }) {
  const path = `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/actions/secrets`;
  return collectGitHubList({ baseUrl, token, path, maxItems, wrappedSecrets: true,
    getId: (item) => typeof item?.name === "string" && item.name.trim() === item.name ? item.name : null });
}

function listRepoDeployKeys({ baseUrl, token, owner, repo, maxItems }) {
  const path = `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/keys`;
  return collectGitHubList({ baseUrl, token, path, maxItems });
}

function listSSHKeys({ baseUrl, token, maxItems }) {
  return collectGitHubList({ baseUrl, token, path: "/user/keys", maxItems });
}

function listWarning(error) {
  if (!error) return {};
  if ([401, 403, 404].includes(error.status)) {
    return { note: `A GitHub list was unavailable or access was denied (HTTP ${error.status}).`, status: error.status };
  }
  return { error: error.message, status: error.status };
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

  const normalizedUrl = baseUrl.endsWith("/")
    ? baseUrl.slice(0, -1)
    : baseUrl;
  const apiBase = resolveGitHubApiBase(normalizedUrl);

  logger.info("Starting GitHub scan", { maxItems });

  const items = [];
  const summary = [];
  const cleanupParentIds = {};
  let host = null;
  let ghUser = null;

  try {
    // The host anchors every GitHub token's provenance (see
    // sourceIdentity.js) so that two GitHub Enterprise instances with
    // colliding user/repo ids can never cross-delete each other's tokens.
    host = new URL(apiBase).host;

    // Get current user info
    // Use short timeout (15s) for initial connection check - fail fast if unreachable
    try {
      ghUser = await githubRequest({
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
        const { items: sshKeys, truncated: keysListTruncated, error } = await listSSHKeys({ baseUrl: apiBase, token, maxItems });
        logger.info("GitHub SSH keys retrieved", { count: sshKeys.length });
        let sshKeysSkippedByCap = 0;
        for (const key of sshKeys) {
          if (items.length >= maxItems) {
            sshKeysSkippedByCap++;
            continue;
          }
          // GitHub SSH keys don't have expiration dates in the API
          items.push({
            source: "github-ssh-key",
            sourceKind: "github-ssh-key",
            sourceObjectId: String(key.id),
            name: key.title || `SSH Key (${key.id})`,
            category: "key_secret",
            type: "ssh_key",
            expiration: null, // GitHub doesn't expose expiration for SSH keys
            location: `github:user/keys/${key.id}`,
            created_at: key.created_at || null,
            last_used_at: key.last_used_at || null,
          });
        }
        const truncated = keysListTruncated || sshKeysSkippedByCap > 0;
        summary.push({
          type: "ssh_keys",
          sourceKind: "github-ssh-key",
          found: sshKeys.length,
          truncated,
          ...listWarning(error),
          complete: !error && !truncated,
        });
      } catch (e) {
        logger.error("GitHub SSH keys scan failed", {
          error: e.message,
          status: e.status,
        });
        summary.push({ type: "ssh_keys", sourceKind: "github-ssh-key",
          ...listWarning(e), complete: false });
      }
    }

    // Both per-repository scopes use the same enumeration, including any
    // partial coverage from an interrupted repository list.
    let repositoryList;
    const getRepositories = () => repositoryList ??= listRepositories({ baseUrl: apiBase, token });

    // Scan Repository Secrets (Actions secrets)
    if (include.secrets) {
      try {
        const { repos, truncated: reposListTruncated, error: reposListError } = await getRepositories();
        let secretsCount = 0;
        let reposFailed = 0;
        let reposSkippedByCap = 0;
        let listsTruncated = false;
        let listError = reposListError;
        const BATCH_SIZE = 10;

        for (let i = 0; i < repos.length; i += BATCH_SIZE) {
          if (items.length >= maxItems) {
            reposSkippedByCap += repos.length - i;
            break;
          }
          const batch = repos.slice(i, i + BATCH_SIZE);

          await Promise.all(
            batch.map(async (repo) => {
              if (items.length >= maxItems) {
                reposSkippedByCap++;
                return;
              }
              try {
                const { items: secrets, truncated, error } = await listRepoSecrets({
                  baseUrl: apiBase,
                  token,
                  owner: repo.owner.login,
                  repo: repo.name,
                  maxItems,
                });
                if (error) {
                  reposFailed++;
                  listError ??= error;
                }
                listsTruncated ||= truncated;
                for (const secret of secrets) {
                  if (items.length >= maxItems) {
                    listsTruncated = true;
                    break;
                  }
                  // GitHub secrets don't expose expiration dates in the API
                  items.push({
                    source: "github-secret",
                    sourceKind: "github-secret",
                    sourceObjectId: `${repo.id}:${secret.name}`,
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
              } catch (error) {
                // Skip repos we can't access, but count them so a scan
                // that couldn't see every repo's secrets is never reported
                // complete for this sub-scope.
                reposFailed++;
                listError ??= error;
              }
            }),
          );
        }
        // "Complete" requires: the repo list itself was exhaustive, every
        // repo we did visit succeeded, and the shared item cap never cut
        // the scan short before every repo was visited.
        const truncated =
          reposListTruncated || listsTruncated || reposSkippedByCap > 0;
        cleanupParentIds["github-secret"] = repos.map(repo => String(repo.id));
        summary.push({
          type: "repository_secrets",
          sourceKind: "github-secret",
          found: secretsCount,
          reposFailed,
          reposSkippedByCap,
          truncated,
          ...listWarning(listError),
          complete: !listError && !truncated,
        });
      } catch (e) {
        if (e.status === 403) {
          summary.push({
            type: "repository_secrets",
            sourceKind: "github-secret",
            error: "Your PAT needs 'repo' scope",
            complete: false,
          });
        } else {
          summary.push({
            type: "repository_secrets",
            sourceKind: "github-secret",
            error: e.message,
            complete: false,
          });
        }
      }
    }

    // Scan Deploy Keys (repository-scoped keys)
    if (include.deployKeys) {
      try {
        const { repos, truncated: reposListTruncated, error: reposListError } = await getRepositories();
        let deployKeysCount = 0;
        let reposFailed = 0;
        let reposSkippedByCap = 0;
        let listsTruncated = false;
        let listError = reposListError;
        const BATCH_SIZE = 10;

        for (let i = 0; i < repos.length; i += BATCH_SIZE) {
          if (items.length >= maxItems) {
            reposSkippedByCap += repos.length - i;
            break;
          }
          const batch = repos.slice(i, i + BATCH_SIZE);

          await Promise.all(
            batch.map(async (repo) => {
              if (items.length >= maxItems) {
                reposSkippedByCap++;
                return;
              }
              try {
                const { items: deployKeys, truncated, error } = await listRepoDeployKeys({
                  baseUrl: apiBase,
                  token,
                  owner: repo.owner.login,
                  repo: repo.name,
                  maxItems,
                });
                if (error) {
                  reposFailed++;
                  listError ??= error;
                }
                listsTruncated ||= truncated;
                for (const key of deployKeys) {
                  if (items.length >= maxItems) {
                    listsTruncated = true;
                    break;
                  }
                  items.push({
                    source: "github-deploy-key",
                    sourceKind: "github-deploy-key",
                    sourceObjectId: `${repo.id}:${key.id}`,
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
              } catch (error) {
                reposFailed++;
                listError ??= error;
              }
            }),
          );
        }
        const truncated =
          reposListTruncated || listsTruncated || reposSkippedByCap > 0;
        cleanupParentIds["github-deploy-key"] = repos.map(repo => String(repo.id));
        summary.push({
          type: "deploy_keys",
          sourceKind: "github-deploy-key",
          found: deployKeysCount,
          reposFailed,
          reposSkippedByCap,
          truncated,
          ...listWarning(listError),
          complete: !listError && !truncated,
        });
      } catch (e) {
        summary.push({
          type: "deploy_keys",
          sourceKind: "github-deploy-key",
          error: e.message,
          complete: false,
        });
      }
    }

    if (include.tokens) {
      summary.push({
        type: "personal_access_tokens",
        note: "This scan does not discover GitHub PATs. Track them manually.",
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
  return { items, summary, cleanupParentIds, host, ownerKey: ghUser?.id ? String(ghUser.id) : null };
}

module.exports = {
  scanGitHub,
  resolveGitHubApiBase,
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
