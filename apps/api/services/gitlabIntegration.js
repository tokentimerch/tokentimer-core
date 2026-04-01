"use strict";

const axios = require("axios");
const { tryParseDate, formatDateYmd } = require("./integrationUtils");
const { logger } = require("../utils/logger");

async function gitlabRequest({
  baseUrl,
  token,
  method = "GET",
  path,
  params = {},
  timeout = 120000, // Default 120s for regular requests (after initial connection)
}) {
  const url = new URL(path.startsWith("/") ? path : `/${path}`, baseUrl);
  const headers = {
    "PRIVATE-TOKEN": token,
    "Content-Type": "application/json",
    Accept: "application/json",
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
          'Authentication failed. Token is invalid or expired. Generate a new Personal Access Token with "read_api" scope.';
      } else if (status === 403) {
        userMessage =
          responseData?.message ||
          'Permission denied. Ensure your token has "read_api" scope and you have access to the requested resources.';
      } else if (status === 404) {
        userMessage =
          responseData?.message ||
          "Not a valid GitLab instance. Ensure the URL points to a GitLab server (e.g., https://gitlab.com or your self-hosted GitLab URL).";
      } else if (status === 429) {
        userMessage =
          responseData?.message ||
          "Rate limit exceeded. Please wait a moment and try again.";
      } else if (status >= 500) {
        userMessage =
          responseData?.message ||
          "GitLab server error. Please try again later or contact your GitLab administrator.";
      } else {
        userMessage =
          responseData?.message ||
          responseData?.error ||
          `Request failed with status ${status}`;
      }

      const err = new Error(userMessage);
      err.status = status;
      err.body = responseData;

      // Use debug level for expected permission errors (401/403/404), warn for unexpected errors
      if ([401, 403, 404].includes(status)) {
        logger.debug("GitLab API request permission denied (expected)", {
          method,
          path,
          status,
          baseUrl: baseUrl.replace(/\/\/[^@]+@/, "//***@"), // Mask credentials in URL
        });
      } else {
        logger.warn("GitLab API request failed", {
          method,
          path,
          status,
          baseUrl: baseUrl.replace(/\/\/[^@]+@/, "//***@"), // Mask credentials in URL
        });
      }
      throw err;
    }
    // Network/connection errors - provide more context
    logger.error("GitLab API request error", {
      method,
      path,
      error: error.message,
      code: error.code,
      baseUrl: baseUrl.replace(/\/\/[^@]+@/, "//***@"),
    });

    // Enhance error with better user-facing message
    if (error.code === "ECONNREFUSED") {
      const err = new Error(
        "Connection refused: GitLab instance actively rejected the connection. This typically means:\n• Wrong URL or port\n• GitLab service is not running\n• Firewall blocking the specific port\n\nPlease verify the URL (including protocol and port) and ensure GitLab is running.",
      );
      err.code = "ECONNREFUSED";
      throw err;
    }
    if (error.code === "ENOTFOUND") {
      const err = new Error(
        "DNS resolution failed: Cannot find the GitLab instance. This could mean:\n• Invalid hostname or domain\n• DNS server issues\n• Network connectivity problems\n\nPlease verify the URL is correct and that DNS is properly configured.",
      );
      err.code = "ENOTFOUND";
      throw err;
    }
    if (error.code === "ETIMEDOUT" || error.code === "ECONNABORTED") {
      const err = new Error(
        "Connection timeout: GitLab instance is not responding. This usually indicates:\n• Firewall blocking the connection\n• GitLab instance is unreachable or down\n• Network routing issues\n\nPlease verify the URL, check firewall rules, and ensure the instance is accessible from this server.",
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

// Helper function to detect if a username looks like a service account
// Returns true if the username appears to be a service/bot account
function isServiceAccount(username) {
  if (!username || typeof username !== "string") return false;

  const lowerUsername = username.toLowerCase();
  const serviceKeywords = [
    "bot",
    "service",
    "deploy",
    "ci",
    "cd",
    "automation",
    "pipeline",
    "runner",
    "gitlab-",
    "system",
    "admin-token",
    "api-",
    "token-",
    "app-",
    "svc-",
    "sa-",
  ];

  return serviceKeywords.some((keyword) => lowerUsername.includes(keyword));
}

async function listProjects({ baseUrl, token, maxItems = 2000 }) {
  const projects = [];
  let page = 1;
  const perPage = Math.min(100, maxItems);

  while (projects.length < maxItems) {
    try {
      const data = await gitlabRequest({
        baseUrl,
        token,
        method: "GET",
        path: "/api/v4/projects",
        params: {
          page,
          per_page: perPage,
          simple: true,
          owned: true, // Only projects owned by current user (works on both cloud and self-hosted)
          membership: true, // Include projects user is a member of
          min_access_level: 40, // Maintainer level or above (needed for token management)
        },
      });

      if (!Array.isArray(data)) break;
      if (data.length === 0) break;

      projects.push(...data);
      if (data.length < perPage) break;
      page++;
    } catch (e) {
      if (e.status === 404 || e.status === 403) break;
      throw e;
    }
  }

  return projects.slice(0, maxItems);
}

async function listGroups({ baseUrl, token, maxItems = 2000 }) {
  const groups = [];
  let page = 1;
  const perPage = Math.min(100, maxItems);

  while (groups.length < maxItems) {
    try {
      const data = await gitlabRequest({
        baseUrl,
        token,
        method: "GET",
        path: "/api/v4/groups",
        params: {
          page,
          per_page: perPage,
          min_access_level: 40, // Maintainer level or above (needed for token management)
        },
      });

      if (!Array.isArray(data)) break;
      if (data.length === 0) break;

      groups.push(...data);
      if (data.length < perPage) break;
      page++;
    } catch (e) {
      if (e.status === 404 || e.status === 403) break;
      throw e;
    }
  }

  return groups.slice(0, maxItems);
}

async function listPersonalAccessTokens({
  baseUrl,
  token,
  userId = null,
  state,
}) {
  try {
    const path = userId
      ? `/api/v4/users/${userId}/personal_access_tokens`
      : "/api/v4/personal_access_tokens";
    const params = {};
    if (state) params.state = state;
    const data = await gitlabRequest({
      baseUrl,
      token,
      method: "GET",
      path,
      params,
    });
    return Array.isArray(data) ? data : [];
  } catch (e) {
    if (e.status === 404 || e.status === 403) return [];
    throw e;
  }
}

async function listUsers({ baseUrl, token, maxItems = 500 }) {
  const users = [];
  let page = 1;
  const perPage = Math.min(100, maxItems);

  while (users.length < maxItems) {
    try {
      const data = await gitlabRequest({
        baseUrl,
        token,
        method: "GET",
        path: "/api/v4/users",
        params: {
          page,
          per_page: perPage,
          active: true, // Only active users
        },
      });

      if (!Array.isArray(data)) break;
      if (data.length === 0) break;

      users.push(...data);
      if (data.length < perPage) break;
      page++;
    } catch (e) {
      if (e.status === 404 || e.status === 403) break;
      throw e;
    }
  }

  return users.slice(0, maxItems);
}

async function listProjectAccessTokens({ baseUrl, token, projectId, state }) {
  try {
    const params = {};
    if (state) params.state = state;
    const data = await gitlabRequest({
      baseUrl,
      token,
      method: "GET",
      path: `/api/v4/projects/${projectId}/access_tokens`,
      params,
    });
    return Array.isArray(data) ? data : [];
  } catch (e) {
    if (e.status === 404 || e.status === 403) return [];
    throw e;
  }
}

async function listGroupAccessTokens({ baseUrl, token, groupId, state }) {
  try {
    const params = {};
    if (state) params.state = state;
    const data = await gitlabRequest({
      baseUrl,
      token,
      method: "GET",
      path: `/api/v4/groups/${groupId}/access_tokens`,
      params,
    });
    return Array.isArray(data) ? data : [];
  } catch (e) {
    if (e.status === 404 || e.status === 403) return [];
    throw e;
  }
}

async function listDeployTokens({ baseUrl, token, projectId }) {
  try {
    const data = await gitlabRequest({
      baseUrl,
      token,
      method: "GET",
      path: `/api/v4/projects/${projectId}/deploy_tokens`,
    });
    return Array.isArray(data) ? data : [];
  } catch (e) {
    if (e.status === 404 || e.status === 403) return [];
    throw e;
  }
}

async function listSSHKeys({ baseUrl, token, userId = null }) {
  try {
    const path = userId ? `/api/v4/users/${userId}/keys` : "/api/v4/user/keys";
    const data = await gitlabRequest({
      baseUrl,
      token,
      method: "GET",
      path,
    });
    return Array.isArray(data) ? data : [];
  } catch (e) {
    if (e.status === 404 || e.status === 403) return [];
    throw e;
  }
}

async function scanGitLab({
  baseUrl,
  token,
  include = { tokens: true, keys: true },
  maxItems = 500,
  filters = {
    includePATs: true,
    includeProjectTokens: true,
    includeGroupTokens: true,
    includeDeployTokens: true,
    includeSSHKeys: true,
    excludeUserPATs: false,
    includeExpired: false,
    includeRevoked: false,
  },
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

  // Normalize baseUrl
  const normalizedUrl = baseUrl.endsWith("/") ? baseUrl.slice(0, -1) : baseUrl;
  const isGitLabCloud = normalizedUrl.toLowerCase().includes("gitlab.com");

  logger.info("Starting GitLab scan", {
    baseUrl: baseUrl.replace(/\/\/[^@]+@/, "//***@"),
    maxItems,
    isCloud: isGitLabCloud,
  });

  const items = [];
  const summary = [];
  const BATCH_SIZE = 10; // Concurrency limit for parallel API calls

  try {
    // Get current user info (works on both cloud and self-hosted)
    // Use short timeout (15s) for initial connection check - fail fast if unreachable
    let currentUser = null;
    try {
      currentUser = await gitlabRequest({
        baseUrl: normalizedUrl,
        token,
        method: "GET",
        path: "/api/v4/user",
        timeout: 15000, // 15 second timeout for initial connection/auth check
      });
      logger.info("GitLab user authenticated", {
        userId: currentUser?.id,
        username: currentUser?.username,
        isAdmin: currentUser?.is_admin || false,
      });
    } catch (e) {
      logger.error("Failed to fetch GitLab user info", { error: e.message });

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
        e.message?.includes("Not a valid GitLab instance");

      if (isAuthOrInvalidUrl) {
        throw e;
      }

      // For other errors, add to summary and continue
      summary.push({ type: "user", error: e.message });
    }

    // NOTE: Personal Access Tokens scanning moved to after group/project tokens
    // to enable deduplication of bot user PATs

    // Scan Project Access Tokens first, then Group Access Tokens, then PATs
    // This order ensures we can identify bot users before scanning PATs

    // Scan Project Access Tokens
    // Note: Requires Maintainer/Owner role on projects. Feature introduced in GitLab 13.9.
    // read_api scope is sufficient - admin accounts will see all projects they have access to
    // Cloud: Always available | Self-hosted: May not be available on older versions or free tier
    // We only scan projects where user has min_access_level=40 (Maintainer) to reduce 401/403 errors
    if (include.tokens && filters.includeProjectTokens) {
      try {
        const projects = await listProjects({
          baseUrl: normalizedUrl,
          token,
          maxItems: 1000,
        });
        let projectTokensCount = 0;
        let projectsScanned = 0;
        let projectsWithTokens = 0;
        let skippedRevoked = 0;
        let skippedExpired = 0;

        logger.info("Scanning GitLab project access tokens", {
          totalProjects: projects.length,
        });

        for (let i = 0; i < projects.length; i += BATCH_SIZE) {
          if (items.length >= maxItems) break;
          const batch = projects.slice(i, i + BATCH_SIZE);

          await Promise.all(
            batch.map(async (project) => {
              if (items.length >= maxItems) return;
              projectsScanned++;
              try {
                const projectTokens = await listProjectAccessTokens({
                  baseUrl: normalizedUrl,
                  token,
                  projectId: project.id,
                  state: filters.includeRevoked ? undefined : "active",
                });

                if (projectTokens.length > 0) projectsWithTokens++;

                for (const pt of projectTokens) {
                  if (items.length >= maxItems) break;

                  // Skip revoked/inactive tokens unless includeRevoked filter is enabled
                  if (
                    !filters.includeRevoked &&
                    (pt.revoked === true || pt.active === false)
                  ) {
                    skippedRevoked++;
                    continue;
                  }

                  const expiresAt = pt.expires_at
                    ? tryParseDate(pt.expires_at)
                    : null;

                  // Skip expired tokens unless includeExpired filter is enabled
                  if (
                    expiresAt &&
                    expiresAt < new Date() &&
                    !filters.includeExpired
                  ) {
                    skippedExpired++;
                    continue;
                  }

                  items.push({
                    source: "gitlab-project-token",
                    name: pt.name || `Project Access Token (${pt.id})`,
                    category: "key_secret",
                    type: "api_key",
                    expiration: expiresAt ? formatDateYmd(expiresAt) : null,
                    location: `gitlab:projects/${project.id}/access_tokens/${pt.id}`,
                    project_id: project.id,
                    project_name: project.name || project.path_with_namespace,
                    scopes: pt.scopes || [],
                    created_at: pt.created_at || null,
                    last_used_at: pt.last_used_at || null,
                    // Add username if available in the response
                    token_username: pt.username || null,
                    // Store user_id to help identify bot users in PAT deduplication
                    token_user_id: pt.user_id || null,
                  });
                  projectTokensCount++;
                }
              } catch (_e) {
                // Expected: user may see project but can't access its tokens (401/403/404)
                // This is normal and we silently skip these projects
              }
            }),
          );
        }
        logger.info("GitLab project tokens scan completed", {
          projectsScanned,
          projectsWithTokens,
          tokensFound: projectTokensCount,
          skippedRevoked,
          skippedExpired,
        });
        summary.push({
          type: "project_access_tokens",
          found: projectTokensCount,
          skippedRevoked,
          skippedExpired,
        });
      } catch (e) {
        // Feature may not be available on older self-hosted instances
        if (e.status === 404 && !isGitLabCloud) {
          logger.info(
            "Project access tokens endpoint not available (older GitLab version or feature not enabled)",
          );
          summary.push({
            type: "project_access_tokens",
            note: "Not available (GitLab 13.9+ required)",
          });
        } else {
          logger.warn("Project access tokens scan failed", {
            error: e.message,
            status: e.status,
          });
          summary.push({ type: "project_access_tokens", error: e.message });
        }
      }
    }

    // Scan Group Access Tokens
    // Note: Requires Maintainer/Owner role on groups. Feature introduced in GitLab 14.7.
    // read_api scope is sufficient
    // Cloud: Always available | Self-hosted: May not be available on older versions or free tier
    if (include.tokens && filters.includeGroupTokens) {
      try {
        const groups = await listGroups({
          baseUrl: normalizedUrl,
          token,
          maxItems: 1000,
        });
        let groupTokensCount = 0;
        let groupsScanned = 0;
        let groupsWithTokens = 0;
        let skippedRevoked = 0;
        let skippedExpired = 0;

        logger.info("Scanning GitLab group access tokens", {
          totalGroups: groups.length,
        });

        for (let i = 0; i < groups.length; i += BATCH_SIZE) {
          if (items.length >= maxItems) break;
          const batch = groups.slice(i, i + BATCH_SIZE);

          await Promise.all(
            batch.map(async (group) => {
              if (items.length >= maxItems) return;
              groupsScanned++;
              try {
                const groupTokens = await listGroupAccessTokens({
                  baseUrl: normalizedUrl,
                  token,
                  groupId: group.id,
                  state: filters.includeRevoked ? undefined : "active",
                });

                if (groupTokens.length > 0) groupsWithTokens++;

                for (const gt of groupTokens) {
                  if (items.length >= maxItems) break;

                  // Skip revoked/inactive tokens unless includeRevoked filter is enabled
                  if (
                    !filters.includeRevoked &&
                    (gt.revoked === true || gt.active === false)
                  ) {
                    skippedRevoked++;
                    continue;
                  }

                  const expiresAt = gt.expires_at
                    ? tryParseDate(gt.expires_at)
                    : null;

                  // Skip expired tokens unless includeExpired filter is enabled
                  if (
                    expiresAt &&
                    expiresAt < new Date() &&
                    !filters.includeExpired
                  ) {
                    skippedExpired++;
                    continue;
                  }

                  items.push({
                    source: "gitlab-group-token",
                    name: gt.name || `Group Access Token (${gt.id})`,
                    category: "key_secret",
                    type: "api_key",
                    expiration: expiresAt ? formatDateYmd(expiresAt) : null,
                    location: `gitlab:groups/${group.id}/access_tokens/${gt.id}`,
                    group_id: group.id,
                    group_name: group.name || group.full_path,
                    scopes: gt.scopes || [],
                    created_at: gt.created_at || null,
                    last_used_at: gt.last_used_at || null,
                    token_username: gt.username || null,
                    // Store user_id to help identify bot users in PAT deduplication
                    token_user_id: gt.user_id || null,
                  });
                  groupTokensCount++;
                }
              } catch (_e) {
                // Expected: user may see group but can't access its tokens (401/403/404)
                // This is normal and we silently skip these groups
              }
            }),
          );
        }
        logger.info("GitLab group tokens scan completed", {
          groupsScanned,
          groupsWithTokens,
          tokensFound: groupTokensCount,
          skippedRevoked,
          skippedExpired,
        });
        summary.push({
          type: "group_access_tokens",
          found: groupTokensCount,
          skippedRevoked,
          skippedExpired,
        });
      } catch (e) {
        // Feature may not be available on older self-hosted instances
        if (e.status === 404 && !isGitLabCloud) {
          logger.info(
            "Group access tokens endpoint not available (older GitLab version or feature not enabled)",
          );
          summary.push({
            type: "group_access_tokens",
            note: "Not available (GitLab 14.7+ required)",
          });
        } else {
          logger.warn("Group access tokens scan failed", {
            error: e.message,
            status: e.status,
          });
          summary.push({ type: "group_access_tokens", error: e.message });
        }
      }
    }

    // Scan Personal Access Tokens
    // Note: This endpoint requires GitLab 13.3+ and read_api scope
    // Admin users: Scan ALL users' PATs across the instance
    // Regular users: Only see their own PATs
    // Cloud: Always available | Self-hosted: May not be available on older versions
    // IMPORTANT: This scan runs AFTER project/group tokens to enable deduplication of bot user PATs
    if (include.tokens && filters.includePATs) {
      try {
        let patsFound = 0;
        const isAdmin = currentUser?.is_admin || false;

        let skippedRevoked = 0; // Declare at function scope for admin scanning
        let skippedExpired = 0; // Track expired tokens that are skipped
        let skippedUserPATs = 0; // Track user PATs excluded when excludeUserPATs is enabled
        let skippedBotUserPATs = 0; // Track bot user PATs that are duplicates of group/project tokens

        // Build a set of bot user IDs from group and project tokens to avoid duplicates
        // Group/project access tokens create bot users whose PATs would be counted separately
        const botUserIds = new Set();
        for (const item of items) {
          if (
            (item.source === "gitlab-group-token" ||
              item.source === "gitlab-project-token") &&
            item.token_user_id
          ) {
            botUserIds.add(item.token_user_id);
          }
        }

        if (botUserIds.size > 0) {
          logger.info(
            `Found ${botUserIds.size} bot user IDs from group/project tokens to deduplicate`,
          );
        }

        if (isAdmin) {
          // Admin mode: Get all PATs via admin endpoint
          // Build a user cache first to avoid 500+ individual API calls
          logger.info(
            "Admin user detected - building user cache for PAT scanning",
          );

          try {
            // Build user cache (fetch all users once)
            const userCache = new Map();
            const users = await listUsers({
              baseUrl: normalizedUrl,
              token,
              maxItems: 10000, // Cache up to 10000 users
            });

            for (const user of users) {
              userCache.set(user.id, {
                username: user.username,
                is_admin: user.is_admin || false,
              });
            }

            logger.info(`Built user cache with ${userCache.size} users`);

            // Now fetch all PATs with pagination
            let page = 1;
            const perPage = 100;
            let hasMore = true;

            while (hasMore && patsFound < maxItems) {
              // Use GitLab's state parameter to only fetch active tokens unless includeRevoked is on
              const patParams = {
                page,
                per_page: perPage,
              };
              if (!filters.includeRevoked) {
                patParams.state = "active";
              }
              const pats = await gitlabRequest({
                baseUrl: normalizedUrl,
                token,
                method: "GET",
                path: "/api/v4/personal_access_tokens",
                params: patParams,
              });

              if (!Array.isArray(pats) || pats.length === 0) {
                hasMore = false;
                break;
              }

              logger.info(`Fetched ${pats.length} PATs from page ${page}`, {
                samplePat: pats[0]
                  ? {
                      id: pats[0].id,
                      name: pats[0].name,
                      user_id: pats[0].user_id,
                      active: pats[0].active,
                      revoked: pats[0].revoked,
                    }
                  : null,
              });

              // Process PATs using cached user info
              for (const pat of pats) {
                if (items.length >= maxItems) break;

                // Skip PATs that belong to bot users (group/project token bot accounts)
                // This prevents double counting the same token as both group/project token and PAT
                if (pat.user_id && botUserIds.has(pat.user_id)) {
                  skippedBotUserPATs++;
                  continue;
                }

                // Skip revoked/inactive PATs unless includeRevoked filter is enabled
                // GitLab marks rotated tokens as active:false; revoked tokens as revoked:true
                if (
                  !filters.includeRevoked &&
                  (pat.revoked === true || pat.active === false)
                ) {
                  skippedRevoked++;
                  continue;
                }

                const expiresAt = pat.expires_at
                  ? tryParseDate(pat.expires_at)
                  : null;

                // Skip expired tokens unless includeExpired filter is enabled
                if (
                  expiresAt &&
                  expiresAt < new Date() &&
                  !filters.includeExpired
                ) {
                  skippedExpired++;
                  continue;
                }

                // Lookup user from cache
                const user = pat.user_id ? userCache.get(pat.user_id) : null;
                const username = user?.username || null;
                const isUserAdmin = user?.is_admin || false;

                // Skip user PATs if excludeUserPATs filter is enabled (keep only service account PATs)
                if (
                  filters.excludeUserPATs &&
                  username &&
                  !isServiceAccount(username)
                ) {
                  skippedUserPATs++;
                  continue;
                }

                items.push({
                  source: "gitlab-pat",
                  name: pat.name || `Personal Access Token (${pat.id})`,
                  category: "key_secret",
                  type: "api_key",
                  expiration: expiresAt ? formatDateYmd(expiresAt) : null,
                  location: username
                    ? `gitlab:users/${username}/personal_access_tokens/${pat.id}`
                    : `gitlab:personal_access_tokens/${pat.id}`,
                  scopes: pat.scopes || [],
                  created_at: pat.created_at || null,
                  last_used_at: pat.last_used_at || null,
                  // Include actual owner information
                  gitlab_owner: username,
                  gitlab_owner_is_admin: isUserAdmin,
                });
                patsFound++;
              }

              if (pats.length < perPage) {
                hasMore = false;
              }
              page++;
            }
          } catch (e) {
            logger.warn("Admin PAT scanning failed", {
              error: e.message,
            });
          }
        } else {
          // Regular user mode: Only scan own PATs
          // If excludeUserPATs is enabled, check if current user is a service account
          const currentUsername = currentUser?.username;
          const shouldScanOwnPATs =
            !filters.excludeUserPATs ||
            (currentUsername && isServiceAccount(currentUsername));

          if (shouldScanOwnPATs) {
            const pats = await listPersonalAccessTokens({
              baseUrl: normalizedUrl,
              token,
              userId: null,
              state: filters.includeRevoked ? undefined : "active",
            });
            for (const pat of pats) {
              if (items.length >= maxItems) break;

              // Skip revoked/inactive PATs unless includeRevoked filter is enabled
              if (
                !filters.includeRevoked &&
                (pat.revoked === true || pat.active === false)
              ) {
                skippedRevoked++;
                continue;
              }

              const expiresAt = pat.expires_at
                ? tryParseDate(pat.expires_at)
                : null;

              // Skip expired tokens unless includeExpired filter is enabled
              if (
                expiresAt &&
                expiresAt < new Date() &&
                !filters.includeExpired
              ) {
                skippedExpired++;
                continue;
              }

              items.push({
                source: "gitlab-pat",
                name: pat.name || `Personal Access Token (${pat.id})`,
                category: "key_secret",
                type: "api_key",
                expiration: expiresAt ? formatDateYmd(expiresAt) : null,
                location: `gitlab:personal_access_tokens/${pat.id}`,
                scopes: pat.scopes || [],
                created_at: pat.created_at || null,
                last_used_at: pat.last_used_at || null,
              });
              patsFound++;
            }
          } else {
            logger.info(
              "Skipping own PATs - excludeUserPATs filter enabled and user is not a service account",
            );
          }
        }

        logger.info("GitLab personal access tokens scan completed", {
          found: patsFound,
          isAdmin,
          usersScanned: isAdmin ? "all" : "self",
          skippedRevoked: isAdmin ? skippedRevoked : undefined,
          skippedExpired,
          skippedUserPATs: filters.excludeUserPATs
            ? skippedUserPATs
            : undefined,
          skippedBotUserPATs,
        });
        summary.push({
          type: "personal_access_tokens",
          found: patsFound,
          skippedExpired,
          skippedUserPATs: filters.excludeUserPATs
            ? skippedUserPATs
            : undefined,
          skippedBotUserPATs,
        });
      } catch (e) {
        // On self-hosted instances with older versions, this endpoint may not exist
        if (e.status === 404 && !isGitLabCloud) {
          logger.info(
            "Personal access tokens endpoint not available (older GitLab version)",
          );
          summary.push({
            type: "personal_access_tokens",
            note: "Not available (GitLab 13.3+ required)",
          });
        } else {
          logger.warn("Personal access tokens scan failed", {
            error: e.message,
            status: e.status,
          });
          summary.push({ type: "personal_access_tokens", error: e.message });
        }
      }
    }

    // Scan Deploy Tokens
    // Note: Requires Maintainer/Owner role. Available on both cloud and self-hosted (GitLab 10.7+)
    // We only scan projects where user has min_access_level=40 to reduce permission errors
    if (include.tokens && filters.includeDeployTokens) {
      try {
        const projects = await listProjects({
          baseUrl: normalizedUrl,
          token,
          maxItems: 1000,
        });
        let deployTokensCount = 0;
        let projectsScanned = 0;
        let projectsWithTokens = 0;

        logger.info("Scanning GitLab deploy tokens", {
          totalProjects: projects.length,
        });

        for (let i = 0; i < projects.length; i += BATCH_SIZE) {
          if (items.length >= maxItems) break;
          const batch = projects.slice(i, i + BATCH_SIZE);

          await Promise.all(
            batch.map(async (project) => {
              if (items.length >= maxItems) return;
              projectsScanned++;
              try {
                const deployTokens = await listDeployTokens({
                  baseUrl: normalizedUrl,
                  token,
                  projectId: project.id,
                });

                if (deployTokens.length > 0) projectsWithTokens++;

                for (const dt of deployTokens) {
                  if (items.length >= maxItems) break;
                  const expiresAt = dt.expires_at
                    ? tryParseDate(dt.expires_at)
                    : null;

                  // Skip expired tokens unless includeExpired filter is enabled
                  if (
                    expiresAt &&
                    expiresAt < new Date() &&
                    !filters.includeExpired
                  ) {
                    continue;
                  }

                  items.push({
                    source: "gitlab-deploy-token",
                    name: dt.name || `Deploy Token (${dt.id})`,
                    category: "key_secret",
                    type: "api_key",
                    expiration: expiresAt ? formatDateYmd(expiresAt) : null,
                    location: `gitlab:projects/${project.id}/deploy_tokens/${dt.id}`,
                    project_id: project.id,
                    project_name: project.name || project.path_with_namespace,
                    scopes: dt.scopes || [],
                    created_at: dt.created_at || null,
                    last_used_at: dt.last_used_at || null,
                  });
                  deployTokensCount++;
                }
              } catch (_e) {
                // Expected: user may see project but can't access its tokens (401/403/404)
                // This is normal and we silently skip these projects
              }
            }),
          );
        }
        logger.info("GitLab deploy tokens scan completed", {
          projectsScanned,
          projectsWithTokens,
          tokensFound: deployTokensCount,
        });
        summary.push({ type: "deploy_tokens", found: deployTokensCount });
      } catch (e) {
        logger.warn("Deploy tokens scan failed", {
          error: e.message,
          status: e.status,
        });
        summary.push({ type: "deploy_tokens", error: e.message });
      }
    }

    // Scan SSH Keys (user's own keys only)
    if (include.keys && filters.includeSSHKeys) {
      try {
        // Always use the user endpoint (no userId) - admin endpoint requires elevated privileges
        const sshKeys = await listSSHKeys({
          baseUrl: normalizedUrl,
          token,
          userId: null,
        });
        for (const key of sshKeys) {
          if (items.length >= maxItems) break;
          const expiresAt = key.expires_at
            ? tryParseDate(key.expires_at)
            : null;

          // Skip expired SSH keys unless includeExpired filter is enabled
          if (expiresAt && expiresAt < new Date() && !filters.includeExpired) {
            continue;
          }

          items.push({
            source: "gitlab-ssh-key",
            name: key.title || `SSH Key (${key.id})`,
            category: "key_secret",
            type: "ssh_key",
            expiration: expiresAt ? formatDateYmd(expiresAt) : null,
            location: `gitlab:user/keys/${key.id}`,
            created_at: key.created_at || null,
            last_used_at: key.last_used_at || null,
          });
        }
        summary.push({ type: "ssh_keys", found: sshKeys.length });
      } catch (e) {
        summary.push({ type: "ssh_keys", error: e.message });
      }
    }
  } catch (e) {
    logger.error("GitLab scan failed", {
      error: e.message,
      baseUrl: baseUrl.replace(/\/\/[^@]+@/, "//***@"),
    });
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
    const err = new Error(
      'Authentication failed. Ensure your Personal Access Token has "read_api" scope and is not expired. Admin accounts: read_api is sufficient to scan projects, tokens, and keys you have access to.',
    );
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
        "Connection timeout: GitLab instance is not responding. This usually indicates:\n• Firewall blocking the connection\n• GitLab instance is unreachable or down\n• Network routing issues\n\nPlease verify the URL, check firewall rules, and ensure the instance is accessible from this server.";
      errorCode = "ECONNABORTED";
    } else if (
      originalError.includes("refused") ||
      originalError.includes("ECONNREFUSED")
    ) {
      userMessage =
        "Connection refused: GitLab instance actively rejected the connection. This typically means:\n• Wrong URL or port\n• GitLab service is not running\n• Firewall blocking the specific port\n\nPlease verify the URL (including protocol and port) and ensure GitLab is running.";
      errorCode = "ECONNREFUSED";
    } else if (
      originalError.includes("GETADDRINFO") ||
      originalError.includes("EAI_AGAIN") ||
      originalError.includes("ENOTFOUND")
    ) {
      userMessage =
        "DNS resolution failed: Cannot find the GitLab instance. This could mean:\n• Invalid hostname or domain\n• DNS server issues\n• Network connectivity problems\n\nPlease verify the URL is correct and that DNS is properly configured.";
      errorCode = "ENOTFOUND";
    } else if (
      originalError.includes("reset") ||
      originalError.includes("ECONNRESET")
    ) {
      userMessage =
        "Connection reset: The network connection was interrupted. This may indicate:\n• Firewall dropping connections\n• Network instability\n• Proxy or load balancer issues\n\nPlease check network stability and firewall configuration.";
      errorCode = "ECONNRESET";
    } else {
      userMessage = `Network error: ${originalError}\n\nPlease check your network connection, firewall rules, and verify the GitLab URL is correct and accessible.`;
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

  // Count results by type for better logging
  const resultsByType = {
    personalTokens: items.filter((i) => i.source === "gitlab-pat").length,
    projectTokens: items.filter((i) => i.source === "gitlab-project-token")
      .length,
    groupTokens: items.filter((i) => i.source === "gitlab-group-token").length,
    deployTokens: items.filter((i) => i.source === "gitlab-deploy-token")
      .length,
    sshKeys: items.filter((i) => i.source === "gitlab-ssh-key").length,
  };

  logger.info("GitLab scan completed", {
    itemsFound: items.length,
    isCloud: isGitLabCloud,
    instanceType: isGitLabCloud ? "GitLab.com" : "Self-hosted",
    baseUrl: baseUrl.replace(/\/\/[^@]+@/, "//***@"),
    ...resultsByType,
  });

  return { items, summary };
}

module.exports = {
  scanGitLab,
};

// Test-only exports for unit coverage of helpers
if (process.env.NODE_ENV === "test") {
  module.exports._test = {
    gitlabRequest,
    listProjects,
    listPersonalAccessTokens,
    listProjectAccessTokens,
    listDeployTokens,
    listSSHKeys,
  };
}
