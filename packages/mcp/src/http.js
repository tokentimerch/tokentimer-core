"use strict";

const { createMcpHandler } = require("@modelcontextprotocol/server");
const { toNodeHandler } = require("@modelcontextprotocol/node");
const { createServerFactory } = require("./server");

function createRemoteHandler() {
  const handler = createMcpHandler(({ authInfo }) => {
    if (!authInfo?.token || !authInfo.extra?.apiOrigin) throw new Error("Verified MCP authority is required");
    const config = {
      origin: authInfo.extra.apiOrigin,
      basePath: "",
      authorizationHeader: () => `Bearer ${authInfo.token}`,
      requestHeaders: authInfo.extra.forwardingHeaders,
      requestTimeoutMs: 30000,
      maxResponseBytes: 2 * 1024 * 1024,
      operatorScopes: authInfo.extra.operatorScopes,
      enableWrites: authInfo.extra.operatorScopes.some((scope) => ["mcp:renew:request", "mcp:issue:request", "mcp:inventory:import", "mcp:inventory:update", "mcp:contacts:create", "mcp:webhooks:create", "mcp:groups:create", "mcp:members:invite"].includes(scope)),
    };
    return createServerFactory(config)();
  }, { responseMode: "json" });
  return toNodeHandler(handler);
}

module.exports = { createRemoteHandler };
