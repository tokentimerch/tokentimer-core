"use strict";

/**
 * Attach route-local workspace-access semantics before the shared membership
 * middleware runs. The RBAC layer consumes only this generic marker and has
 * no product-route knowledge.
 */
function hideWorkspaceExistence(req, _res, next) {
  req.workspaceAccessPolicy = {
    ...(req.workspaceAccessPolicy || {}),
    hideExistence: true,
  };
  next();
}

module.exports = { hideWorkspaceExistence };
