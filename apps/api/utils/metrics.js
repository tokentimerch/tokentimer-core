const client = require("prom-client");

const httpRequestDuration = new client.Histogram({
  name: "tokentimer_api_http_request_duration_seconds",
  help: "HTTP request duration in seconds",
  labelNames: ["method", "route", "status"],
  buckets: [0.05, 0.1, 0.25, 0.5, 1, 2, 5],
});

const httpRequestsTotal = new client.Counter({
  name: "tokentimer_api_http_requests_total",
  help: "Total number of HTTP requests",
  labelNames: ["method", "route", "status"],
});

const loginAttempts = new client.Counter({
  name: "tokentimer_api_login_attempts_total",
  help: "Login attempts",
  labelNames: ["outcome"],
});

const login2faVerifications = new client.Counter({
  name: "tokentimer_api_2fa_verifications_total",
  help: "2FA verification attempts",
  labelNames: ["outcome"],
});

const rateLimitHits = new client.Counter({
  name: "tokentimer_api_rate_limit_hits_total",
  help: "Rate limit responses (HTTP 429)",
});

const csrfRejections = new client.Counter({
  name: "tokentimer_api_csrf_rejections_total",
  help: "Requests rejected by CSRF protection",
});

const rbacDeniedTotal = new client.Counter({
  name: "tokentimer_api_rbac_denied_total",
  help: "RBAC authorization denials",
});

const workspacesCreatedTotal = new client.Counter({
  name: "tokentimer_api_workspace_created_total",
  help: "Workspaces created",
});

const inviteSentTotal = new client.Counter({
  name: "tokentimer_api_invite_sent_total",
  help: "Workspace invites created",
});

const inviteCancelledTotal = new client.Counter({
  name: "tokentimer_invite_cancelled_total",
  help: "Workspace invites cancelled (pending rows only)",
});

module.exports = {
  httpRequestDuration,
  httpRequestsTotal,
  loginAttempts,
  login2faVerifications,
  rateLimitHits,
  csrfRejections,
  rbacDeniedTotal,
  workspacesCreatedTotal,
  inviteSentTotal,
  inviteCancelledTotal,
};
