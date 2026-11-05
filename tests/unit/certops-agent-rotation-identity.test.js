"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const express = require("node:module").createRequire(path.resolve(__dirname, "../../apps/api/package.json"))("express");
const supertest = require("supertest");
const { createCertOpsAgentRouter } = require("../../apps/api/routes/certops-agent");
const { createAgentCredentialAuth } = require("../../apps/api/middleware/agent-auth");

test("identity route binds response to authenticated bearer and refuses retired or invalid credentials", async () => {
  const agents = {};
  const active = "ttagent_"+"1".repeat(16)+"_"+"1".repeat(64);
  const other = "ttagent_"+"2".repeat(16)+"_"+"2".repeat(64);
  const retired = "ttagent_"+"3".repeat(16)+"_"+"3".repeat(64);
  agents[active] = { id:"11111111-1111-4111-8111-111111111111", agentId:"agent-a", workspaceId:"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", status:"active" };
  agents[other] = { id:"22222222-2222-4222-8222-222222222222", agentId:"agent-b", workspaceId:"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", status:"active" };
  agents[retired] = { id:"33333333-3333-4333-8333-333333333333", agentId:"agent-c", workspaceId:"cccccccc-cccc-4ccc-8ccc-cccccccccccc", status:"retired" };
  const next = (_req, _res, proceed) => proceed();
  const app = express();
  app.use(express.json());
  app.use(createCertOpsAgentRouter({
    rotationEnv: { CERTOPS_AGENT_ROTATION_ALL_API_FENCED:"true" },
    credentialAuthMiddleware: createAgentCredentialAuth({ validateAgentCredential: ({rawCredential}) => Promise.resolve({valid: !!agents[rawCredential], agent: agents[rawCredential]}) }),
    readRotationAgentIdentity: ({agent}) => Promise.resolve(agent),
    preAuthRateLimitMiddleware: next, rateLimitMiddleware: next, certOpsEnabledMiddleware: next,
  }));
  const route = "/api/v1/certops/agent/credential-rotation/identity";
  const result = await supertest(app).post(route).query({agentId:"agent-b",workspaceId:"workspace-b"}).set("Authorization", `Bearer ${active}`).send({});
  assert.equal(result.status, 200);
  assert.deepEqual(result.body, {id:agents[active].id,agentId:agents[active].agentId,workspaceId:agents[active].workspaceId});
  assert.equal(result.headers["cache-control"], "no-store");
  assert.equal((await supertest(app).post(route).set("Authorization", `Bearer ${other}`).send({})).body.workspaceId, agents[other].workspaceId);
  assert.equal((await supertest(app).post(route).set("Authorization", `Bearer ${retired}`).send({})).status, 410);
  assert.equal((await supertest(app).post(route).set("Authorization", "Bearer invalid").send({})).status, 401);
  assert.equal((await supertest(app).post(route).set("Authorization", `Bearer ${active}`).send({ workspaceId:"workspace-b" })).status, 400);
  const validAgent = { ...agents[active] };
  for (const bad of [{id:"invalid"},{agentId:"bad/agent"},{workspaceId:"invalid"}]) {
    agents[active] = { ...validAgent, ...bad };
    assert.equal((await supertest(app).post(route).set("Authorization", `Bearer ${active}`).send({})).status, 503);
  }
  const disabled = express();
  disabled.use(createCertOpsAgentRouter({ rotationEnv:{}, preAuthRateLimitMiddleware:next }));
  assert.equal((await supertest(disabled).post(route).set("Authorization", `Bearer ${active}`).send({})).status, 404);
});
