"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { resolveInstalledAgentRowId, retireInstalledAgent, cleanupInstalledAgent, assertInstallIdentityResolved } = require("../tests/e2e/linux-systemd-real-journey");
const EXPECTED_ROW_ID="d89b4df5-f82a-4db7-a10d-53f45a507181", CONSUMER_ID="a89b4df5-f82a-4db7-a10d-53f45a507181", SERVICE_KEY="b".repeat(64);
const ownedProof=()=>({id:CONSUMER_ID,serviceKey:SERVICE_KEY,path:"/owned/installed-discovery-random/server.crt",fingerprint:"a".repeat(64),hostname:"test-host"});

test("registration anchors exactly one workspace-scoped agent UUID", async()=>{
  const calls=[];const pool={query:async(sql,params)=>{calls.push({sql,params});return {rows:[{id:EXPECTED_ROW_ID}]};}};
  assert.equal(await resolveInstalledAgentRowId({pool,workspaceId:"workspace",agentId:"candidate-host-42"}),EXPECTED_ROW_ID);
  assert.deepEqual(calls[0].params,["workspace","candidate-host-42"]);
  for(const rows of [[],[{id:"invalid"}],[{id:EXPECTED_ROW_ID},{id:EXPECTED_ROW_ID}]])
    await assert.rejects(resolveInstalledAgentRowId({pool:{query:async()=>({rows})},workspaceId:"workspace",agentId:"candidate-host-42"}));
});

test("retirement resolves the installed public agent ID to its workspace-scoped UUID", async () => {
  const workspaceId = "52d0545a-5844-4e07-8bd1-4524416c970a";
  const rowId = "d89b4df5-f82a-4db7-a10d-53f45a507181";
  const publicAgentId = "candidate-linux-42";
  const queries = [];
  const client = { async query(sql, params) { queries.push({ sql, params }); return { rows: sql.startsWith("SELECT") ? [{ id: rowId }] : [] }; }, release() { queries.push({ sql: "RELEASE" }); } };
  const pool = { connect: async () => client };
  let passed;
  await retireInstalledAgent({ pool, workspaceId, agentId: publicAgentId, agentRowId:rowId, userId: 19, retireAgent: async options => { passed = options; return { retiredNow: true, agent: { id: rowId, agentId: publicAgentId, status: "retired" } }; } });
  assert.equal(queries[0].sql, "BEGIN");
  assert.match(queries[1].sql, /workspace_id\s*=\s*\$1\s+AND\s+agent_id\s*=\s*\$2\s+FOR UPDATE/i);
  assert.deepEqual(queries[1].params, [workspaceId, publicAgentId]);
  assert.equal(passed.agentId, rowId);
  assert.equal(passed.workspaceId, workspaceId);
  assert.equal(passed.retiredBy, 19);
  assert.equal(passed.client, client);
  assert.deepEqual(queries.slice(2).map(q => q.sql), ["COMMIT", "RELEASE"]);
});

test("retirement refuses missing, ambiguous or malformed rows before changing state", async () => {
  for (const rows of [[], [{ id: "not-a-uuid" }], [{ id: "d89b4df5-f82a-4db7-a10d-53f45a507181" }, { id: "e89b4df5-f82a-4db7-a10d-53f45a507181" }]]) {
    let called = false;
    const client = { query: async sql => ({ rows: sql.startsWith("SELECT") ? rows : [] }), release() {} };
    await assert.rejects(retireInstalledAgent({ pool: { connect: async () => client }, workspaceId: "workspace", agentId: "candidate-host-42", agentRowId:EXPECTED_ROW_ID, userId: 19, retireAgent: async () => { called = true; } }));
    assert.equal(called, false);
  }
});

test("retirement fails closed when the target was not newly retired", async () => {
  const client = { query: async sql => ({ rows: sql.startsWith("SELECT") ? [{ id: "d89b4df5-f82a-4db7-a10d-53f45a507181" }] : [] }), release() {} };
  const pool = { connect: async () => client };
  await assert.rejects(retireInstalledAgent({ pool, workspaceId: "workspace", agentId: "candidate-host-42", agentRowId:EXPECTED_ROW_ID, userId: 19, retireAgent: async () => ({ retiredNow: false }) }), /not newly retired/);
});

test("retirement rolls back when returned identity differs from the locked agent", async () => {
  const calls = [], rowId = "d89b4df5-f82a-4db7-a10d-53f45a507181";
  const client = { query: async sql => { calls.push(sql); return { rows: sql.startsWith("SELECT") ? [{ id: rowId }] : [] }; }, release() { calls.push("RELEASE"); } };
  await assert.rejects(retireInstalledAgent({ pool: { connect: async () => client }, workspaceId: "workspace", agentId: "candidate-host-42", agentRowId:rowId, userId: 19, retireAgent: async () => ({ retiredNow: true, agent: { id: rowId, agentId: "other", status: "retired" } }) }));
  assert.deepEqual(calls.map(sql => sql.startsWith("SELECT") ? "SELECT" : sql), ["BEGIN", "SELECT", "ROLLBACK", "RELEASE"]);
});

function cleanupFixture({ consumers = [{ id: "a89b4df5-f82a-4db7-a10d-53f45a507181" }], failDeleteAgent = false } = {}) {
  const calls = [];
  const rowId = "d89b4df5-f82a-4db7-a10d-53f45a507181";
  const consumerId = "a89b4df5-f82a-4db7-a10d-53f45a507181";
  const client = { async query(sql, params) {
    calls.push({ sql, params });
    if (/SELECT id FROM certops_agents/.test(sql)) return { rows: [{ id: rowId }] };
    if (/SELECT d.id FROM certops_discovered_consumers/.test(sql)) return { rows: consumers };
    if (/DELETE FROM certops_discovered_consumers/.test(sql)) return { rows: [{ id: consumerId }] };
    if (/DELETE FROM certops_agents/.test(sql)) { if (failDeleteAgent) throw new Error("foreign key"); return { rows: [{ id: rowId }] }; }
    return { rows: [] };
  }, release() { calls.push({ sql: "RELEASE" }); } };
  return { pool: { connect: async () => client }, calls, rowId, consumerId };
}

test("cleanup deletes only the identified fixture consumer and agent in one transaction", async () => {
  const f = cleanupFixture();
  const proof = ownedProof();
  await cleanupInstalledAgent({ pool: f.pool, workspaceId: "workspace", agentId: "candidate-host-42", agentRowId:f.rowId, discoveryResources: [{ ownedConsumer: () => proof }] });
  const sql = f.calls.map(c => c.sql);
  assert.equal(sql[0], "BEGIN");
  assert.match(sql[1], /FOR UPDATE/);
  assert.match(sql[2], /source_kind\s*=\s*'filesystem'/i);
  assert.match(sql[2], /service_identity\s*=\s*\$3.*material_location\s*=\s*\$3/is);
  for (const statement of [sql[2], sql[3]]) {
    assert.match(statement, /service_key\s*=\s*\$6/i);
    assert.match(statement, /d\.id\s*=\s*\$7/i);
  }
  assert.deepEqual(f.calls[2].params, ["workspace", f.rowId, proof.path, proof.fingerprint, proof.hostname, proof.serviceKey, f.consumerId]);
  assert.deepEqual(f.calls[3].params, f.calls[2].params);
  assert.match(sql[4], /DELETE FROM certops_agents/);
  assert.equal(sql[5], "COMMIT");
  assert.equal(sql[6], "RELEASE");
});

test("cleanup rolls back if fixture identity is absent, ambiguous, or agent has another dependency", async () => {
  for (const options of [{ consumers: [] }, { consumers: [{ id: "one" }, { id: "two" }] }, { failDeleteAgent: true }]) {
    const f = cleanupFixture(options);
    await assert.rejects(cleanupInstalledAgent({ pool: f.pool, workspaceId: "workspace", agentId: "candidate-host-42", agentRowId:f.rowId, discoveryResources: [{ ownedConsumer: ownedProof }] }));
    const sql = f.calls.map(c => c.sql);
    assert.ok(sql.includes("ROLLBACK"));
    assert.ok(!sql.includes("COMMIT"));
    assert.equal(sql.at(-1), "RELEASE");
    if (!options.failDeleteAgent) assert.ok(!sql.some(s => /DELETE FROM certops_/.test(s)));
  }
});

test("an attempted installation with unknown agent identity cannot discard its ownership receipt", () => {
  assert.throws(() => assertInstallIdentityResolved(true, undefined), /identity is unresolved/);
  assert.doesNotThrow(() => assertInstallIdentityResolved(false, undefined));
  assert.throws(() => assertInstallIdentityResolved(true, "candidate-linux-42"));
  assert.doesNotThrow(() => assertInstallIdentityResolved(true, "candidate-linux-42", EXPECTED_ROW_ID));
});

test("uncertain database commit is reported and never acknowledged as cleanup success", async () => {
  const f = cleanupFixture();
  const client = await f.pool.connect();
  const query = client.query;
  client.query = async (sql, params) => {
    if (sql === "COMMIT") { f.calls.push({ sql }); throw new Error("commit response lost"); }
    return query.call(client, sql, params);
  };
  await assert.rejects(cleanupInstalledAgent({ pool: f.pool, workspaceId: "workspace", agentId: "candidate-host-42", agentRowId:f.rowId, discoveryResources: [{ ownedConsumer: ownedProof }] }), /commit response lost/);
  assert.deepEqual(f.calls.slice(-3).map(c => c.sql), ["COMMIT", "ROLLBACK", "RELEASE"]);
});

test("replaced agent UUID aborts retirement and cleanup before mutation",async()=>{
  let called=false;const f=cleanupFixture();
  await assert.rejects(cleanupInstalledAgent({pool:f.pool,workspaceId:"workspace",agentId:"candidate-host-42",agentRowId:"e89b4df5-f82a-4db7-a10d-53f45a507181",discoveryResources:[{ownedConsumer:ownedProof}]}),/identity changed/);
  assert.ok(!f.calls.some(c=>/DELETE FROM/.test(c.sql)));
  await assert.rejects(retireInstalledAgent({pool:f.pool,workspaceId:"workspace",agentId:"candidate-host-42",agentRowId:"e89b4df5-f82a-4db7-a10d-53f45a507181",userId:19,retireAgent:async()=>{called=true;}}),/identity changed/);
  assert.equal(called,false);
});

test("replacement of the anchored consumer UUID refuses and rolls back",async()=>{
  const f=cleanupFixture({consumers:[{id:"e89b4df5-f82a-4db7-a10d-53f45a507181"}]});
  await assert.rejects(cleanupInstalledAgent({pool:f.pool,workspaceId:"workspace",agentId:"candidate-host-42",agentRowId:f.rowId,discoveryResources:[{ownedConsumer:ownedProof}]}),/identity changed/);
  assert.ok(!f.calls.some(c=>/DELETE FROM/.test(c.sql)));
  assert.ok(f.calls.some(c=>c.sql==="ROLLBACK"));
});
