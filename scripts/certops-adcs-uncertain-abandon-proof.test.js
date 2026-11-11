"use strict";
/**
 * Qualification notes: native zero-request uncertain abandonment
 *
 * Block only certreq outbound to uniquely resolved CA IPv4 matching provisioned domain-ca lab VM,
 * never offline root. Observe durable submitting/exact owned SYSTEM tree, drain; missed phase
 * fails. CA subject count zero every checkpoint; restore transport while stopped before
 * acknowledged public recovery so no-resubmit proof has working CA. Actual persisted
 * lease+ordinary 60s grace+ 30s observation, <=15min prerequisite, measured monotonic timing/no
 * shortened experiment lease. Reconciliation retains CSR/frozen identity/CNG public
 * blob/nonexportability/unknown-effect job. Public abandon schedules normal terminal cleanup:
 * audit/abandoned DB+journal/exact key absent/ no leaf/CA count zero . No journal/state/lease/time
 * fabrication. No SCM failure actions, policy fixed; exact observer closes/drains before
 * receipt/rule release/restart, failed drain preserves state. Three mandatory scenarios separate
 * from pending abandon refusal/crash/survivor qualifications.
 *
 * Shared setup, evidence and cleanup policy: .github/maintainers/certops/e2e-qualification.md.
 */
/* Supporting proof-contract checks, without native host operations. Actual
 * submitting/recovery/abandon qualification requires the disposable forest. */
const assert = require("node:assert/strict");
const test = require("node:test");
const { assertProof, validateDisposableCaAddress, recoveryWaitBudget, createOwnedRecoverySuspension, selectUncertainIssuer } = require("../tests/e2e/helpers/certops-adcs-uncertain-abandon");

test("abandonment followed by candidate recovery preserves the confirmed rotated CA key", async () => {
  const originalKey = "a".repeat(64), currentKey = "b".repeat(64);
  const issuerId = "11111111-1111-4111-8111-111111111111";
  const caConfig = "tt-ca.lab.certops.test\\TTQualificationRoot";
  const current = { ca_key_sha256: currentKey, ca_config: caConfig,
    template: "TTQualificationRSAShort", confirmed_at: new Date(), revalidation_required: false };
  let confirmations = 0;
  const context = { caConfig, api: "/qualification", renewalFixture: {
    issuerId, authority: { keySha256: currentKey }, item: { template: current.template },
  }, fixture: { workspaceId: "22222222-2222-4222-8222-222222222222",
    pool: { async query(sql, args) {
      assert.match(sql, /v.version=i.current_version/);
      assert.match(sql, /v.workspace_id=i.workspace_id/);
      assert.deepEqual(args, [context.fixture.workspaceId, issuerId]);
      return { rows: [{ ...current }] };
    } },
    async request(url, method, body) {
      assert.equal(url, `/qualification/issuers/${issuerId}/confirm`);
      assert.equal(method, "POST"); confirmations++;
      current.ca_key_sha256 = body.caKeySha256; return { status: 200 };
    },
  }, async preflight() { return { issuerId, result: { caCheck: { verdict: "safe" },
    templateCheck: { verdict: "safe" }, caCertificates: [
      { keySha256: originalKey }, { keySha256: currentKey },
    ] } }; } };
  for (const mode of ["abandon", "operator-created-unique", "operator-created-ambiguity"]) {
    assert.equal(await selectUncertainIssuer(context, mode), issuerId);
    assert.equal(current.ca_key_sha256, currentKey,
      "A prior CA certificate must not replace the pin used by later public recovery");
  }
  assert.equal(confirmations, 0, "The existing confirmed native issuer must remain unchanged");
});

test("uncertain setup refuses a stale, unconfirmed or different native issuer", async () => {
  const caConfig = "tt-ca.lab.certops.test\\TTQualificationRoot";
  const keySha256 = "b".repeat(64);
  const current = { ca_key_sha256: keySha256, ca_config: caConfig,
    template: "TTQualificationRSAShort", confirmed_at: new Date(), revalidation_required: false };
  const context = { caConfig, renewalFixture: { issuerId: "11111111-1111-4111-8111-111111111111",
    authority: { keySha256 } }, fixture: { workspaceId: "22222222-2222-4222-8222-222222222222",
    request: () => assert.fail("Qualification must never change issuer confirmation"),
    pool: { query: async () => ({ rows: [{ ...current }] }) } } };
  for (const mutation of [{ ca_key_sha256: "a".repeat(64) }, { ca_config: "foreign" },
    { template: "foreign" }, { confirmed_at: null }, { revalidation_required: true }]) {
    context.fixture.pool.query = async () => ({ rows: [{ ...current, ...mutation }] });
    await assert.rejects(selectUncertainIssuer(context));
  }
  context.fixture.pool.query = async () => ({ rows: [] });
  await assert.rejects(selectUncertainIssuer(context));
  await assert.rejects(selectUncertainIssuer({ ...context, renewalFixture: null }));
});

test("fault suspension restores exact production SCM policy even after a failed disable", () => {
  for (const failDisable of [false, true]) {
    const original={actions:Buffer.from("native-installer-policy").toString("base64"),nonCrash:1};
    let current=original;const commands=[];
    const controller=createOwnedRecoverySuspension({readPolicy:()=>({...current}),command:(exe,args)=>{
      assert.equal(exe,"sc.exe");commands.push(args);
      if(args[3]==="0"){current={...original,actions:"disabled"};if(failDisable)throw Error("SCM response interrupted");}
      else current=original;
    }});
    if(failDisable)assert.throws(()=>controller.suspend(),/interrupted/);else controller.suspend();
    assert.equal(controller.restore(),true);assert.deepEqual(current,original);
    assert.deepEqual(commands.map(args=>args.slice(2)),[["reset=","0","actions=",""],["reset=","86400","actions=","restart/5000"]]);
    assert.equal(controller.restore(),false);
  }
});

test("SCM restore refuses changed ownership and cannot claim different restored bytes", () => {
  const original={actions:"cHJvZHVjdGlvbg==",nonCrash:1};let changed=false;let restores=0;
  const controller=createOwnedRecoverySuspension({readPolicy:()=>{if(changed)throw Error("Foreign service");return original;},command:()=>{restores++;}});
  controller.suspend();changed=true;assert.throws(()=>controller.restore(),/Foreign service/);assert.equal(restores,1);
  let reads=0;
  const mismatch=createOwnedRecoverySuspension({readPolicy:()=>++reads<3?original:{...original,actions:"wrong"},command:()=>{}});
  mismatch.suspend();assert.throws(()=>mismatch.restore(),/captured installer bytes/);
  for(const policy of [{actions:null,nonCrash:1},{actions:"",nonCrash:1},{...original,nonCrash:0}]){
    const unsafe=createOwnedRecoverySuspension({readPolicy:()=>policy,command:()=>assert.fail("Unsafe policy changed")});
    assert.throws(()=>unsafe.suspend());assert.equal(unsafe.restore(),false);
  }
});
function fixture() {
  return { scope: "native-zero-request-uncertain-abandon", ownedTransportBlock: true,
    resolvedIssuingCaAddress: "10.64.0.4", ownedObserverDrained: true,
    leaseRemainingAtFaultMs: 60000, recoveryWaitBudgetMs: 150000, actualLeaseWaitMs: 61000,
    observedSubmittingTermination: true, actualLeaseExpiry: true,
    acknowledgedPublicRecovery: true, sameCsrAndKey: true, noAutomaticResubmit: true,
    publicAbandonAudited: true, unacceptedKeyRemoved: true, originalOrphanPreserved: true,
    recoveryPolicyUnchanged: true, caRequestsAtFault: 0, caRequestsAfterRecovery: 0,
    caRequestsAfterAbandon: 0 };
}
test("uncertain abandon requires every actual native safety observation", () => {
  assert.equal(assertProof(fixture()), true);
  for (const key of Object.keys(fixture())) {
    const report = fixture(); delete report[key]; assert.throws(() => assertProof(report), undefined, key);
  }
});
test("recovery budget follows the actual persisted lease without rewriting clocks", () => {
  const at = "2026-10-14T12:00:00Z";
  assert.deepEqual(recoveryWaitBudget("2026-10-14T12:05:00Z", at), { leaseRemainingAtFaultMs: 300000, recoveryWaitBudgetMs: 390000 });
  assert.deepEqual(recoveryWaitBudget("2026-10-14T11:59:00Z", at), { leaseRemainingAtFaultMs: 0, recoveryWaitBudgetMs: 90000 });
  assert.throws(() => recoveryWaitBudget("2026-10-14T12:30:00Z", at));
  assert.throws(() => recoveryWaitBudget("invalid", at));
});
test("native fault resolves only the provisioned issuing CA, never another host or subnet", () => {
  const ca = "tt-ca.lab.certops.test\\TTQualificationRoot";
  assert.equal(validateDisposableCaAddress(ca, [{ address: "10.64.0.4", family: 4 }]), "10.64.0.4");
  for (const addresses of [[], [{ address: "10.64.0.7" }], [{ address: "10.64.0.5" }], [{ address: "10.65.0.4" }], [{ address: "::1" }], [{ address: "10.64.0.4" }, { address: "10.64.0.7" }]]) assert.throws(() => validateDisposableCaAddress(ca, addresses));
  assert.throws(() => validateDisposableCaAddress("tt-root.lab.certops.test\\TTQualificationOfflineRoot", [{ address: "10.64.0.4" }]));
});
test("a request allocated at any stage or missing safety proof refuses qualification", () => {
  for (const [key, value] of Object.entries(fixture())) {
    if (key === "scope") continue;
    assert.throws(() => assertProof({ ...fixture(), [key]: typeof value === "boolean" ? false : 1 }), undefined, key);
  }
  assert.throws(() => assertProof({ ...fixture(), scope: "enterprise-adcs-journal-phase-experimental" }));
  assert.throws(() => assertProof({ ...fixture(), privateKey: "unapproved report field" }));
});
