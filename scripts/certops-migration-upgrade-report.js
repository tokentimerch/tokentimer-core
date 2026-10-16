"use strict";
/**
 * Checks historical-to-candidate API migration evidence beyond the generic named report contract.
 * Invoked after the isolated upgrade harness; requires exact source, real PostgreSQL schema
 * preservation and public lifecycle transitions, without claiming native agent upgrades.
 */
const assert=require("node:assert/strict"),fs=require("node:fs");
const {BASELINE}=require("./certops-migration-upgrade");
function verifyEvidence(report){
  assert.equal(report.suite,"core-api-migration-upgrade");assert.equal(report.status,"passed");
  assert.ok(["workflow-checkout-source","local-worktree-source-baseline-sha-only"].includes(report.artifactQualification));assert.equal(report.sourceProvenance,"historical-source-build-to-candidate-source");
  assert.equal(report.sourceIdentity?.baseline?.sha,BASELINE);assert.match(report.sourceIdentity?.candidate?.sha||"",/^[a-f0-9]{40}$/);assert.notEqual(report.sourceIdentity.candidate.sha,BASELINE);
  for(const version of ["baseline","candidate"]){assert.match(report.sourceIdentity[version].lockfileSha256||"",/^[a-f0-9]{64}$/);assert.ok(report.sourceIdentity[version].version);}
  assert.match(report.databaseRuntime?.imageId||"",/^sha256:[a-f0-9]{64}$/);assert.match(report.databaseRuntime?.serverVersion||"",/^16\./);
  for(const schema of [report.baselineSchema,report.candidateSchema]){assert.ok(Array.isArray(schema?.migrations)&&schema.migrations.length>0);assert.ok(Number.isInteger(schema.tables)&&schema.tables>0);assert.ok(Number.isInteger(schema.columns)&&schema.columns>=schema.tables);assert.equal(new Set(schema.migrations.map(row=>row.version)).size,schema.migrations.length);}
  for(const row of report.baselineSchema.migrations)assert.ok(report.candidateSchema.migrations.some(candidate=>candidate.version===row.version&&candidate.name===row.name));
  assert.ok(report.candidateSchema.migrations.length>report.baselineSchema.migrations.length);assert.ok(report.candidateSchema.tables>=report.baselineSchema.tables);assert.ok(report.candidateSchema.columns>=report.baselineSchema.columns);
  assert.equal(report.actualTlsObservedPromotion,true);assert.equal(report.repeatMigrationSchemaUnchanged,true);
  return true;
}
if(require.main===module){try{assert.equal(process.argv.length,3);verifyEvidence(JSON.parse(fs.readFileSync(process.argv[2],"utf8")));process.stdout.write("Historical-to-candidate source and migration evidence passed\n");}catch{process.stderr.write("Migration source/schema/transition evidence incomplete\n");process.exitCode=1;}}
module.exports={verifyEvidence};
