import test from 'node:test';
import assert from 'node:assert/strict';
import { audit, main } from './check-roadmap-drift.mjs';

const now = Date.parse('2026-10-28T12:00:00Z');
const entry = {id:'mcp',issue:502,edition:'core',horizon:'alongside-0.x',inRoadmap:true,
 planningStatus:'In Progress',implementationPr:406,feedback:[{slug:'mcp',status:'In Progress'}]};
const index = {schemaVersion:1,repository:'tokentimerch/tokentimer-core',reviewedAt:'2026-10-28',outcomes:[entry]};
const roadmap = 'Last reviewed: 2026-10-28\n[#502](https://github.com/tokentimerch/tokentimer-core/issues/502)';
const snapshot = {capturedAt:'2026-10-28T11:00:00Z',issues:[{number:502,state:'open'}],pulls:[{number:406,state:'open',merged_at:null}]};
const companion = {capturedAt:snapshot.capturedAt,planning:[{issue:502,status:'In Progress'}],
 feedback:[{url:'https://tokentimer.featurebase.app/en/p/mcp',status:'In Progress',issues:[502],edition:'core'}]};
const codes = (i=index,r=roadmap,s=snapshot,c=companion) => audit(i,r,s,c,now).findings.map(f=>f.code);

test('aligned evidence passes and unavailable companion remains explicit',()=>{
 assert.deepEqual(codes(),[]);
 assert.match(audit(index,roadmap,snapshot,undefined,now).coverage,/github-only/);
});
test('missing roadmap and issue evidence are detected',()=>{
 assert.ok(codes(index,'',{...snapshot,issues:[]}).includes('ROADMAP_MISSING'));
 assert.ok(codes(index,'',{...snapshot,issues:[]}).includes('ISSUE_MISSING'));
});
test('closing an active issue cannot silently pass',()=>{
 assert.ok(codes(index,roadmap,{...snapshot,issues:[{number:502,state:'closed'}]}).includes('CLOSED_ACTIVE'));
});
test('released scope requires closure and a release reference',()=>{
 const i={...index,outcomes:[{...entry,horizon:'shipped',inRoadmap:false}]};
 assert.ok(codes(i).includes('SHIPPED_OPEN'));
 assert.ok(codes(i).includes('RELEASE_MISSING'));
});
test('status conflicts and absent delivery links are detected',()=>{
 const c={...companion,planning:[{issue:502,status:'Backlog'}],
 feedback:[{...companion.feedback[0],status:'Live',issues:[]}]};
 for(const code of ['PLANNING_STATUS','FEEDBACK_STATUS','FEEDBACK_LINK']) assert.ok(codes(index,roadmap,snapshot,c).includes(code));
});
test('partial exports are not treated as agreement',()=>{
 const c={...companion,planning:[],feedback:[]};
 assert.ok(codes(index,roadmap,snapshot,c).includes('PLANNING_UNVERIFIED'));
 assert.ok(codes(index,roadmap,snapshot,c).includes('FEEDBACK_UNVERIFIED'));
});
test('stale evidence and unknown index references are reported',()=>{
 assert.ok(codes(index,roadmap,{...snapshot,capturedAt:'2026-10-01T00:00:00Z'}).includes('STALE_EVIDENCE'));
 assert.ok(codes(index,roadmap+' https://github.com/tokentimerch/tokentimer-core/issues/999').includes('INDEX_MISSING'));
});
test('edition and implementation conflicts are detected',()=>{
 const c={...companion,feedback:[{...companion.feedback[0],edition:'enterprise'}]};
 assert.ok(codes(index,roadmap,snapshot,c).includes('EDITION_MISMATCH'));
 assert.ok(codes(index,roadmap,{...snapshot,pulls:[]}).includes('IMPLEMENTATION_UNVERIFIED'));
 assert.ok(codes(index,roadmap,{...snapshot,pulls:[{number:406,state:'closed',merged_at:null}]}).includes('IMPLEMENTATION_CLOSED'));
});
test('malformed snapshots, duplicate identifiers and future evidence fail explicitly',()=>{
 assert.throws(()=>audit(index,roadmap,{issues:[]},companion,now),/capturedAt/);
 assert.throws(()=>codes({...index,outcomes:[entry,entry]}),/duplicate/);
 assert.throws(()=>codes(index,roadmap,{...snapshot,capturedAt:'2027-01-01'}),/future/);
 assert.throws(()=>codes(index,roadmap,snapshot,{capturedAt:snapshot.capturedAt}),/planning/);
 assert.throws(()=>codes(index,roadmap,{...snapshot,issues:[{number:502,state:'unknown'}]}),/Unknown/);
});
test('CLI refuses unknown flags and missing values before network access',()=>{
 assert.throws(()=>main(['--write']),/Unknown option/);
 assert.throws(()=>main(['--snapshot']),/Missing value/);
});
