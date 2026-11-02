import test from 'node:test';
import assert from 'node:assert/strict';
import { audit, main } from './check-roadmap-drift.mjs';

const now = Date.parse('2026-10-28T12:00:00Z');
const entry = {id:'mcp',issue:502,edition:'core',horizon:'alongside-0.x',inRoadmap:true,
 planningStatus:'In Progress',implementationPr:406,feedback:[{slug:'mcp',status:'In Progress'}]};
const index = {schemaVersion:1,repository:'tokentimerch/tokentimer-core',reviewedAt:'2026-10-28',outcomes:[entry]};
const roadmap = 'Last reviewed: 2026-10-28\n## Alongside 0.x -- does not gate v1.0.0\n[#502](https://github.com/tokentimerch/tokentimer-core/issues/502)';
const snapshot = {capturedAt:'2026-10-28T11:00:00Z',issues:[{number:502,state:'open'}],pulls:[{number:406,state:'open',merged_at:null}]};
const companion = {capturedAt:snapshot.capturedAt,planning:[{issue:502,status:'In Progress',links:['https://github.com/tokentimerch/tokentimer-core/issues/502']}],
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
 assert.throws(()=>codes(index,roadmap,{...snapshot,issues:[{number:502,state:'unknown'}]}),/GitHub issue state/);
});
test('CLI refuses unknown flags and missing values before network access',()=>{
 assert.throws(()=>main(['--write']),/Unknown option/);
 assert.throws(()=>main(['--snapshot']),/Missing value/);
});

test('roadmap section must match the outcome horizon',()=>{
 const wrong=roadmap.replace('## Alongside 0.x -- does not gate v1.0.0','## Before v1.0.0 -- operator-stable product');
 assert.ok(codes(index,wrong).includes('ROADMAP_HORIZON'));
});
test('a release tag string alone does not prove publication',()=>{
 const shipped={...index,outcomes:[{...entry,horizon:'shipped',inRoadmap:false,release:'v0.18.0'}]};
 assert.ok(codes(shipped,roadmap,{...snapshot,issues:[{number:502,state:'closed'}]}).includes('RELEASE_UNVERIFIED'));
});
test('matching a slug on another site is not feedback evidence',()=>{
 const fake={...companion,feedback:[{...companion.feedback[0],url:'https://example.com/en/p/mcp'}]};
 assert.ok(codes(index,roadmap,snapshot,fake).includes('FEEDBACK_UNVERIFIED'));
});
test('planning evidence must contain an observed canonical issue link',()=>{
 assert.ok(codes(index,roadmap,snapshot,{...companion,planning:[{issue:502,status:'In Progress',links:[]}]}).includes('PLANNING_LINK'));
});
test('duplicate primary delivery issues cannot represent independent outcomes',()=>{
 assert.throws(()=>codes({...index,outcomes:[entry,{...entry,id:'duplicate'}]}),/duplicate/i);
});
test('a referenced active implementation omitted from the index is detected',()=>{
 const untracked={...snapshot,issues:[...snapshot.issues,{number:498,state:'open',pull_request:{},body:'Refs #502.'}]};
 assert.ok(codes(index,roadmap,untracked).includes('ACTIVE_PR_UNMAPPED'));
});
test('published release evidence passes, while drafts and prereleases do not',()=>{
 const shipped={...index,outcomes:[{...entry,horizon:'shipped',inRoadmap:false,release:'v0.18.0'}]};
 const published={...snapshot,issues:[{number:502,state:'closed'}],releases:[{tag_name:'v0.18.0',draft:false,prerelease:false,published_at:'2026-10-25T00:00:00Z'}]};
 const plans={...companion,planning:[{...companion.planning[0],status:'Done'}]};
 const noActiveLink='Last reviewed: 2026-10-28';
 const i={...shipped,outcomes:[{...shipped.outcomes[0],planningStatus:'Done'}]};
 assert.deepEqual(codes(i,noActiveLink,published,plans),[]);
 for(const invalid of [{draft:true},{prerelease:true},{published_at:'2026-10-29T00:00:00Z'}]) {
  assert.ok(codes(i,noActiveLink,{...published,releases:[{...published.releases[0],...invalid}]},plans).includes('RELEASE_UNVERIFIED'));
 }
});
test('multiple implementations require independent evidence',()=>{
 const multi={...index,outcomes:[{...entry,implementationPrs:[406,498]}]};
 assert.ok(codes(multi).includes('IMPLEMENTATION_UNVERIFIED'));
 assert.ok(!codes(multi,roadmap,{...snapshot,pulls:[...snapshot.pulls,{number:498,state:'open'}]}).includes('IMPLEMENTATION_UNVERIFIED'));
});
test('related planning scope uses actual child links and closure state',()=>{
 const i={...index,outcomes:[{...entry,relatedIssues:[503]}]};
 const c={...companion,planning:[...companion.planning,{issue:502,deliveryIssue:503,status:'Backlog',links:['https://github.com/tokentimerch/tokentimer-core/issues/503']}]};
 const s={...snapshot,issues:[...snapshot.issues,{number:503,state:'closed'}]};
 assert.ok(codes(i,roadmap,s,c).includes('PLANNING_STATUS'));
 assert.ok(codes(i,roadmap,snapshot,c).includes('PLANNING_CHILD_UNVERIFIED'));
});
test('open planning work need not remain Backlog forever',()=>{
 const i={...index,outcomes:[{...entry,planningStatus:undefined}]};
 for(const state of ['Backlog','Todo','In Progress','In Review']) {
  assert.ok(!codes(i,roadmap,snapshot,{...companion,planning:[{...companion.planning[0],status:state}]}).includes('PLANNING_STATUS'));
 }
});
test('feedback implementation links and malformed evidence are checked',()=>{
 const i={...index,outcomes:[{...entry,feedback:[{...entry.feedback[0],implementationPrs:[406]}]}]};
 assert.ok(codes(i).includes('FEEDBACK_IMPLEMENTATION_LINK'));
 assert.throws(()=>codes(index,roadmap,snapshot,{...companion,feedback:[{...companion.feedback[0],issues:'502'}]}),/feedback issue evidence/);
});
test('independent stale source dates and duplicate card evidence cannot silently pass',()=>{
 assert.ok(codes(index,roadmap,snapshot,{...companion,planningCapturedAt:'2026-10-01T00:00:00Z'}).includes('STALE_EVIDENCE'));
 assert.ok(codes(index,roadmap,snapshot,{...companion,feedback:[...companion.feedback,...companion.feedback]}).includes('FEEDBACK_UNVERIFIED'));
 assert.throws(()=>codes({...index,repository:'another/repository'}),/Core outcome/);
});
