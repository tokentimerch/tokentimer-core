const {describe,it}=require('node:test');
const assert=require('node:assert/strict');
const {systemMetricPolicy,effectiveMetricSettings,assertMetricSettingsEditable,systemMetricSettingsError}=require('../../apps/api/services/autoSyncMetricLabels');
const low=['configuration_name','monitoring_group','kind'];
const local={enabled:true,labels:['kind'],monitoring_group:'local'};
describe('independent global auto-sync overrides',()=>{
 it('leaves integration choices intact until an override is configured',()=>{assert.equal(systemMetricPolicy({},{}).override_metrics,false);assert.deepEqual(effectiveMetricSettings(local,{},{}),local);assert.deepEqual(effectiveMetricSettings(local,{}, {override_metrics:false,enabled:false,labels:low}),local);});
 it('forces metrics on every connection, including explicit local opt-outs',()=>{const forced=effectiveMetricSettings({...local,enabled:false,inherit_system:false},{},{override_metrics:true,enabled:true,labels:low});assert.equal(forced.enabled,true);assert.deepEqual(forced.labels,low);assert.equal(forced.monitoring_group,'local');});
 it('forces the group independently and allows an explicit empty global group',()=>{assert.deepEqual(effectiveMetricSettings(local,{}, {override_monitoring_group:true,monitoring_group:'critical'}),{...local,monitoring_group:'critical'});assert.equal(effectiveMetricSettings(local,{}, {override_monitoring_group:true,monitoring_group:''}).monitoring_group,'');});
 it('restores both local settings when the corresponding override is released',()=>{const stored={override_metrics:false,enabled:false,labels:low,override_monitoring_group:false,monitoring_group:'global'};assert.deepEqual(effectiveMetricSettings(local,{},stored),local);});
 it('preserves previously saved global policy as an active override',()=>{assert.equal(systemMetricPolicy({enabled:false},{}).override_metrics,true);assert.equal(effectiveMetricSettings(local,{}, {enabled:false}).enabled,false);});
 it('keeps environment priority for both overrides and high-cardinality restrictions',()=>{const env={AUTO_SYNC_METRICS_ENABLED:'false',AUTO_SYNC_METRICS_MONITORING_GROUP:' production ',AUTO_SYNC_METRICS_EXTRA_LABELS:'none'};const policy=systemMetricPolicy({override_metrics:false,override_monitoring_group:false},env);assert.equal(policy.override_metrics,true);assert.equal(policy.monitoring_group_locked,true);const forced=effectiveMetricSettings({...local,labels:['asset_name','kind']},env,{});assert.equal(forced.enabled,false);assert.equal(forced.monitoring_group,'production');assert.ok(!forced.labels.includes('asset_name'));});
 it('rejects changes to managed fields while allowing unrelated integration preferences',()=>{const policy={override_metrics:true,override_monitoring_group:false};assert.throws(()=>assertMetricSettingsEditable(local,{...local,enabled:false},policy),{code:'AUTO_SYNC_METRICS_MANAGED'});assert.equal(assertMetricSettingsEditable(local,{...local,monitoring_group:'other'},policy).monitoring_group,'other');assert.throws(()=>assertMetricSettingsEditable(local,{...local,monitoring_group:'other'},{override_monitoring_group:true}),{code:'AUTO_SYNC_METRICS_MANAGED'});assert.deepEqual(assertMetricSettingsEditable(local,local,{override_metrics:true,override_monitoring_group:true}),local);});
 it('validates typed independent flags and the global group',()=>{assert.ok(systemMetricSettingsError({override_metrics:'yes'}));assert.ok(systemMetricSettingsError({override_monitoring_group:1}));assert.ok(systemMetricSettingsError({monitoring_group:'x'.repeat(65)}));assert.ok(systemMetricSettingsError({monitoring_group:'bad\nvalue'}));assert.equal(systemMetricSettingsError({enabled:false,labels:[],override_metrics:true,override_monitoring_group:true,monitoring_group:''}),null);});
 it('rejects malformed global values through the shared save path',async()=>{const service=require('../../apps/api/services/systemSettings');await assert.rejects(service.saveJsonColumn({query(){throw Error('must not query');}},'auto_sync_metrics',{enabled:'true'},1,{strictKeys:true}),{code:'JSON_COLUMN_INVALID_VALUE'});});
 it('does not expose previously saved asset labels without an operator selection',()=>{
  const settings={enabled:true,labels:['asset_name','project']};
  assert.deepEqual(effectiveMetricSettings(settings,{},{}).labels,[]);
  assert.deepEqual(effectiveMetricSettings(settings,{}, {override_metrics:false,labels:['asset_name']}).labels,['asset_name']);
  assert.deepEqual(effectiveMetricSettings(settings,{AUTO_SYNC_METRICS_EXTRA_LABELS:'none'},{override_metrics:false,labels:['asset_name']}).labels,[]);
 });

});

describe('mixed-source metric hierarchy',()=>{
  const savedLocal={enabled:true,labels:['kind'],monitoring_group:'local'};
  it('uses the environment for exposure and the active system override for the group',()=>{
    const stored={override_metrics:true,enabled:false,labels:['kind'],override_monitoring_group:true,monitoring_group:'system'};
    const original=structuredClone({stored,savedLocal});
    assert.deepEqual(effectiveMetricSettings(savedLocal,{AUTO_SYNC_METRICS_ENABLED:'true'},stored),{...savedLocal,monitoring_group:'system'});
    const policy=systemMetricPolicy(stored,{AUTO_SYNC_METRICS_ENABLED:'true'});assert.equal(policy.locked,true);assert.equal(policy.monitoring_group_locked,false);
    assert.deepEqual({stored,savedLocal},original);
  });
  it('uses the saved system exposure override and environment group independently',()=>{
    const stored={override_metrics:true,enabled:false,labels:['kind'],override_monitoring_group:true,monitoring_group:'system'};
    assert.deepEqual(effectiveMetricSettings(savedLocal,{AUTO_SYNC_METRICS_MONITORING_GROUP:'environment'},stored),{...savedLocal,enabled:false,monitoring_group:'environment'});
    const policy=systemMetricPolicy(stored,{AUTO_SYNC_METRICS_MONITORING_GROUP:'environment'});assert.equal(policy.locked,false);assert.equal(policy.monitoring_group_locked,true);
  });
  it('ignores inactive saved overrides and empty environment values, preserving local choices',()=>{
    const stored={override_metrics:false,enabled:false,labels:[],override_monitoring_group:false,monitoring_group:'system'};
    const env={AUTO_SYNC_METRICS_ENABLED:' ',AUTO_SYNC_METRICS_MONITORING_GROUP:' '};
    assert.deepEqual(effectiveMetricSettings(savedLocal,env,stored),savedLocal);
    assert.equal(systemMetricPolicy(stored,env).override_metrics,false);assert.equal(systemMetricPolicy(stored,env).override_monitoring_group,false);
  });
});

it('reports asset-label environment ownership without forcing unrelated overrides',()=>{
  for(const raw of ['none','project']){const policy=systemMetricPolicy({override_metrics:false,override_monitoring_group:false},{AUTO_SYNC_METRICS_EXTRA_LABELS:raw});assert.equal(policy.extra_labels_locked,true);assert.equal(policy.locked,false);assert.equal(policy.override_metrics,false);assert.equal(policy.override_monitoring_group,false);}
  assert.equal(systemMetricPolicy({},{}).extra_labels_locked,false);
});
it('identifies the controlling sources in managed-edit API errors',()=>{
  const next={...local,enabled:false,monitoring_group:'new'};
  assert.throws(()=>assertMetricSettingsEditable(local,next,{override_metrics:true,locked:true,override_monitoring_group:true,monitoring_group_locked:false}),error=>error.code==='AUTO_SYNC_METRICS_MANAGED'&&error.message.includes('environment settings (Helm/Compose)')&&error.message.includes('System Settings → Auto-sync'));
  assert.throws(()=>assertMetricSettingsEditable(local,{...local,monitoring_group:'new'},{override_monitoring_group:true,monitoring_group_locked:true}),error=>error.code==='AUTO_SYNC_METRICS_MANAGED'&&error.message.includes('environment settings')&&!error.message.includes('System Settings'));
});

describe('global deployment label selection',()=>{
 const stored={override_metrics:false,enabled:false,labels:['kind','asset_name']};
 const env=(labels,enabled='true')=>({AUTO_SYNC_METRICS_ENABLED:enabled,AUTO_SYNC_METRICS_LABELS:labels});
 it('forces one explicit label selection globally without changing saved choices',()=>{
  const original=structuredClone(stored);const selected=env(' project,kind ');
  const policy=systemMetricPolicy(stored,selected);assert.equal(policy.labels_locked,true);assert.equal(policy.override_metrics,true);assert.deepEqual(policy.labels,['kind','project']);
  assert.deepEqual(effectiveMetricSettings({...local,enabled:false},selected,stored),{...local,labels:['kind','project']});assert.deepEqual(stored,original);
 });
 it('keeps the legacy asset-label cap restrictive without adding unselected labels',()=>{
  assert.deepEqual(systemMetricPolicy(stored,{...env('kind,project'),AUTO_SYNC_METRICS_EXTRA_LABELS:'asset_name,group'}).labels,['kind']);
  assert.deepEqual(systemMetricPolicy(stored,{...env('kind,project'),AUTO_SYNC_METRICS_EXTRA_LABELS:'none'}).labels,['kind']);
  assert.deepEqual(systemMetricPolicy(stored,{...env('kind,project'),AUTO_SYNC_METRICS_EXTRA_LABELS:'project'}).labels,['kind','project']);
 });
 it('supports no optional labels and restores database choices when unset',()=>{
  assert.deepEqual(systemMetricPolicy(stored,env('none')).labels,[]);
  assert.deepEqual(systemMetricPolicy(stored,env(' ')).labels,stored.labels);
  assert.equal(systemMetricPolicy(stored,{}).labels_locked,false);
 });
 it('keeps global disabling ahead of explicit metadata selection',()=>{
  const settings=effectiveMetricSettings(local,env('asset_name,project','false'),stored);assert.equal(settings.enabled,false);
 });
 it('rejects unknown, duplicate, empty and mixed sentinel entries',()=>{
  for(const labels of ['secret','kind,kind','kind,','kind,,project','none,kind'])assert.throws(()=>systemMetricPolicy(stored,env(labels)),/unique supported labels/);
 });
 it('requires an explicit enabled or disabled global override with a label list',()=>{
  for(const enabled of ['', 'yes'])assert.throws(()=>systemMetricPolicy(stored,env('kind',enabled)),/requires AUTO_SYNC_METRICS_ENABLED/);
  assert.throws(()=>systemMetricPolicy(stored,{AUTO_SYNC_METRICS_LABELS:'kind'}),/requires AUTO_SYNC_METRICS_ENABLED/);
 });
});
