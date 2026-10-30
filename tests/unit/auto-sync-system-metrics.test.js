const {describe,it}=require('node:test');const assert=require('node:assert/strict');const {systemMetricPolicy,effectiveMetricSettings,creationDimensions}=require('../../apps/api/services/autoSyncMetricLabels');const low=['configuration_name','monitoring_group','kind'];
describe('system auto-sync metric precedence',()=>{
 it('uses environment before database, then disabled defaults for inherited connections',()=>{
  const config={inherit_system:true,enabled:false,labels:[],monitoring_group:'critical'};
  assert.equal(effectiveMetricSettings(config,{},{}).enabled,false);
  assert.equal(effectiveMetricSettings(config,{}, {enabled:true,labels:low}).enabled,true);
  assert.equal(effectiveMetricSettings(config,{AUTO_SYNC_METRICS_ENABLED:'false'},{enabled:true,labels:low}).enabled,false);
  assert.equal(effectiveMetricSettings(config,{AUTO_SYNC_METRICS_ENABLED:'true'},{enabled:false,labels:low}).enabled,true);
  assert.equal(systemMetricPolicy({enabled:true},{AUTO_SYNC_METRICS_ENABLED:'false'}).locked,true);
 });
 it('preserves existing explicit choices until a system policy is configured',()=>{
  const config={enabled:true,labels:['kind'],monitoring_group:'critical',inherit_system:false};
  assert.equal(effectiveMetricSettings(config,{},{}).enabled,true);
  assert.equal(effectiveMetricSettings(config,{}, {enabled:false}).enabled,false);
 });
 it('allows a local opt-out but cannot enable labels disabled by system or environment',()=>{
  const local={enabled:true,inherit_system:false,labels:['kind','asset_name','project'],monitoring_group:'critical'};
  assert.deepEqual(effectiveMetricSettings(local,{AUTO_SYNC_METRICS_EXTRA_LABELS:'project'},{enabled:true,labels:['kind','asset_name']}).labels,['kind','project']);
  assert.equal(effectiveMetricSettings({...local,enabled:false},{},{enabled:true,labels:low}).enabled,false);
  assert.deepEqual(creationDimensions({name:'private',source_kind:'gitlab-pat',source_dimensions:{project:'private'}},local,{AUTO_SYNC_METRICS_EXTRA_LABELS:'project'},{enabled:false,labels:['project']}),{kind:'gitlab-pat',asset_name:'',project:'',group:''});
 });
});

it('uses saved high-label choices when env is unset, and an explicit none overrides them',()=>{
 const setting={enabled:true,inherit_system:true};const stored={enabled:true,labels:['kind','asset_name']};
 assert.ok(effectiveMetricSettings(setting,{},stored).labels.includes('asset_name'));
 assert.deepEqual(effectiveMetricSettings(setting,{AUTO_SYNC_METRICS_EXTRA_LABELS:'none'},stored).labels,['kind']);
});
it('rejects malformed global values through the shared JSON save path',async()=>{
 const settings=require('../../apps/api/services/systemSettings');
 await assert.rejects(settings.saveJsonColumn({query(){throw Error('must not query')}},'auto_sync_metrics',{enabled:'true'},1,{strictKeys:true}),{code:'JSON_COLUMN_INVALID_VALUE'});
});
