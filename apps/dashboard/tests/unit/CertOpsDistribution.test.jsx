import {beforeEach,describe,expect,it,vi} from 'vitest';
import {fireEvent,render,screen,waitFor,within} from '@testing-library/react';
import {ChakraProvider} from '@chakra-ui/react';
import {MemoryRouter,Outlet,Route,Routes} from 'react-router';
import {DashboardThemeProvider} from '../../src/hooks/useDashboardTheme.js';
import CertOpsDistribution from '../../src/pages/certops/CertOpsDistribution.jsx';
const {api,manage,admin}=vi.hoisted(()=>({api:Object.fromEntries(['groups','management','preflight','retention','consumer','activation','policy','rollout','state','retry','reconcile','cleanup','emergency'].map(key=>[key,vi.fn()])),manage:vi.fn(),admin:vi.fn()}));
vi.mock('../../src/components/certops/distributionApi.js',()=>({distributionApi:api}));
vi.mock('../../src/utils/WorkspaceContext.jsx',()=>({useWorkspace:()=>({workspaceId:'workspace'})}));
vi.mock('../../src/components/certops/useCertOps.js',()=>({useCertOpsCanManage:manage,useCertOpsIsWorkspaceAdmin:admin}));
const latest='11111111-1111-4111-8111-111111111111',retained='22222222-2222-4222-8222-222222222222';
const policy={mode:'manual',maxParallel:1,authorizationExpiresAt:null,verification:{enabled:false,intervalSeconds:3600,maxBackoffSeconds:86400,staleJobSeconds:3600,failureThreshold:3},
  alerts:{enabled:false,offlineSeconds:900,stuckSeconds:3600,convergenceSeconds:3600,expiryWarningDays:14,repeatSeconds:86400,contactGroupIds:[]},retention:{minimumSeconds:2592000,minimumVersions:3,rollbackSeconds:604800,cleanupEnabled:false,reportOnly:true,requiresApproval:true}};
const consumer={binding_id:'binding',assigned_agent_id:'agent',deployment_profile_ref:'nginx',profile_revision:1,authorization_revision:2,required:true,wave:0,verification_policy:'served',freshness_seconds:3600,
  binding_state:'active',agent_name:'Consumer host',agent_status:'offline',desired_version:2,observed_version:1,health_status:'old_certificate_active',verification_method:'installed',observed_at:new Date().toISOString(),observed_valid_to:'2027-01-01T00:00:00Z'};
let data;
function page({paused=false,resolved=true}={}){return render(<ChakraProvider><DashboardThemeProvider><MemoryRouter><Routes><Route element={<Outlet context={{certOpsPaused:paused,killSwitchResolved:resolved}}/>}><Route path='/' element={<CertOpsDistribution/>}/></Route></Routes></MemoryRouter></DashboardThemeProvider></ChakraProvider>);}
async function openView(name){fireEvent.click(await screen.findByRole('tab',{name:new RegExp('^'+name)}));}
beforeEach(()=>{vi.clearAllMocks();manage.mockReturnValue(true);admin.mockReturnValue(true);api.cleanup.mockResolvedValue({status:'pending_approval'});data={evaluated_at:new Date().toISOString(),group:{id:'group',state:'active',generation:1,material_store_ref:'customer',latest_material_version_id:latest},
  policy:null,defaults:structuredClone(policy),consumers:[structuredClone(consumer)],versions:[{id:latest,state:'published',provider_version:2,valid_to:'2027-01-01T00:00:00Z'},{id:retained,state:'published',provider_version:1,valid_to:'2026-12-01T00:00:00Z'}],
  rollouts:[],approvals:[],incidents:[],schedule:null,discoveries:[],agents:[{id:'agent',name:'Consumer host',status:'active'}],contactGroups:[{id:'ops',name:'Operations'}]};
  api.groups.mockResolvedValue({groups:[data.group]});api.management.mockImplementation(async()=>data);api.rollout.mockResolvedValue({status:'pending_approval'});api.policy.mockResolvedValue({});api.consumer.mockResolvedValue({});api.activation.mockResolvedValue({});
  api.preflight.mockResolvedValue({consumers:[{bindingId:'binding',diagnostics:[{code:'CERTOPS_AGENT_OFFLINE'},{code:'CERTOPS_CUSTOMER_LOCAL_PREFLIGHT_REQUIRED'}]}]});
  api.retention.mockResolvedValue({versions:[{id:latest,provider_version:2,retainedReasons:['desired_consumer_version']}]});});
describe('Distribution Management',()=>{
  it('requests a reviewed read-only inspection of a rejected uncertain original job',async()=>{
    data.consumers[0].latest_deployment={jobId:'original-job',jobStatus:'rejected',needsOperatorReconciliation:true};
    api.reconcile.mockResolvedValue({job:{id:'inspection-job'}});
    page();await openView('Destinations');
    fireEvent.click(await screen.findByRole('button',{name:'Request read-only reconciliation'}));
    expect(api.reconcile).not.toHaveBeenCalled();
    expect(screen.getByText(/A different authorized operator must approve it/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button',{name:'Confirm'}));
    await waitFor(()=>expect(api.reconcile).toHaveBeenCalledWith('workspace','original-job'));
    expect(await screen.findByRole('link',{name:'Review the inspection in Jobs'})).toHaveAttribute('href',expect.stringContaining('inspection-job'));
    expect(api.retry).not.toHaveBeenCalled();expect(api.rollout).not.toHaveBeenCalled();
    expect(screen.queryByText('Review a retired destination')).not.toBeInTheDocument();
  });
  it('does not offer reconciliation without an uncertain terminal original job or write access',async()=>{
    data.consumers[0].latest_deployment={jobId:'original-job',jobStatus:'completed',needsOperatorReconciliation:false};
    page();await openView('Destinations');
    expect(screen.queryByRole('button',{name:'Request read-only reconciliation'})).not.toBeInTheDocument();
  });
  it('keeps the reconciliation action unavailable to viewers and paused workspaces',async()=>{
    data.consumers[0].latest_deployment={jobId:'original-job',jobStatus:'rejected',needsOperatorReconciliation:true};
    manage.mockReturnValue(false);
    const view=page();await openView('Destinations');
    expect(screen.queryByRole('button',{name:'Request read-only reconciliation'})).not.toBeInTheDocument();
    view.unmount();manage.mockReturnValue(true);page({paused:true});await openView('Destinations');
    expect(screen.getByRole('button',{name:'Request read-only reconciliation'})).toBeDisabled();
  });
  it('shows an unavailable-proof error without claiming that reconciliation succeeded',async()=>{
    data.consumers[0].latest_deployment={jobId:'original-job',jobStatus:'rejected',needsOperatorReconciliation:true};
    api.reconcile.mockRejectedValue({response:{data:{error:'Original deployment proof is unavailable.',code:'CERTOPS_RECONCILIATION_UNAVAILABLE'}}});
    page();await openView('Destinations');fireEvent.click(await screen.findByRole('button',{name:'Request read-only reconciliation'}));
    fireEvent.click(screen.getByRole('button',{name:'Confirm'}));
    expect(await screen.findByText(/Original deployment proof is unavailable/)).toBeInTheDocument();
    expect(screen.queryByRole('link',{name:'Review the inspection in Jobs'})).not.toBeInTheDocument();
  });
  it('labels bounded recent counts and includes paused rollouts without implying global totals',async()=>{
    data.rollouts=[{id:'r1',state:'paused',generation:1},{id:'r2',state:'completed',generation:2}];
    data.approvals=[{id:'a1',status:'pending_approval'},{id:'a2',status:'completed'}];
    data.incidents=[{id:'i1',code:'offline',resolved_at:null},{id:'i2',code:'offline',resolved_at:'2026-01-01'}];
    page();const rollouts=await screen.findByText('Recent ongoing rollouts');
    expect(within(rollouts.parentElement).getByText('1')).toBeInTheDocument();
    expect(within(rollouts.parentElement).getByText(/1 recent pending approval · includes paused rollouts/)).toBeInTheDocument();
    expect(within(screen.getByText('Recent open incidents').parentElement).getByText('1')).toBeInTheDocument();
    expect(screen.getByText('From the latest 100 incidents')).toBeInTheDocument();
  });
  it('guides the next step truthfully for an unpublished version',async()=>{
    data.versions=[];data.group.latest_material_version_id=null;page();
    expect(await screen.findByText(/Publish a certificate before requesting a rollout/)).toBeInTheDocument();
  });
  it('reports the current published version even when a newer version is a draft',async()=>{
    data.versions.unshift({id:'new-draft',state:'publishing',provider_version:3});page();
    expect(await screen.findByText(/Latest publication: published/)).toBeInTheDocument();
  });
  it('does not claim a published version when the current reference is missing from the returned history',async()=>{
    data.versions=[];page();
    expect(await screen.findByText(/Latest publication: current published version unavailable/)).toBeInTheDocument();
  });
  it('recommends selecting an available version when the current version is fenced',async()=>{
    data.versions[0].cleanup_state='fenced';page();
    expect(await screen.findByText(/Choose an available published version/)).toBeInTheDocument();
    expect(screen.getByRole('button',{name:'Request rollout'})).toBeDisabled();
    expect(screen.getByRole('button',{name:'Verify only'})).toBeDisabled();
    expect(screen.getByRole('button',{name:'Run safe preflight'})).toBeEnabled();
    fireEvent.change(screen.getByLabelText('Exact published version'),{target:{value:retained}});
    expect(screen.getByRole('button',{name:'Request rollback approval'})).toBeEnabled();
    fireEvent.click(screen.getByRole('button',{name:'Verify only'}));
    await waitFor(()=>expect(api.rollout).toHaveBeenCalledWith('workspace','group',expect.objectContaining({materialVersionId:retained,verificationOnly:true}),expect.any(String)));
  });
  it('guides the next step truthfully when no active destination exists',async()=>{
    data.consumers=[];page();
    expect(await screen.findByText(/Add and authorize an active destination/)).toBeInTheDocument();
  });
  it('explains the manager requirement to viewers',async()=>{
    manage.mockReturnValue(false);page();
    expect(await screen.findByText(/A workspace manager can configure destinations/)).toBeInTheDocument();
  });
  it('explains pause status before recommending a rollout',async()=>{
    page({paused:true});expect(await screen.findByText(/Workspace operations are paused. A workspace administrator must resume/)).toBeInTheDocument();
  });
  it('keeps recent approval and incident attention visible across focused views',async()=>{
    data.approvals=[{id:'a1',status:'pending_approval'}];data.incidents=[{id:'i1',code:'offline',resolved_at:null}];
    page();await openView('Destinations');
    expect(screen.getByRole('tab',{name:'Destinations'})).toHaveAttribute('aria-selected','true');
    expect(screen.getByRole('tab',{name:'Deployments: 1 recent pending approval'})).toBeInTheDocument();
    expect(screen.getByRole('tab',{name:'Issues: 1 recent open incident'})).toBeInTheDocument();
    expect(screen.queryByRole('button',{name:'Request rollout'})).not.toBeInTheDocument();
  });
  it('keeps completed preparation separate from installed and served evidence',async()=>{
    Object.assign(data.consumers[0],{health_status:'unknown_coverage',verification_method:null,observed_at:null,observed_valid_to:null,
      latest_deployment:{stage:'staged',stagingReceipt:{staged:true,installed:false,servedVerified:false,observedAt:new Date().toISOString()}}});
    page();await openView('Destinations');await screen.findByText(/Material staged/);
    expect(screen.getByText(/activation and verification remain separate/)).toBeInTheDocument();
    expect(screen.getByText('unknown coverage',{exact:true})).toBeInTheDocument();
    expect(screen.queryByText('installed')).not.toBeInTheDocument();
  });
  it('makes independent staging an explicit Linux policy choice',async()=>{
    data.consumers[0].agent_platform='linux';page();await openView('Destinations');
    fireEvent.click(await screen.findByRole('button',{name:'Maintenance'}));
    const staging=screen.getByRole('checkbox',{name:/Stage material before the activation window/});
    expect(staging).not.toBeChecked();fireEvent.click(staging);
    fireEvent.click(screen.getByRole('button',{name:'Save activation policy'}));
    await waitFor(()=>expect(api.activation).toHaveBeenCalled());
    expect(api.activation.mock.calls[0][3].independentStaging).toBe(true);
  });
  it('keeps viewer permissions, coverage warnings and installed-versus-served assurance visible',async()=>{
    manage.mockReturnValue(false);admin.mockReturnValue(false);page();await screen.findByRole('tab',{name:'Overview'});expect(screen.queryByRole('button',{name:'Request rollout'})).not.toBeInTheDocument();await openView('Destinations');await screen.findByText('Consumer host · offline');
    expect(screen.getByText(/old certificate active/)).toBeInTheDocument();expect(screen.getByText('installed')).toBeInTheDocument();
    expect(screen.queryByRole('button',{name:'Add consumer'})).not.toBeInTheDocument();expect(screen.queryByRole('button',{name:'Request rollout'})).not.toBeInTheDocument();
    await openView('Issues');expect(screen.getByText(/A certificate in a machine store does not establish/)).toBeInTheDocument();
  });
  it('presents discovery observations with explicit confidence and a shared served-certificate caveat',async()=>{
    data.discoveries=[
      {id:'one',source_kind:'custom_service',service_identity:'edge/frontend',confidence:'stale',last_observed_at:'2026-01-02T00:00:00Z'},
      {id:'two',source_kind:'other_source',service_identity:'db/listener',confidence:'unknown',last_observed_at:null},
    ];
    page();await openView('Issues');
    const first=within(screen.getByText('edge/frontend').closest('li'));
    expect(first.getByText('Source: custom service')).toBeInTheDocument();
    expect(first.getByText('stale')).toBeInTheDocument();
    expect(first.getByText(/Last observed/)).toBeInTheDocument();
    expect(screen.getByText(/All entries are read-only configuration observations; served certificates are unverified/)).toBeInTheDocument();
    const second=within(screen.getByText('db/listener').closest('li'));
    expect(second.getByText('unknown')).toBeInTheDocument();
    expect(second.getByText('Source: other source')).toBeInTheDocument();
  });
  it('keeps the empty discovery state and coverage limitation explicit',async()=>{
    page();await openView('Issues');
    expect(screen.getByText('No service relationships observed')).toBeInTheDocument();
    expect(screen.getByText(/unknown coverage is not healthy coverage/)).toBeInTheDocument();
    expect(screen.getByText(/IIS rebind is implemented and requires a production-qualified agent/)).toBeInTheDocument();
  });
  it('keeps recovery and supported-target guidance available in disclosures',async()=>{
    data.incidents=[{id:'incident',code:'consumer_offline',resolved_at:null,opened_at:'2026-01-02T00:00:00Z',updated_at:'2026-01-03T00:00:00Z',evidence:{jobId:'job'}}];
    page();await openView('Issues');
    expect(screen.getByText('consumer offline')).toBeInTheDocument();
    expect(screen.getByRole('link',{name:'View affected job'})).toHaveAttribute('href','/certops/jobs?workspace=workspace&job=job');
    for(const title of ['Recovery guidance','Supported targets']){
      const summary=screen.getByText(title),disclosure=summary.closest('details');
      expect(disclosure).not.toHaveAttribute('open');fireEvent.click(summary);expect(disclosure).toHaveAttribute('open');
    }
    expect(screen.getByText(/request read-only reconciliation from its destination/)).toBeVisible();
    expect(screen.getByText(/production-qualified agent/)).toBeVisible();
  });
  it('identifies jobless incidents and preserves historical binding evidence',async()=>{
    data.incidents=[
      {id:'offline-one',binding_id:'binding',code:'required_consumer_offline',severity:'warning',resolved_at:null,evidence:{bindingId:'binding',agentId:'agent',desiredVersionId:'version-a'}},
      {id:'offline-two',binding_id:'historical-binding',code:'required_consumer_offline',severity:'critical',resolved_at:'2026-01-01',evidence:{bindingId:'historical-binding',agentId:'former-agent',rolloutId:'rollout-old',observedVersionId:'version-b'}},
    ];
    page();await openView('Issues');
    const first=within(screen.getByText('Binding: binding').closest('li'));
    expect(first.getByText('Agent: agent')).toBeInTheDocument();
    expect(first.getByText('Current profile: nginx')).toBeInTheDocument();
    expect(first.getByText('Desired version: version-a')).toBeInTheDocument();
    expect(first.getByRole('link',{name:'View consumer'})).toHaveAttribute('href','/?workspace=workspace&group=group#distribution-consumers');
    expect(first.queryByRole('link',{name:'View affected job'})).not.toBeInTheDocument();
    const historical=within(screen.getByText('Binding: historical-binding').closest('li'));
    expect(historical.getByText('Agent: former-agent')).toBeInTheDocument();
    expect(historical.getByText('Observed version: version-b')).toBeInTheDocument();
    expect(historical.getByText('Rollout: rollout-old')).toBeInTheDocument();
    expect(historical.getByText('Severity: critical')).toBeInTheDocument();
    expect(historical.getByText('Resolved')).toBeInTheDocument();
    expect(historical.queryByRole('link',{name:'View consumer'})).not.toBeInTheDocument();
    fireEvent.click(first.getByRole('link',{name:'View consumer'}));
    await waitFor(()=>expect(screen.getByRole('tab',{name:'Destinations'})).toHaveAttribute('aria-selected','true'));
  });
  it('displays opaque provider versions in overview and retention',async()=>{
    const azure='00112233445566778899aabbccddeeff';data.versions[0].provider_version=azure;
    api.retention.mockResolvedValue({versions:[{id:latest,provider_version:azure,retainedReasons:['desired_consumer_version']}]});
    page();expect(await screen.findByRole('option',{name:new RegExp(azure)})).toBeInTheDocument();
    await openView('Policy');fireEvent.click(screen.getByRole('button',{name:'Preview retained versions'}));
    expect(await screen.findByText(`Store version ${azure}`)).toBeInTheDocument();
  });
  it('selects an exact retained version and requests approval only after confirmation',async()=>{
    page();const select=await screen.findByLabelText('Exact published version');fireEvent.change(select,{target:{value:retained}});
    fireEvent.click(screen.getByRole('button',{name:'Request rollback approval'}));expect(api.rollout).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button',{name:'Confirm'}));await screen.findByText(/Request created. Review and approve/);
    expect(api.rollout).toHaveBeenCalledWith('workspace','group',expect.objectContaining({materialVersionId:retained,requiresApproval:true,verificationOnly:false}),expect.any(String));
  });
  it('uses verification-only jobs and never labels a request as successful deployment',async()=>{
    page();fireEvent.click(await screen.findByRole('button',{name:'Verify only'}));await waitFor(()=>expect(api.rollout).toHaveBeenCalled());
    expect(api.rollout.mock.calls[0][2]).toEqual(expect.objectContaining({verificationOnly:true,materialVersionId:latest}));
    expect(screen.queryByText('Deployment succeeded')).not.toBeInTheDocument();
  });
  it('uses a fresh idempotency key for each confirmed verification request',async()=>{
    api.rollout.mockResolvedValue({status:'pending'});page();
    const verify=await screen.findByRole('button',{name:'Verify only'});
    fireEvent.click(verify);await waitFor(()=>expect(api.rollout).toHaveBeenCalledTimes(1));
    await waitFor(()=>expect(screen.getByRole('button',{name:'Verify only'})).toBeEnabled());
    fireEvent.click(screen.getByRole('button',{name:'Verify only'}));
    await waitFor(()=>expect(api.rollout).toHaveBeenCalledTimes(2));
    expect(api.rollout.mock.calls[1][3]).not.toBe(api.rollout.mock.calls[0][3]);
  });
  it('uses a fresh idempotency key for each confirmed rollout request',async()=>{
    api.rollout.mockResolvedValue({status:'pending'});page();
    fireEvent.click(await screen.findByRole('button',{name:'Request rollout'}));
    fireEvent.click(screen.getByRole('button',{name:'Confirm'}));
    await waitFor(()=>expect(api.rollout).toHaveBeenCalledTimes(1));
    await waitFor(()=>expect(screen.getByRole('button',{name:'Request rollout'})).toBeEnabled());
    fireEvent.click(screen.getByRole('button',{name:'Request rollout'}));
    fireEvent.click(screen.getByRole('button',{name:'Confirm'}));
    await waitFor(()=>expect(api.rollout).toHaveBeenCalledTimes(2));
    expect(api.rollout.mock.calls[1][3]).not.toBe(api.rollout.mock.calls[0][3]);
  });
  it('reuses the idempotency key when a verification response is uncertain',async()=>{
    api.rollout.mockRejectedValueOnce(new Error('network interrupted')).mockResolvedValueOnce({status:'pending'});page();
    fireEvent.click(await screen.findByRole('button',{name:'Verify only'}));
    await screen.findByText(/Operation failed/);
    fireEvent.click(screen.getByRole('button',{name:'Verify only'}));
    await waitFor(()=>expect(api.rollout).toHaveBeenCalledTimes(2));
    expect(api.rollout.mock.calls[1][3]).toBe(api.rollout.mock.calls[0][3]);
  });
  it('adds a consumer using a registered agent and a customer-local alias',async()=>{
    page();await openView('Destinations');fireEvent.click(await screen.findByRole('button',{name:'Add consumer'}));fireEvent.change(screen.getByLabelText('Registered agent'),{target:{value:'agent'}});
    fireEvent.change(screen.getByLabelText('Customer-local deployment profile'),{target:{value:'web_secondary'}});fireEvent.click(screen.getByRole('button',{name:'Save consumer'}));
    await waitFor(()=>expect(api.consumer).toHaveBeenCalledWith('workspace','group',expect.any(String),expect.objectContaining({agentId:'agent',deploymentProfileRef:'web_secondary',required:true,wave:0,verificationPolicy:'served'})));
  });
  it('keeps an unfinished destination form when changing views',async()=>{
    page();await openView('Destinations');fireEvent.click(screen.getByRole('button',{name:'Add consumer'}));
    fireEvent.change(screen.getByLabelText('Customer-local deployment profile'),{target:{value:'unfinished'}});
    await openView('Deployments');await openView('Destinations');
    expect(screen.getByLabelText('Customer-local deployment profile')).toHaveValue('unfinished');
  });
  it('keeps policy edits when switching views',async()=>{
    page();await openView('Policy');fireEvent.click(screen.getByRole('button',{name:'Edit policy settings'}));
    const mode=screen.getByLabelText('After publication');fireEvent.change(mode,{target:{value:'approval_request'}});
    fireEvent.click(screen.getByRole('button',{name:'Hide policy settings'}));fireEvent.click(screen.getByRole('button',{name:'Edit policy settings'}));
    await openView('Overview');
    await openView('Policy');
    expect(screen.getByLabelText('After publication')).toHaveValue('approval_request');
  });
  it('summarizes the active policy and groups related controls',async()=>{
    page();await openView('Policy');
    expect(screen.getByText(/Recurring verification: disabled/)).toBeInTheDocument();
    expect(screen.getByText(/Incident notifications: disabled · Cleanup policy: report-only/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button',{name:'Edit policy settings'}));
    for(const name of ['Rollout authority','Verification','Incident notifications','Retention and cleanup'])
      expect(screen.getByRole('heading',{name})).toBeInTheDocument();
    expect(screen.getByText(/not from the last use or replacement of a version/)).toBeInTheDocument();
  });
  it('distinguishes configured verification from its last outcome and does not imply notification delivery without a contact group',async()=>{
    data.contactGroups=[];data.schedule={last_outcome:'success'};page();await openView('Policy');
    expect(screen.getByText(/Recurring verification: disabled/)).toBeInTheDocument();
    expect(screen.getByText(/Last verification outcome: success/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button',{name:'Edit policy settings'}));
    expect(screen.getByText(/Configure an eligible workspace contact group for notifications/)).toBeInTheDocument();
  });
  it('saves policy through revision checks and keeps manual automation defaults',async()=>{
    page();await openView('Policy');fireEvent.click(screen.getByRole('button',{name:'Edit policy settings'}));const mode=await screen.findByLabelText('After publication');expect(mode).toHaveValue('manual');
    fireEvent.change(mode,{target:{value:'approval_request'}});fireEvent.click(screen.getByRole('button',{name:'Save distribution policy'}));
    await waitFor(()=>expect(api.policy).toHaveBeenCalledWith('workspace','group',expect.objectContaining({mode:'approval_request'}),0));
  });
  it('shows actionable preflight and protected retention reasons without creating a deployment',async()=>{
    page();fireEvent.click(await screen.findByRole('button',{name:'Run safe preflight'}));await screen.findByText(/Bring the registered agent online/);
    await openView('Policy');fireEvent.click(screen.getByRole('button',{name:'Preview retained versions'}));await screen.findByText(/desired consumer version/);expect(api.rollout).not.toHaveBeenCalled();
  });
  it('disables mutations when workspace operations are paused',async()=>{
    page({paused:true});expect(await screen.findByRole('button',{name:'Request rollout'})).toBeDisabled();await openView('Policy');fireEvent.click(screen.getByRole('button',{name:'Edit policy settings'}));expect(screen.getByRole('button',{name:'Save distribution policy'})).toBeDisabled();
  });
  it('waits for workspace pause authority before enabling mutations',async()=>{
    page({resolved:false});expect(await screen.findByRole('button',{name:'Request rollout'})).toBeDisabled();await openView('Policy');fireEvent.click(screen.getByRole('button',{name:'Edit policy settings'}));expect(screen.getByRole('button',{name:'Save distribution policy'})).toBeDisabled();
    await openView('Overview');expect(screen.getByRole('button',{name:'Run safe preflight'})).toBeEnabled();
  });
  it('requests exact-version cleanup approval only after administrator confirmation',async()=>{
    data.policy={revision:1,policy:structuredClone(policy)};data.policy.policy.retention.cleanupEnabled=true;data.policy.policy.retention.reportOnly=false;
    api.retention.mockResolvedValue({cleanupAvailable:true,versions:[{id:retained,provider_version:1,retainedReasons:[],metadataEligible:true}]});
    page();await openView('Policy');fireEvent.click(await screen.findByRole('button',{name:'Preview retained versions'}));fireEvent.click(await screen.findByRole('button',{name:'Request cleanup approval'}));expect(api.cleanup).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button',{name:'Confirm'}));await screen.findByText(/Cleanup approval requested in Jobs. Nothing has been deleted/);
    expect(api.cleanup).toHaveBeenCalledWith('workspace','group',{materialVersionId:retained,expectedRevision:1,reauthorize:false});
  });
  it('hides destructive cleanup from managers without administrator permission and excludes cleaned rollback material',async()=>{
    admin.mockReturnValue(false);data.versions[1].cleanup_state='soft_deleted';
    api.retention.mockResolvedValue({cleanupAvailable:true,versions:[{id:retained,provider_version:1,retainedReasons:[],metadataEligible:true}]});
    page();const select=await screen.findByLabelText('Exact published version');expect([...select.options].some(option=>option.value===retained)).toBe(false);
    await openView('Policy');fireEvent.click(screen.getByRole('button',{name:'Preview retained versions'}));await screen.findByText(/Metadata eligible/);expect(screen.queryByRole('button',{name:'Request cleanup approval'})).not.toBeInTheDocument();
  });
  it('distinguishes material identities when Vault objects share a provider version before cleanup review',async()=>{
    const oldest='33333333-3333-4333-8333-333333333333',protectedVersion='44444444-4444-4444-8444-444444444444';
    data.policy={revision:1,policy:structuredClone(policy)};
    Object.assign(data.policy.policy.retention,{minimumSeconds:0,minimumVersions:2,rollbackSeconds:0,cleanupEnabled:true,reportOnly:false});
    data.versions=[latest,protectedVersion,retained,oldest].map(id=>({id,state:'published',provider_version:1}));
    api.retention.mockResolvedValue({cleanupAvailable:true,versions:data.versions.map((version,index)=>({...version,retainedReasons:index<2?['minimum_version_count']:[],metadataEligible:index>=2}))});
    page();await openView('Policy');fireEvent.click(await screen.findByRole('button',{name:'Preview retained versions'}));
    await screen.findByText(`Material version ${oldest}`);
    for(const version of data.versions){
      const row=screen.getByRole('article',{name:`Material version ${version.id}`});
      expect(within(row).getByText('Store version 1')).toBeInTheDocument();
    }
    const row=screen.getByRole('article',{name:`Material version ${oldest}`});
    fireEvent.click(within(row).getByRole('button',{name:'Request cleanup approval'}));
    expect(api.cleanup).not.toHaveBeenCalled();
    expect(screen.getByRole('alertdialog')).toHaveTextContent(`soft delete only material version ${oldest}`);
    fireEvent.click(screen.getByRole('button',{name:'Confirm'}));
    await waitFor(()=>expect(api.cleanup).toHaveBeenCalledWith('workspace','group',{materialVersionId:oldest,expectedRevision:1,reauthorize:false}));
  });
  it('requires confirmation for a bounded administrator emergency and still requires rollout approval',async()=>{
    page();await openView('Destinations');fireEvent.click(await screen.findByRole('button',{name:'Maintenance'}));
    fireEvent.change(screen.getByLabelText('Emergency audit reference'),{target:{value:'CHANGE_248'}});
    fireEvent.click(screen.getByRole('button',{name:'Review emergency exception'}));expect(api.emergency).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button',{name:'Confirm'}));await screen.findByText(/Emergency authorization saved. Request a fresh rollout approval/);
    const body=api.emergency.mock.calls[0][3];expect(body.expectedAuthorizationRevision).toBe(2);expect(body.policy.requiresApproval).toBe(true);
    expect(Date.parse(body.policy.emergency.end)-Date.parse(body.policy.emergency.start)).toBe(3600000);
  });
  it('provides loading, empty, and retry states',async()=>{
    api.groups.mockRejectedValueOnce(new Error('offline'));page();await screen.findByText('Distribution sources unavailable');api.groups.mockResolvedValue({groups:[]});
    fireEvent.click(screen.getByRole('button',{name:'Retry'}));await screen.findByText('No distribution sources configured');
  });
});
