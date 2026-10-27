import {beforeEach,describe,expect,it,vi} from 'vitest';
import {fireEvent,render,screen,waitFor} from '@testing-library/react';
import {ChakraProvider} from '@chakra-ui/react';
import {MemoryRouter,Outlet,Route,Routes} from 'react-router';
import {DashboardThemeProvider} from '../../src/hooks/useDashboardTheme.js';
import CertOpsDistribution from '../../src/pages/certops/CertOpsDistribution.jsx';
const {api,manage,admin}=vi.hoisted(()=>({api:Object.fromEntries(['groups','management','preflight','retention','consumer','activation','policy','rollout','state','retry','cleanup','emergency'].map(key=>[key,vi.fn()])),manage:vi.fn(),admin:vi.fn()}));
vi.mock('../../src/components/certops/distributionApi.js',()=>({distributionApi:api}));
vi.mock('../../src/utils/WorkspaceContext.jsx',()=>({useWorkspace:()=>({workspaceId:'workspace'})}));
vi.mock('../../src/components/certops/useCertOps.js',()=>({useCertOpsCanManage:manage,useCertOpsIsWorkspaceAdmin:admin}));
const latest='11111111-1111-4111-8111-111111111111',retained='22222222-2222-4222-8222-222222222222';
const policy={mode:'manual',maxParallel:1,authorizationExpiresAt:null,verification:{enabled:false,intervalSeconds:3600,maxBackoffSeconds:86400,staleJobSeconds:3600,failureThreshold:3},
  alerts:{enabled:false,offlineSeconds:900,stuckSeconds:3600,convergenceSeconds:3600,expiryWarningDays:14,repeatSeconds:86400,contactGroupIds:[]},retention:{minimumSeconds:2592000,minimumVersions:3,rollbackSeconds:604800,cleanupEnabled:false,reportOnly:true,requiresApproval:true}};
const consumer={binding_id:'binding',assigned_agent_id:'agent',deployment_profile_ref:'nginx',profile_revision:1,authorization_revision:2,required:true,wave:0,verification_policy:'served',freshness_seconds:3600,
  binding_state:'active',agent_name:'Consumer host',agent_status:'offline',desired_version:2,observed_version:1,health_status:'old_certificate_active',verification_method:'installed',observed_at:new Date().toISOString(),observed_valid_to:'2027-01-01T00:00:00Z'};
let data;
function page({paused=false}={}){return render(<ChakraProvider><DashboardThemeProvider><MemoryRouter><Routes><Route element={<Outlet context={{certOpsPaused:paused}}/>}><Route path='/' element={<CertOpsDistribution/>}/></Route></Routes></MemoryRouter></DashboardThemeProvider></ChakraProvider>);}
beforeEach(()=>{vi.clearAllMocks();manage.mockReturnValue(true);admin.mockReturnValue(true);api.cleanup.mockResolvedValue({status:'pending_approval'});data={evaluated_at:new Date().toISOString(),group:{id:'group',state:'active',generation:1,material_store_ref:'customer',latest_material_version_id:latest},
  policy:null,defaults:structuredClone(policy),consumers:[structuredClone(consumer)],versions:[{id:latest,state:'published',provider_version:2,valid_to:'2027-01-01T00:00:00Z'},{id:retained,state:'published',provider_version:1,valid_to:'2026-12-01T00:00:00Z'}],
  rollouts:[],approvals:[],incidents:[],schedule:null,discoveries:[],agents:[{id:'agent',name:'Consumer host',status:'active'}],contactGroups:[{id:'ops',name:'Operations'}]};
  api.groups.mockResolvedValue({groups:[data.group]});api.management.mockImplementation(async()=>data);api.rollout.mockResolvedValue({status:'pending_approval'});api.policy.mockResolvedValue({});api.consumer.mockResolvedValue({});api.activation.mockResolvedValue({});
  api.preflight.mockResolvedValue({consumers:[{bindingId:'binding',diagnostics:[{code:'CERTOPS_AGENT_OFFLINE'},{code:'CERTOPS_CUSTOMER_LOCAL_PREFLIGHT_REQUIRED'}]}]});
  api.retention.mockResolvedValue({versions:[{id:latest,provider_version:2,retainedReasons:['desired_consumer_version']}]});});
describe('Distribution Management',()=>{
  it('keeps viewer permissions, coverage warnings and installed-versus-served assurance visible',async()=>{
    manage.mockReturnValue(false);admin.mockReturnValue(false);page();await screen.findByText('Consumer host · offline');
    expect(screen.getByText(/old certificate active/)).toBeInTheDocument();expect(screen.getByText('installed')).toBeInTheDocument();
    expect(screen.queryByRole('button',{name:'Add consumer'})).not.toBeInTheDocument();expect(screen.queryByRole('button',{name:'Request rollout'})).not.toBeInTheDocument();
    expect(screen.getByText(/A certificate in a machine store does not establish/)).toBeInTheDocument();
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
  it('adds a consumer using a registered agent and a customer-local alias',async()=>{
    page();fireEvent.click(await screen.findByRole('button',{name:'Add consumer'}));fireEvent.change(screen.getByLabelText('Registered agent'),{target:{value:'agent'}});
    fireEvent.change(screen.getByLabelText('Customer-local deployment profile'),{target:{value:'web_secondary'}});fireEvent.click(screen.getByRole('button',{name:'Save consumer'}));
    await waitFor(()=>expect(api.consumer).toHaveBeenCalledWith('workspace','group',expect.any(String),expect.objectContaining({agentId:'agent',deploymentProfileRef:'web_secondary',required:true,wave:0,verificationPolicy:'served'})));
  });
  it('saves policy through revision checks and keeps manual automation defaults',async()=>{
    page();const mode=await screen.findByLabelText('After publication');expect(mode).toHaveValue('manual');
    fireEvent.change(mode,{target:{value:'approval_request'}});fireEvent.click(screen.getByRole('button',{name:'Save distribution policy'}));
    await waitFor(()=>expect(api.policy).toHaveBeenCalledWith('workspace','group',expect.objectContaining({mode:'approval_request'}),0));
  });
  it('shows actionable preflight and protected retention reasons without creating a deployment',async()=>{
    page();fireEvent.click(await screen.findByRole('button',{name:'Run safe preflight'}));await screen.findByText(/Bring the registered agent online/);
    fireEvent.click(screen.getByRole('button',{name:'Preview retained versions'}));await screen.findByText(/desired consumer version/);expect(api.rollout).not.toHaveBeenCalled();
  });
  it('disables mutations when workspace operations are paused',async()=>{
    page({paused:true});expect(await screen.findByRole('button',{name:'Request rollout'})).toBeDisabled();expect(screen.getByRole('button',{name:'Save distribution policy'})).toBeDisabled();
  });
  it('requests exact-version cleanup approval only after administrator confirmation',async()=>{
    data.policy={revision:1,policy:structuredClone(policy)};data.policy.policy.retention.cleanupEnabled=true;data.policy.policy.retention.reportOnly=false;
    api.retention.mockResolvedValue({cleanupAvailable:true,versions:[{id:retained,provider_version:1,retainedReasons:[],metadataEligible:true}]});
    page();fireEvent.click(await screen.findByRole('button',{name:'Preview retained versions'}));fireEvent.click(await screen.findByRole('button',{name:'Request cleanup approval'}));expect(api.cleanup).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button',{name:'Confirm'}));await screen.findByText(/Cleanup approval requested in Jobs. Nothing has been deleted/);
    expect(api.cleanup).toHaveBeenCalledWith('workspace','group',{materialVersionId:retained,expectedRevision:1,reauthorize:false});
  });
  it('hides destructive cleanup from managers without administrator permission and excludes cleaned rollback material',async()=>{
    admin.mockReturnValue(false);data.versions[1].cleanup_state='soft_deleted';
    api.retention.mockResolvedValue({cleanupAvailable:true,versions:[{id:retained,provider_version:1,retainedReasons:[],metadataEligible:true}]});
    page();const select=await screen.findByLabelText('Exact published version');expect([...select.options].some(option=>option.value===retained)).toBe(false);
    fireEvent.click(screen.getByRole('button',{name:'Preview retained versions'}));await screen.findByText(/Metadata eligible/);expect(screen.queryByRole('button',{name:'Request cleanup approval'})).not.toBeInTheDocument();
  });
  it('requires confirmation for a bounded administrator emergency and still requires rollout approval',async()=>{
    page();fireEvent.click(await screen.findByRole('button',{name:'Maintenance'}));
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
