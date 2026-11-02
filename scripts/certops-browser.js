/**
 * Exercise certificate UI journeys in Chromium against a disposable dashboard/API.
 * certops-browser-qualification.yml supplies URLs and OpenSSL. Assertions combine
 * visible controls with authenticated API reads and reloads; fixture users and data
 * are removed on failure. Browser success alone does not qualify native deployment. */
"use strict";
const assert=require("node:assert/strict");
const {chromium}=require("playwright");
const {createApiFixture}=require("../tests/e2e/helpers/certops-api-fixture");
const {createHostGate}=require("../packages/agent/scripts/host-gate");
async function eventuallyBrowser(check){
  const deadline=Date.now()+30000;
  while(Date.now()<deadline){if(await check())return;await new Promise(resolve=>setTimeout(resolve,250));}
  throw new Error("Browser operation did not reach its expected persisted outcome");
}
async function main(){
  const api=process.env.CERTOPS_CSR_API_URL;
  const ui=process.env.CERTOPS_BROWSER_URL;
  assert.ok(api&&ui,"Real isolated API and dashboard URLs required");
  const fixture=await createApiFixture(api);
  let browser,primary,ready=false;
  const gate=createHostGate({suite:"browser-certificate-surfaces",evidenceLevel:"e2e",requiredCapabilities:["browser","api","openssl"],probeCapabilities:async()=>{
    let browserAvailable=false;
    try{browser=await chromium.launch({headless:true});browserAvailable=true;}catch{ /* A missing browser is a reported qualification prerequisite. */ }
    return {browser:{available:browserAvailable},api:{available:(await fetch(api)).ok},openssl:{available:require("node:child_process").spawnSync("openssl",["version"]).status===0}};
  }});
  gate.report.fixtureSource={file:"scripts/certops-browser.js",sha256:require("node:crypto").createHash("sha256").update(require("node:fs").readFileSync(__filename)).digest("hex")};
  gate.report.artifactQualification=process.env.GITHUB_ACTIONS==="true"?"workflow-checkout-source":"local-worktree-source-baseline-sha-only";
  try{
    assert.equal(await gate.preflight(),true);
    ready=true;
    const context=await browser.newContext();
    const page=await context.newPage();
    page.setDefaultTimeout(30000);
    await gate.scenario("browser-real-login",async()=>{
      gate.report.browserStage="login-page";
      await page.goto(new URL("/login",ui).href);
      gate.report.browserStage="login-form";
      await page.getByLabel("Email",{exact:true}).fill(fixture.email);
      await page.getByLabel("Password",{exact:true}).fill(fixture.password);
      await page.getByRole("button",{name:"Sign In",exact:true}).click();
      gate.report.browserStage="login-redirect";
      await page.waitForURL(url=>!url.pathname.includes("login"));
      const session=await context.request.get(new URL("/api/v1/workspaces",api).href);
      gate.report.browserStage="authenticated-session";
      assert.equal(session.status(),200,"Browser session must be authenticated by actual API");
    },{oracle:"Real credential form and authenticated API session; no request interception"});
    await gate.scenario("browser-certificate-navigation",async()=>{
      await page.goto(new URL("/certops/certificates",ui).href);
      const navigation=page.getByRole("navigation",{name:"Certificate Management sections"});
      for(const label of ["Jobs","Certificates","Renewals","Agents","Settings"]){
        gate.report.browserStage="navigate-"+label.toLowerCase();
        await navigation.getByRole("link",{name:label,exact:true}).click();
        await page.waitForURL(url=>url.pathname=== "/certops/"+label.toLowerCase());
        await navigation.getByRole("link",{name:label,exact:true}).waitFor({state:"visible"});
        await page.waitForFunction(expected=>[...document.querySelectorAll('nav[aria-label="Certificate Management sections"] a')].some(link=>link.textContent===expected&&link.getAttribute("aria-current")==="page"),label);
        const active=await navigation.getByRole("link",{name:label,exact:true}).getAttribute("aria-current");
        gate.report.navigationState=active || "none";
        assert.equal(active,"page");
      }
    },{oracle:"Actual React navigation and backend session"});
    await gate.scenario("browser-responsive-navigation",async()=>{
      for(const colorScheme of ["light","dark"]){
        await page.emulateMedia({colorScheme});
        await page.setViewportSize({width:390,height:844});
        await page.goto(new URL("/certops/renewals",ui).href);
        const navigation=page.getByRole("navigation",{name:"Certificate Management sections"});
        await navigation.getByRole("link",{name:"Settings",exact:true}).click();
        await page.waitForURL(url=>url.pathname==="/certops/settings");
      }
    },{oracle:"Phone viewport native navigation remains actionable; visual contrast qualification separate"});
    await gate.scenario("browser-keyboard-dialog",async()=>{
      await page.setViewportSize({width:1280,height:900});
      await page.goto(new URL("/certops/certificates",ui).href);
      const opener=page.getByRole("button",{name:"CSR workflows",exact:true});
      await opener.focus(); await page.keyboard.press("Enter");
      const dialog=page.getByRole("dialog"); await dialog.waitFor();
      await page.waitForFunction(()=>document.querySelector('[role="dialog"]')?.contains(document.activeElement));
      for(let index=0;index<12;index++){
        await page.keyboard.press("Tab");
        assert.equal(await dialog.evaluate(element=>element.contains(document.activeElement)),true,"Keyboard focus must remain within the open dialog");
      }
      await page.keyboard.press("Escape"); await dialog.waitFor({state:"hidden"});
      await page.waitForFunction(()=>document.activeElement?.textContent?.trim()==="CSR workflows");
    },{oracle:"Real keyboard opens dialog, focus remains contained and Escape restores opener focus"});
    await gate.scenario("browser-pause-persistence",async()=>{
      await page.setViewportSize({width:1280,height:900});
      await page.goto(new URL("/certops/settings",ui).href);
      await page.getByRole("button",{name:"Pause certificate operations",exact:true}).click();
      await page.getByRole("dialog").getByRole("button",{name:"Pause",exact:true}).click();
      await page.getByRole("button",{name:"Resume certificate operations",exact:true}).waitFor();
      assert.equal((await fixture.request('/api/v1/workspaces/'+fixture.workspaceId+'/certops/settings')).body.certOpsPaused,true);
      await page.getByRole("button",{name:"Resume certificate operations",exact:true}).click();
      await page.getByRole("dialog").getByRole("button",{name:"Resume",exact:true}).click();
      await page.getByRole("button",{name:"Pause certificate operations",exact:true}).waitFor();
      assert.equal((await fixture.request('/api/v1/workspaces/'+fixture.workspaceId+'/certops/settings')).body.certOpsPaused,false);
    },{oracle:"Actual browser settings write persists through independently read authenticated API"});
    await gate.scenario("browser-approval-persistence",async()=>{
      await page.goto(new URL("/certops/settings",ui).href);
      gate.report.browserStage="approval-control";
      const control=page.getByLabel("Require approval for every new job",{exact:true});
      await control.waitFor({state:"attached"});
      gate.report.browserStage="approval-check";
      assert.equal(await control.isChecked(),false);
      await control.locator("..").click();
      await page.waitForFunction(()=>document.querySelector('input[aria-label="Require approval for every new job"]')?.checked===true);
      await page.waitForFunction(()=>document.querySelector('input[aria-label="Require approval for every new job"]')?.disabled===false);
      assert.equal((await fixture.request('/api/v1/workspaces/'+fixture.workspaceId+'/certops/settings')).body.certOpsRequireApprovalAlways,true);
      await page.reload(); await control.waitFor(); assert.equal(await control.isChecked(),true);
      await control.locator("..").click();
      await page.waitForFunction(()=>document.querySelector('input[aria-label="Require approval for every new job"]')?.disabled===false);
      assert.equal((await fixture.request('/api/v1/workspaces/'+fixture.workspaceId+'/certops/settings')).body.certOpsRequireApprovalAlways,false);
    },{oracle:"Real browser approval setting survives reload and independent authenticated API read"});
    await gate.scenario("browser-settings-failed-save",async()=>{
      const route=`/api/v1/workspaces/${fixture.workspaceId}/certops/settings`;
      const before=(await fixture.request(route)).body;
      const control=page.getByLabel("Require approval for every new job",{exact:true});
      assert.equal(await control.isChecked(),before.certOpsRequireApprovalAlways);
      // Revoke permission after the real form has loaded. The stale visible
      // control must still obey the actual backend's authorization decision.
      const previous=(await fixture.pool.query("SELECT role FROM workspace_memberships WHERE workspace_id=$1 AND user_id=$2",[fixture.workspaceId,fixture.userId])).rows[0].role;
      assert.equal(previous,"admin");
      try{
        await fixture.pool.query("UPDATE workspace_memberships SET role='workspace_manager' WHERE workspace_id=$1 AND user_id=$2",[fixture.workspaceId,fixture.userId]);
        const responsePromise=page.waitForResponse(response=>new URL(response.url()).pathname===route&&response.request().method()==="PUT");
        await control.locator("..").click();
        const response=await responsePromise;assert.equal(response.status(),403);
        const body=await response.json();assert.equal(typeof body.error,"string");
        await page.getByText(body.error,{exact:true}).waitFor();
        await page.waitForFunction(()=>document.querySelector('input[aria-label="Require approval for every new job"]')?.disabled===false);
        assert.equal(await control.isChecked(),before.certOpsRequireApprovalAlways);
        const after=(await fixture.request(route)).body;
        assert.equal(after.certOpsRequireApprovalAlways,before.certOpsRequireApprovalAlways);
        assert.equal(after.certOpsPaused,before.certOpsPaused);
      }finally{
        await fixture.pool.query("UPDATE workspace_memberships SET role=$3 WHERE workspace_id=$1 AND user_id=$2",[fixture.workspaceId,fixture.userId,previous]);
      }
      await page.reload();await control.waitFor();assert.equal(await control.isChecked(),before.certOpsRequireApprovalAlways);
    },{oracle:"Actual permission revocation and HTTP403, visible backend error, unchanged API policy and restored fixture role; no intercepted requests"});
    // A stored public policy is a supporting prerequisite, not issuance or
    // native agent evidence. All changes below go through the real dashboard.
    const profileName="Browser owned renewal policy";
    const profileId=(await fixture.pool.query("INSERT INTO certificate_profiles(workspace_id,name,key_mode,renew_before_days,public_metadata,created_by) VALUES($1,$2,'agent-local',30,$3,$4) RETURNING id",[fixture.workspaceId,profileName,JSON.stringify({renewalProfile:{schemaVersion:1,keyAlgorithm:"rsa",keySize:2048,sanPolicy:{mode:"exact",sans:["browser.example.test"],allowWildcards:false}}}),fixture.userId])).rows[0].id;
    const readProfile=async()=>{
      const response=await fixture.request(`/api/v1/workspaces/${fixture.workspaceId}/certops/profiles/${profileId}`);
      assert.equal(response.status,200);return response.body;
    };
    const profileRow=()=>page.getByRole("row").filter({hasText:profileName});
    const openProfiles=async()=>{
      const disclosure=page.locator('button[aria-controls="certops-renewal-profiles"]');
      await disclosure.waitFor();
      if(await disclosure.getAttribute("aria-expanded")!=="true")await disclosure.click();
    };
    await gate.scenario("browser-renewal-switch-persistence",async()=>{
      assert.equal((await readProfile()).autoRenewEnabled,true);
      await page.goto(new URL("/certops/renewals",ui).href);
      await openProfiles();
      gate.report.browserStage="renewal-switch-off";
      await profileRow().getByRole("button",{name:"Switch off",exact:true}).click();
      gate.report.browserStage="renewal-switch-confirmation";
      await page.getByRole("dialog").getByRole("button",{name:"Switch renewal off",exact:true}).click();
      gate.report.browserStage="renewal-switch-disabled";
      await profileRow().getByRole("button",{name:"Switch on",exact:true}).waitFor();
      assert.equal((await readProfile()).autoRenewEnabled,false);
      await page.reload();await openProfiles();await profileRow().getByRole("button",{name:"Switch on",exact:true}).click();
      await profileRow().getByRole("button",{name:"Switch off",exact:true}).waitFor();
      assert.equal((await readProfile()).autoRenewEnabled,true);
      await page.reload();await openProfiles();await profileRow().getByRole("button",{name:"Switch off",exact:true}).waitFor();
    },{oracle:"Real browser confirmation, persisted public profile API and reload; no issuance claim"});
    await gate.scenario("browser-renewal-lead-time-persistence",async()=>{
      const original=await readProfile();
      await profileRow().getByRole("button",{name:"Change",exact:true}).click();
      await profileRow().getByLabel("Renewal lead time in days",{exact:true}).fill("45");
      await profileRow().getByRole("button",{name:"Save",exact:true}).click();
      await eventuallyBrowser(async()=>(await readProfile()).renewBeforeDays===45);
      await page.reload();await openProfiles();await profileRow().getByText("45 days",{exact:true}).waitFor();
      assert.deepEqual((await readProfile()).renewalProfile,original.renewalProfile,"Lead-time edit must preserve execution policy");
    },{oracle:"Actual permitted policy edit persists without changing public execution contract"});
    await gate.scenario("browser-renewal-edit-cancellation",async()=>{
      const original=await readProfile();
      await profileRow().getByRole("button",{name:"Change",exact:true}).click();
      await profileRow().getByLabel("Renewal lead time in days",{exact:true}).fill("60");
      await profileRow().getByRole("button",{name:"Cancel",exact:true}).click();
      await profileRow().getByRole("button",{name:"Switch off",exact:true}).click();
      await page.getByRole("dialog").getByRole("button",{name:"Keep renewing",exact:true}).click();
      await page.reload();await openProfiles();await profileRow().getByText("45 days",{exact:true}).waitFor();
      const after=await readProfile();assert.equal(after.renewBeforeDays,original.renewBeforeDays);assert.equal(after.autoRenewEnabled,true);assert.deepEqual(after.renewalProfile,original.renewalProfile);
      assert.equal(Number((await fixture.pool.query("SELECT count(*) AS count FROM certificate_jobs WHERE workspace_id=$1",[fixture.workspaceId])).rows[0].count),0,"Policy-only controls must create no execution jobs");
    },{oracle:"Real cancelled dialogs and independent API/database confirm unchanged policy and zero jobs"});
    await gate.scenario("browser-viewer-settings",async()=>{
      const viewer=await createApiFixture(api);
      let viewerContext;
      let viewerPage;
      try{
        await fixture.pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES($1,$2,'viewer')",[fixture.workspaceId,viewer.userId]);
        viewerContext=await browser.newContext();
        viewerPage=await viewerContext.newPage(); viewerPage.setDefaultTimeout(30000);
        gate.report.viewerResponseStatuses=[];
        viewerPage.on("response",response=>{if(gate.report.viewerResponseStatuses.length<64&&new URL(response.url()).pathname.includes('/api/v1/workspaces/'))gate.report.viewerResponseStatuses.push(response.status());});
        await viewerPage.goto(new URL("/login",ui).href);
        await viewerPage.getByLabel("Email",{exact:true}).fill(viewer.email);
        await viewerPage.getByLabel("Password",{exact:true}).fill(viewer.password);
        await viewerPage.getByRole("button",{name:"Sign In",exact:true}).click();
        await viewerPage.waitForURL(url=>!url.pathname.includes("login"));
        const membership=await viewer.request('/api/v1/workspaces/'+fixture.workspaceId);
        gate.report.viewerObservedRole=membership.body.role||"unavailable";
        gate.report.browserStage="viewer-controls";
        const viewerUrl=new URL("/certops/settings",ui);
        viewerUrl.searchParams.set("workspace",fixture.workspaceId);
        await viewerPage.goto(viewerUrl.href);
        gate.report.viewerPagePath=new URL(viewerPage.url()).pathname;
        await viewerPage.waitForURL(url=>url.pathname==="/dashboard");
        assert.equal(await viewerPage.getByLabel("Require approval for every new job",{exact:true}).count(),0);
        assert.equal(await viewerPage.getByRole("button",{name:"Create token",exact:true}).count(),0);
        const before=await viewer.request('/api/v1/workspaces/'+fixture.workspaceId+'/certops/settings');
        assert.equal((await viewer.request('/api/v1/workspaces/'+fixture.workspaceId+'/certops/settings','PUT',{certOpsRequireApprovalAlways:true})).status,403);
        const after=await viewer.request('/api/v1/workspaces/'+fixture.workspaceId+'/certops/settings');
        assert.equal(after.body.certOpsRequireApprovalAlways,before.body.certOpsRequireApprovalAlways);
      }catch(error){
        if(viewerPage){
          gate.report.viewerWorkspaceMatches=new URL(viewerPage.url()).searchParams.get("workspace")===fixture.workspaceId;
          const text=await viewerPage.locator("body").innerText();
          gate.report.viewerScreen={settings:text.includes("Job approval"),notice:text.includes("Only workspace admins"),availabilityError:text.includes("Could not load certificate operations status"),disabled:text.includes("Certificate operations are not enabled")};
        }
        throw error;
      }finally{try{if(viewerContext)await viewerContext.close();}finally{await viewer.cleanup();}}
    },{oracle:"Actual viewer membership blocks the CertOps route despite admin access in another workspace; authenticated server refuses settings write and preserves policy"});
    await gate.scenario("browser-machine-token-lifecycle",async()=>{
      gate.report.browserStage="machine-token-open";
      const settingsUrl=new URL("/certops/settings",ui);settingsUrl.searchParams.set("workspace",fixture.workspaceId);
      await page.goto(settingsUrl.href);
      await page.getByRole("button",{name:"Create token",exact:true}).click();
      const dialog=page.getByRole("dialog");
      gate.report.browserStage="machine-token-fields";
      await dialog.getByPlaceholder("e.g. certbot-prod-hook",{exact:true}).fill("Browser scoped machine fixture");
      gate.report.browserStage="machine-token-scope";
      await dialog.getByRole("checkbox",{name:/^events:write/}).locator("..").click();
      gate.report.browserStage="machine-token-submit";
      await dialog.getByRole("button",{name:"Create token",exact:true}).click();
      gate.report.browserStage="machine-token-secret";
      const secret=await dialog.getByText(/^ttx_[a-f0-9]{16}_[a-f0-9]{64}$/).textContent();
      assert.match(secret,/^ttx_[a-f0-9]{16}_[a-f0-9]{64}$/);
      await page.keyboard.press("Escape");assert.equal(await dialog.isVisible(),true,"Unacknowledged one-time credential must remain visible");
      const listed=await fixture.request('/api/v1/workspaces/'+fixture.workspaceId+'/certops/tokens');
      assert.ok(!JSON.stringify(listed.body).includes(secret));
      const machineEvent=()=>fetch(new URL("/api/v1/certops/executor/events",api),{method:"POST",signal:AbortSignal.timeout(15000),headers:{"content-type":"application/json",authorization:`Bearer ${secret}`},body:JSON.stringify({workspaceId:fixture.workspaceId})});
      assert.equal((await machineEvent()).status,400,"UI-created credential must authenticate before event-body validation");
      gate.report.browserStage="machine-token-acknowledge";
      await dialog.getByRole("button",{name:"I stored the token",exact:true}).click();
      await dialog.getByRole("button",{name:"Done",exact:true}).click();await dialog.waitFor({state:"hidden"});
      await page.reload();await page.getByText("Browser scoped machine fixture",{exact:true}).waitFor();
      gate.report.browserStage="machine-token-revoke";
      assert.ok(!(await page.locator("body").innerText()).includes(secret),"Reloaded token inventory must not reveal the one-time credential");
      await page.getByRole("button",{name:"Revoke",exact:true}).click();
      await page.getByRole("alertdialog").getByRole("button",{name:"Revoke",exact:true}).click();
      await eventuallyBrowser(async()=> (await machineEvent()).status===401);
    },{oracle:"Actual browser creates scoped show-once credential, acknowledgment protects closure, inventory never re-reveals it and public revocation fences real executor HTTP"});
    await gate.scenario("browser-public-csr",async()=>{
      const fs=require("node:fs"),path=require("node:path");
      const directory=fs.mkdtempSync(path.join(require("node:os").tmpdir(),"certops-browser-csr-"));
      try{
        const run=args=>{const result=require("node:child_process").spawnSync("openssl",args,{cwd:directory,stdio:"ignore",timeout:20000});assert.equal(result.status,0,"Browser CSR signer prerequisite failed");};
        run(["req","-new","-newkey","rsa:2048","-nodes","-keyout","private.key","-out","public.csr","-subj","/CN=browser.example.test","-addext","subjectAltName=DNS:browser.example.test"]);
        run(["x509","-req","-in","public.csr","-signkey","private.key","-copy_extensions","copy","-days","2","-out","public.crt"]);
        await page.goto(new URL("/certops/certificates",ui).href);
        await page.getByRole("button",{name:"CSR workflows",exact:true}).click();
        const dialog=page.getByRole("dialog");
        await dialog.getByLabel("CSR PEM",{exact:true}).fill(fs.readFileSync(path.join(directory,"public.csr"),"utf8"));
        await dialog.getByLabel("New target name",{exact:true}).fill("Browser fixture target");
        await dialog.getByRole("button",{name:"Save CSR",exact:true}).click();
        await dialog.getByLabel("CA-signed public certificate PEM",{exact:true}).fill(fs.readFileSync(path.join(directory,"public.crt"),"utf8"));
        await dialog.getByRole("button",{name:"Import signed certificate",exact:true}).click();
        await dialog.getByRole("button",{name:"Confirm installation",exact:true}).click();
        await dialog.getByText("Completed by manager attestation.",{exact:true}).waitFor();
        const rows=await fixture.request('/api/v1/workspaces/'+fixture.workspaceId+'/certops/csrs');
        const fingerprint=new(require("node:crypto").X509Certificate)(fs.readFileSync(path.join(directory,"public.crt"))).fingerprint256.replace(/:/g,"").toLowerCase();
        assert.ok(rows.body.items.some(row=>row.status==="completed"&&row.signedFingerprintSha256===fingerprint));
      }finally{fs.rmSync(directory,{recursive:true,force:true});}
    },{oracle:"Actual browser CSR submit/import/attestation agrees with independently signed public leaf and API workflow; attestation is not deployment proof"});
    await gate.scenario("browser-private-key-refusal",async()=>{
      await page.goto(new URL("/certops/certificates",ui).href);
      await page.getByRole("button",{name:"CSR workflows",exact:true}).click();
      const dialog=page.getByRole("dialog");
      const before=await fixture.request('/api/v1/workspaces/'+fixture.workspaceId+'/certops/csrs');
      const key=require("node:crypto").generateKeyPairSync("ec",{namedCurve:"prime256v1",privateKeyEncoding:{type:"pkcs8",format:"pem"},publicKeyEncoding:{type:"spki",format:"pem"}}).privateKey;
      let submissions=0;
      const count=request=>{if(request.method()==="POST"&&new URL(request.url()).pathname.endsWith("/certops/csrs"))submissions++;};
      page.on("request",count);
      try{
        await dialog.getByLabel("New target name",{exact:true}).fill("Refused private material");
        for(const value of [key,Buffer.from(key).toString("base64")]){
          await dialog.getByLabel("CSR PEM",{exact:true}).fill(value);
          await dialog.getByRole("button",{name:"Save CSR",exact:true}).click();
          await dialog.getByText(/This looks like it contains a private key/).waitFor();
        }
        assert.equal(submissions,0,"Browser courtesy guard must refuse before transport");
        const after=await fixture.request('/api/v1/workspaces/'+fixture.workspaceId+'/certops/csrs');
        assert.equal(after.body.items.length,before.body.items.length);
      }finally{page.off("request",count);await dialog.getByLabel("CSR PEM",{exact:true}).fill("");}
    },{oracle:"Real browser rejects generated raw and wrapped private key before HTTP submission; public workflow inventory stays unchanged"});
    await gate.scenario("browser-adcs-prerequisite-gate",async()=>{
      gate.report.browserStage="adcs-disclosure";
      await page.goto(new URL("/certops/renewals",ui).href);
      await page.getByRole("button",{name:/AD CS issuers/}).click();
      await page.getByRole("button",{name:"New issuer",exact:true}).click();
      gate.report.browserStage="adcs-name";
      const dialog=page.getByRole("dialog");
      assert.equal(await dialog.getByRole("button",{name:"Continue",exact:true}).isEnabled(),false);
      await dialog.getByLabel("Issuer name",{exact:true}).fill("Browser pending qualification issuer");
      await dialog.getByRole("button",{name:"Continue",exact:true}).click();
      gate.report.browserStage="adcs-fields";
      await dialog.getByLabel("CA config",{exact:true}).fill("fixture.example.test\\Qualification CA");
      await dialog.getByLabel("Template",{exact:true}).fill("QualificationTemplate");
      assert.equal(await dialog.getByRole("button",{name:"Run check",exact:true}).isEnabled(),false,"No real agent is available to qualify CA preflight");
      const rows=await fixture.request('/api/v1/workspaces/'+fixture.workspaceId+'/certops/issuers');
      gate.report.browserStage="adcs-api-read";
      gate.report.issuerListStatus=rows.status;
      assert.equal(rows.status,200);
      assert.equal(rows.body.items.length,0,"Wizard prerequisites must not fabricate an approved issuer");
      const drafts=await fixture.request('/api/v1/workspaces/'+fixture.workspaceId+'/certops/issuers?includeUnconfigured=true');
      assert.equal(drafts.status,200);
      assert.ok(drafts.body.items.every(row=>row.currentVersion===0),"Any wizard draft must remain unqualified");
      await dialog.getByRole("button",{name:"Close",exact:true}).last().click();
    },{oracle:"Actual AD CS wizard requires agent/preflight prerequisites; no fake safe verdict or CA approval"});
  }catch(error){primary=error;throw error;}
  finally{
    try{
      const cleanup=async()=>{try{if(browser)await browser.close();}finally{await fixture.cleanup();}};
      if(ready){
        await gate.scenario("browser-fixture-cleanup",cleanup,{oracle:"Run-owned API identities and session fixture removed"});
        await gate.finish({requiredScenarios:["browser-real-login","browser-certificate-navigation","browser-responsive-navigation","browser-keyboard-dialog","browser-pause-persistence","browser-approval-persistence","browser-settings-failed-save","browser-renewal-switch-persistence","browser-renewal-lead-time-persistence","browser-renewal-edit-cancellation","browser-viewer-settings","browser-machine-token-lifecycle","browser-public-csr","browser-private-key-refusal","browser-adcs-prerequisite-gate","browser-fixture-cleanup"]});
      }else await cleanup();
    }catch(error){if(primary)throw new AggregateError([primary,error],"Browser journey and finalization failed");throw error;}
  }
}
if(require.main===module)main().catch(()=>{console.error("Browser certificate qualification failed; inspect sanitized report");process.exitCode=1;});
module.exports={main};
