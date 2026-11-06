"use strict";
const fs = require("node:fs"), path = require("node:path"), assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { spawnSync } = require("node:child_process");
const { readProtectedFile } = require("../packages/agent/src/material-store/index");
const root = path.resolve(__dirname,".."), configFile=path.resolve(process.argv[2] || "");
if(!configFile.startsWith(path.join(root,".tmp")+path.sep))throw new Error("Expected this checkout's protected UI fixture config");
const config=JSON.parse(readProtectedFile(configFile));
const candidateSha=spawnSync("git",["rev-parse","HEAD"],{cwd:root,encoding:"utf8",windowsHide:true}).stdout.trim();
for(const url of [config.apiUrl,config.dashboardUrl])assert.match(url,/^http:\/\/127\.0\.0\.1:\d+$/);
async function main(){
  const browser=await chromium.launch({headless:true});
  const scenarios=[];
  try{
    const context=await browser.newContext({viewport:{width:1440,height:1000}});
    const csrf=await(await context.request.get(config.apiUrl+"/api/csrf-token")).json();
    const login=await context.request.post(config.apiUrl+"/auth/login",{data:{email:config.email,password:config.password},headers:{"X-CSRF-Token":csrf.csrfToken}});
    assert.equal(login.status(),200,"Normal session login must succeed");
    const page=await context.newPage();
    const url=`${config.dashboardUrl}/certops/distribution?workspace=${config.workspaceId}&group=${config.groupId}`;
    const capture=async(name,expected)=>{
      const file=name+".png";await page.screenshot({path:path.join(config.evidence,file),fullPage:true});
      scenarios.push({name,repository:"tokentimerch/tokentimer-core",candidateSha,environment:"owned loopback API/dashboard and disposable PostgreSQL",
        action:`Open ${name.replace(/-/g," ")} in the running application`,expected,actual:"Rendered by the real dashboard using the running API and PostgreSQL",status:"PASS",screenshot:file,
        limitation:"Disposable fixtures; this does not establish complete fleet/operator or native artifact acceptance."});
    };
    await page.goto(url);
    await page.getByRole("heading",{name:"Distribution Management",exact:true}).waitFor();
    await page.getByRole("button",{name:"Maintenance",exact:true}).waitFor();
    await capture("distribution-overview","Consumer desired/observed proof remains unknown until verified; no installation is inferred from publication.");
    await page.getByRole("button",{name:"Maintenance",exact:true}).click();
    await page.getByRole("button",{name:"Save activation policy",exact:true}).waitFor();
    const approval=page.getByRole("checkbox",{name:"Require explicit rollout approval",exact:true});
    if(!await approval.isChecked())await page.getByText("Require explicit rollout approval",{exact:true}).click();
    assert.equal(await approval.isChecked(),true);
    await capture("maintenance-policy","Maintenance approval, calendar and unsupported connector controls are visible.");
    await page.getByRole("button",{name:"Save activation policy",exact:true}).click();
    await page.getByRole("button",{name:"Preview retained versions",exact:true}).click();
    await page.getByText("soft deleted",{exact:false}).first().waitFor();
    const proof=JSON.parse(fs.readFileSync(path.join(config.evidence,"provider-completion.json")));
    await page.getByRole("article",{name:`Material version ${proof.materialVersionId}`,exact:true}).scrollIntoViewIfNeeded();
    await capture("retention-cleanup","The genuine completed cleanup is visible alongside exact material IDs and retention protection reasons.");
    const select=page.getByLabel("Exact published version");
    const values=await select.locator("option").evaluateAll(options=>options.map(option=>option.value).filter(Boolean));
    assert.ok(values.length);
    await select.selectOption(values[0]);
    await page.getByRole("button",{name:"Request rollout",exact:true}).click();
    await page.getByRole("button",{name:"Confirm",exact:true}).waitFor();
    await capture("exact-rollout-request","The exact selected material and destinations are presented before requesting execution.");
    await page.getByRole("button",{name:"Confirm",exact:true}).click();
    await page.getByText("Request created. Review and approve the exact version in Jobs.",{exact:true}).waitFor();
    await capture("pending-rollout-approval","The approved-scope request is visibly pending; it is not represented as completed installation.");
    await page.goto(`${config.dashboardUrl}/certops/jobs?workspace=${config.workspaceId}`);
    await page.getByRole("heading",{name:/Jobs/}).first().waitFor();
    await page.locator("span").filter({hasText:/^Pending approval$/}).first().waitFor();
    await capture("jobs-cleanup-and-approval","Real completed cleanup and pending rollout jobs are shown by the application.");
    await page.getByRole("button",{name:"Approve",exact:true}).first().click();
    await page.getByText("Immutable approval scope",{exact:true}).first().waitFor();
    await capture("exact-pending-review","Fresh job detail presents the pending version, destination and activation policy for independent review.");
  }finally{
    fs.writeFileSync(path.join(config.evidence,"ui-scenarios.json"),JSON.stringify({schemaVersion:1,scenarios},null,2)+"\n");
    await browser.close();
  }
  console.log(`${scenarios.length} genuine browser captures: ${config.evidence}`);
}
main().catch(error=>{console.error(error.message);process.exitCode=1;});
