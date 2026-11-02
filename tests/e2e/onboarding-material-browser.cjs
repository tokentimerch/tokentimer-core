"use strict";
// Real Chromium and the shipped React components, with synthetic API responses.
// This is UI/HTTP-intent validation, not provider, CA, IIS or production qualification.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");
const { pathToFileURL } = require("node:url");
const { chromium } = require("playwright");
const root = path.resolve(__dirname, "../..");
const dashboard = path.join(root, "apps/dashboard");
const dashboardRequire = createRequire(path.join(dashboard, "package.json"));
const WS = "11111111-1111-4111-8111-111111111111", GROUP = "22222222-2222-4222-8222-222222222222";
const ISSUER = "44444444-4444-4444-8444-444444444444", CONSUMER = "55555555-5555-4555-8555-555555555555";
const VERSION = "33333333-3333-4333-8333-333333333333";
function fixture(provider = "vault-kv2", role = "workspace_manager") {
  const setup = { provider, issuerAgentId: ISSUER, materialStoreRef: "customer", issuanceProfileRef: "wildcard", profileRevision: 1, groupId: GROUP };
  const caps = ["material-store-vault-kv2-v1", "material-store-openbao-kv2-v1", "certificate-publication-v1", "deploy-from-store-v1", "evidence-claim-binding-v1"];
  return {
    workspaceId: WS,
    session: { intent: { goal: "certops_vault" }, progress: { certops: { objective: "vault", materialSetup: setup, names: "web.example.test", zone: "example.test" } } },
    capabilities: { viewer: { workspaceRole: role }, items: [
      ...["certops.core", "certops.vault_distribution"].map(id => ({ id, qualified: true, authorized: role !== "viewer", state: role === "viewer" ? "role_handoff" : "ready" })),
      ...["vault_kv2", "openbao_kv2", "azure_key_vault"].map(p => ({ id: `certops.material_store_${p}`, qualified: p !== "azure_key_vault", authorized: role !== "viewer", state: p === "azure_key_vault" ? "candidate" : role === "viewer" ? "role_handoff" : "ready" })),
      { id: "certops.windows_material_iis", qualified: false, authorized: role !== "viewer", state: "candidate" },
    ] },
    summary: { certops: { agents: { items: [
      { id: ISSUER, wireAgentId: "issuer-wire", name: "Issuer", platform: "linux", livenessState: "live", claimEvidenceFresh: true, declaredCapabilities: caps, supportedOperations: ["issue"], commandProfiles: ["certbot"] },
      { id: CONSUMER, wireAgentId: "consumer-wire", name: "Consumer", platform: "linux", livenessState: "live", claimEvidenceFresh: true, declaredCapabilities: caps, supportedOperations: ["deploy-from-store"], commandProfiles: [] },
    ] }, distribution: { items: [{ id: GROUP, ...setup, active: true, completed: false, verified: false,
      publication: provider === "azure-key-vault" ? null : { materialVersionId: VERSION, publishedAt: new Date().toISOString(), validTo: new Date(Date.now() + 86400000).toISOString() } }] } } },
  };
}
const entry = `import React, {useState} from 'react';
import {createRoot} from 'react-dom/client';
import {ChakraProvider, Box, Button, HStack, Text} from '@chakra-ui/react';
import {theme} from '/src/styles/theme.js';
import {DashboardThemeProvider} from '/src/hooks/useDashboardTheme.js';
import {MaterialStoreStep} from '/src/components/onboarding/materialStoreStep.jsx';
import {MaterialConsumerStep} from '/src/components/onboarding/materialConsumerStep.jsx';
import {materialConsumersSatisfied} from '/src/components/onboarding/materialSetupModel.js';
function Lab(){
 const [session,setSession]=useState(window.__fixture.session), [summary,setSummary]=useState(window.__fixture.summary), [step,setStep]=useState('store');
 const ctx={...window.__fixture,session,summary,docs:()=>[],refresh:async()=>{const r=await fetch('/api/onboarding-lab/summary');const s=await r.json();setSummary(s);return s;},
 controller:{update:async fn=>{const next={...session,...fn(session)};await fetch('/api/onboarding-lab/progress',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(next)});setSession(next);}}};
 return <Box maxW='960px' mx='auto' p={4}><Text>Synthetic component lab; no real provider or deployment</Text><HStack mb={4}><Button onClick={()=>setStep('store')}>Store step</Button><Button onClick={()=>setStep('consumers')}>Consumer step</Button></HStack>
 <Text data-testid='backend-completion'>{materialConsumersSatisfied(summary,session.progress.certops)?'Backend consumer evidence complete':'Backend consumer evidence incomplete'}</Text>
 {step==='store'?<MaterialStoreStep ctx={ctx}/>:<MaterialConsumerStep ctx={ctx}/>}</Box>;
}
createRoot(document.getElementById('root')).render(<ChakraProvider theme={theme}><DashboardThemeProvider><Lab/></DashboardThemeProvider></ChakraProvider>);`;

async function main() {
  const scratch = path.resolve(dashboard, ".scratch");
  fs.mkdirSync(scratch, { recursive: true });
  const directory = fs.mkdtempSync(path.join(scratch, "onboarding-browser-"));
  const evidence = path.join(root, ".scratch/onboarding-material-browser-evidence");
  fs.mkdirSync(evidence, { recursive: true });
  fs.writeFileSync(path.join(directory, "entry.jsx"), entry);
  fs.writeFileSync(path.join(directory, "index.html"), '<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><script>window.__ENV__={API_URL:location.origin};</script></head><body><div id="root"></div><script type="module" src="./entry.jsx"></script></body></html>');
  const vite = await import(pathToFileURL(dashboardRequire.resolve("vite")).href);
  let server, browser;
  const report = { passed: 0, failed: 0, skipped: 0, scope: "Chromium with synthetic backend fixtures", screenshots: [] };
  try {
    server = await vite.createServer({ configFile: path.join(dashboard, "vite.config.js"), root: dashboard,
      server: { host: "127.0.0.1", port: 0 }, logLevel: "error" });
    await server.listen();
    const url = `http://127.0.0.1:${server.httpServer.address().port}/.scratch/${path.basename(directory)}/index.html`;
    browser = await chromium.launch({ headless: true });
    for (const width of [1280, 390]) {
      const context = await browser.newContext({ viewport: { width, height: 900 } });
      const page = await context.newPage();
      const facts = fixture("openbao-kv2"), requests = [], errors = [];
      let consumers = [];
      page.on("pageerror", e => errors.push(e.message));
      await page.addInitScript(data => { window.__fixture = data; }, facts);
      await page.route("**/api/**", async route => {
        const request = route.request(), pathname = new URL(request.url()).pathname;
        const body = request.postDataJSON();
        if (request.method() !== "GET") requests.push({ pathname, method: request.method(), body });
        let response = {};
        if (pathname.endsWith("/summary")) response = facts.summary;
        else if (pathname.endsWith("/progress")) { facts.session = body; response = body; }
        else if (pathname.endsWith("/csrf-token")) response = { csrfToken: "synthetic-csrf-fixture" };
        else if (pathname.endsWith("/settings")) response = { certOpsRequireApprovalAlways: true };
        else if (pathname.endsWith("/versions")) response = { versions: [{ id: VERSION, state: "published", provider_version: 1, valid_to: new Date(Date.now() + 86400000).toISOString() }] };
        else if (pathname.endsWith("/consumers")) response = { consumers };
        else if (pathname.includes("/consumers/") && request.method() === "PUT") {
          const id = pathname.split("/").pop();
          const binding = { id, group_id: GROUP, assigned_agent_id: body.agentId, deployment_profile_ref: body.deploymentProfileRef,
            profile_revision: body.profileRevision, authorization_revision: 1, verification_policy: body.verificationPolicy, state: "active" };
          consumers = [{ ...binding, binding_id: id, binding_state: "active" }]; response = { binding };
        } else if (pathname.endsWith("/rollouts")) response = { job: { id: "verification-job", status: "pending_approval" } };
        else if (/\/jobs\/[^/]+$/.test(pathname)) response = { job: { id: "verification-job", operation: "deploy-from-store", status: "pending_approval", mode: "real" } };
        else response = { items: [], pagination: { limit: 100, offset: 0 }, lines: [], cursor: null };
        await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(response) });
      });
      await page.goto(url);
      await page.getByRole("heading", { name: "Configure material store", exact: true }).waitFor();
      await page.getByText("Agent publication verified", { exact: true }).waitFor();
      await page.getByLabel("Customer-local store HTTPS address").fill("https://browser-only-store.example.test");
      const savedProgress = page.waitForResponse(r => r.url().endsWith("/progress") && r.status() === 200);
      await page.getByRole("button", { name: "Save public references", exact: true }).click();
      await savedProgress;
      assert.equal(JSON.stringify(facts.session).includes("browser-only-store"), false);
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), "Store layout must not overflow the viewport");
      const storeShot = `store-${width}.png`; await page.screenshot({ path: path.join(evidence, storeShot) }); report.screenshots.push(storeShot);
      await page.getByRole("button", { name: "Consumer step", exact: true }).click();
      await page.getByLabel("Customer-local store HTTPS address").fill("https://browser-only-store.example.test");
      await page.getByRole("button", { name: "Assign Consumer", exact: true }).click();
      await page.getByRole("group", { name: /Consumer configuration/ }).waitFor();
      assert.equal(requests.find(r => r.pathname.includes("/consumers/")).body.verificationPolicy, "installed");
      await page.getByRole("button", { name: "Check installed material (no deployment)", exact: true }).click();
      await page.getByTestId("approval-wait").waitFor();
      assert.equal(requests.find(r => r.pathname.endsWith("/rollouts")).body.verificationOnly, true);
      assert.match(await page.getByTestId("backend-completion").textContent(), /incomplete/);
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), "Consumer layout must not overflow the viewport");
      const consumerShot = `consumers-${width}.png`; await page.screenshot({ path: path.join(evidence, consumerShot) }); report.screenshots.push(consumerShot);
      facts.summary.certops.distribution.items[0].completed = true;
      await page.getByRole("button", { name: "Refresh consumer evidence", exact: true }).click();
      await page.getByText("Backend consumer evidence complete", { exact: true }).waitFor();
      facts.summary.certops.distribution.items[0].completed = false;
      await page.getByRole("button", { name: "Refresh consumer evidence", exact: true }).click();
      await page.getByText("Backend consumer evidence incomplete", { exact: true }).waitFor();
      await page.getByLabel("Consumer destination").selectOption("win32");
      assert.equal(await page.getByRole("button", { name: "Authorize IIS binding", exact: true }).isDisabled(), true);
      assert.equal(await page.getByRole("button", { name: "Request real IIS deployment", exact: true }).isDisabled(), true);
      assert.deepEqual(errors, []);
      report.passed++; await context.close();
    }
    fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify(report, null, 2));
    console.log(JSON.stringify(report));
  } finally {
    await browser?.close(); await server?.close();
    if (!path.resolve(directory).startsWith(scratch + path.sep)) throw new Error("Unsafe browser fixture cleanup target");
    fs.rmSync(directory, { recursive: true, force: true });
  }
}
if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
