'use strict';
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const infra = path.resolve(__dirname, '../infra/certops-adcs');
const guard = path.join(infra, 'store-noiis-prepare-guard.ps1');
const files = ['provision-lab.ps1', 'store-noiis-prepare-guard.ps1', 'store-noiis-clean-member.ps1', 'store-noiis-registration.ps1'];
const uuid = '11111111-1111-1111-1111-111111111111';
const provision = '22222222-2222-2222-2222-222222222222';
const cleanup = '33333333-3333-3333-3333-333333333333';
const env = {
  GITHUB_ACTIONS: 'true',
  GITHUB_REPOSITORY: 'tokentimerch/tokentimer-core',
  GITHUB_WORKFLOW_REF: 'tokentimerch/tokentimer-core/.github/workflows/certops-adcs-store-noiis-prepare.yml@refs/heads/main',
  GITHUB_REF: 'refs/heads/main',
  GITHUB_EVENT_NAME: 'workflow_dispatch',
  GITHUB_SHA: 'a'.repeat(40),
  GITHUB_RUN_ID: '1234',
  GITHUB_RUN_ATTEMPT: '2',
  AZURE_SUBSCRIPTION_ID: uuid,
  AZURE_CLIENT_ID: provision,
};
const sha256 = (text) => createHash('sha256').update(text).digest('hex');
const fixtureRoot = process.env.TT_STORE_TEST_TEMP_ROOT ?? os.tmpdir();
const ps = (text, values = {}, cwd) => {
  const setup = cwd ? "Set-Location -LiteralPath $env:TT_FIXTURE_CWD\n" : "";
  // Assert the exception text, which PowerShell's console renderer can truncate.
  const script = `
    $ErrorActionPreference = 'Stop'
    try {
      ${setup}${text}
    } catch {
      [Console]::Error.WriteLine($_.Exception.Message)
      exit 1
    }
  `;
  return spawnSync('pwsh', ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
    Buffer.from(script, 'utf16le').toString('base64')],
  { env: { ...process.env, ...env, ...values, TT_FIXTURE_CWD: cwd }, encoding: 'utf8', timeout: 60000 });
};

function fixture(options = {}) {
  const now = Date.now();
  const receipt = Object.assign({
    schema: 'certops-adcs-store-registration-v1',
    resourceGroup: 'tt-certops-1234-2',
    subscriptionSha256: sha256(uuid),
    location: 'swedencentral',
    workflowCommit: env.GITHUB_SHA,
    runId: '1234',
    runAttempt: '2',
    mediaSourceCommit: 'b'.repeat(40),
    mediaReceiptSha256: 'c'.repeat(64),
    registrationNonce: 'd'.repeat(64),
    createdAt: new Date(now - 120000).toISOString(),
    expiresAt: new Date(now + (238 * 60000)).toISOString(),
    observedAt: new Date(now - 30000).toISOString(),
    cleanupClientSha256: sha256(cleanup),
    provisionClientSha256: sha256(provision),
    workflowOwnedGroupVerified: true,
    independentExpiryVerified: true,
    janitorRunId: '6789',
    janitorCommit: 'f'.repeat(40),
  }, options.receipt);
  const group = {
    id: '/subscriptions/' + uuid + '/resourceGroups/tt-certops-1234-2',
    name: 'tt-certops-1234-2',
    location: 'swedencentral',
    properties: { provisioningState: 'Succeeded' },
    tags: {
      purpose: 'certops-adcs-qualification',
      candidateSha: env.GITHUB_SHA,
      createdAt: receipt.createdAt,
      expiresAt: receipt.expiresAt,
      storePrepareRun: '1234',
      storePrepareAttempt: '2',
      storePrepareNonce: receipt.registrationNonce,
      ...options.tags,
    },
    ...options.group,
  };
  return { receipt, group, members: options.members ?? [], deployments: options.deployments ?? [] };
}

function removeFixture(directory) {
  const relative = path.relative(fs.realpathSync.native(fixtureRoot), fs.realpathSync.native(directory));
  assert.match(relative, /^tt-store-(?:bootstrap|registration|prepare)-test-[a-zA-Z0-9_-]+$/);
  fs.rmSync(directory, { recursive: true, force: true });
}
function exercise(options = {}) {
  const { receipt, group, members, deployments } = fixture(options);
  const temp = fs.mkdtempSync(path.join(fixtureRoot, 'tt-store-bootstrap-test-'));
  const file = path.join(temp, 'pinned-receipt.json');
  const bytes = JSON.stringify(receipt);
  fs.writeFileSync(file, bytes);
  try {
    const values = {
      TT_GUARD: guard, TT_FILE: file,
      TT_SHA: options.digest ?? createHash('sha256').update(bytes).digest('hex'),
      TT_GROUP: JSON.stringify(group),
      TT_MEMBERS: JSON.stringify(members),
      TT_DEPLOYMENTS: JSON.stringify(deployments),
      ...options.env,
    };
    return ps(String.raw`
      . $env:TT_GUARD
      function az {
        $global:LASTEXITCODE = 0
        switch ("$($args[0]) $($args[1]) $(if($args[0] -eq 'deployment'){$args[2]})".Trim()){
          'account show' { return $env:AZURE_SUBSCRIPTION_ID }
          'group show' { return $env:TT_GROUP }
          'resource list' { return $env:TT_MEMBERS }
          'deployment group list' { return $env:TT_DEPLOYMENTS }
          default { throw "Unexpected Azure call in offline receipt validation" }
        }
      }
      $r = Read-CertOpsStoreRegistration -Path $env:TT_FILE -ExpectedSha256 $env:TT_SHA -ResourceGroup 'tt-certops-1234-2' -Location 'swedencentral'
      Assert-CertOpsStoreRegistrationScope -Registration $r
      Write-Output 'ready-for-provision-only'
    `, values);
  } finally {
    removeFixture(temp);
  }
}

function passed(result) {
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), 'ready-for-provision-only');
}

function refused(options, message) {
  const result = exercise(options);
  assert.ifError(result.error);
  assert.notEqual(result.status, 0, result.stdout);
  assert.match(result.stderr, message);
}

test('all preparation PowerShell sources parse', () => {
  for (const name of files) {
    const result = ps(`
      $tokens = $null
      $errors = $null
      $null = [Management.Automation.Language.Parser]::ParseFile($env:TT_FILE, [ref]$tokens, [ref]$errors)
      if($errors.Count){throw ($errors.Message -join '; ')}
    `, { TT_FILE: path.join(infra, name) });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
  }
});

test('fresh exact independent registration and empty Azure group pass the pre-deployment readback', () => {
  passed(exercise());
});

test('old or foreign workflow, altered digest and different run fail before deployment', () => {
  refused({ env: { GITHUB_WORKFLOW_REF: env.GITHUB_WORKFLOW_REF.replace('/main', '/old') } }, /Protected Store preparation/);
  refused({ digest: 'e'.repeat(64) }, /receipt digest mismatch/);
  refused({ receipt: { runAttempt: '1' } }, /not bound to this exact owned run/);
});

test('requires a distinct cleanup principal and proof of its expiry and workflow ownership', () => {
  refused({ receipt: { cleanupClientSha256: sha256(provision) } }, /independent cleanup/);
  refused({ receipt: { independentExpiryVerified: 'true' } }, /independent cleanup/);
  refused({ receipt: { workflowOwnedGroupVerified: false } }, /independent cleanup/);
});

test('rejects expired, stale and extended registrations', () => {
  refused({ receipt: {
    createdAt: '2026-11-16T11:00:00.000Z', observedAt: '2026-11-16T11:00:01.000Z',
    expiresAt: '2026-11-16T15:00:00.000Z',
  } }, /fresh independent readback/);
  refused({ receipt: { observedAt: new Date(Date.now() - 180000).toISOString() } }, /fresh independent readback/);
  refused({ receipt: { expiresAt: new Date(Date.now() + 5 * 3600000).toISOString() } }, /four-hour lease/);
});

test('rejects a foreign group, modified ownership or deployment/resource preexistence', () => {
  refused({ group: { id: '/subscriptions/foreign/resourceGroups/tt-certops-1234-2' } }, /exact registered/);
  refused({ tags: { storePrepareNonce: 'e'.repeat(64) } }, /owner or expiry changed/);
  refused({ members: ['/foreign/child'] }, /empty before the first deployment/);
  refused({ deployments: ['/foreign/deployment'] }, /empty before the first deployment/);
});

test('Store opt-in cannot reach older templates, app, trust, or service activation', () => {
  const source = fs.readFileSync(path.join(infra, files[0]), 'utf8');
  assert.match(source, /\$StoreNoIisPrepare='0'/);
  assert.match(source, /if\(-not \$storeRegistration\)\{\s*\$existing = az group exists/);
  assert.ok(source.indexOf('Assert-CertOpsStoreRegistrationScope') < source.indexOf('az deployment group create'));
  const start = source.indexOf("  if($storeRegistration){\n    $originalVmId = Read-CertOpsStoreMemberVmId");
  const stop = source.indexOf('\n  $templateStagePath=', start);
  assert.ok(start > 0 && stop > start);
  const prepare = source.slice(start, stop);
  assert.match(prepare, /'IisMode=absent'/);
  assert.match(prepare, /'store-noiis-clean-member\.ps1'/);
  assert.match(prepare, /'store-noiis-infrastructure-prepared'\s+return/);
  assert.doesNotMatch(prepare, /domain-verify|windows-tools|Start-ControlPlane|service|install/i);
  assert.match(source.slice(stop), /Invoke-Stage 'windows-agent'.*'domain-member\.ps1'.*DomainPassword=\$password"\)/);
  const probes = fs.readFileSync(path.join(infra, files[2]), 'utf8');
  assert.match(probes, /20348/);
  assert.match(probes, /S-1-5-18/);
  assert.match(probes, /Get-WindowsFeature -Name Web-Server/);
  assert.match(probes, /Get-CimInstance Win32_Service/);
  assert.match(probes, /certutil\.exe.*-ping/);
  assert.doesNotMatch(probes, /-addstore|Start-Service|Set-Item|Install-WindowsFeature|New-Service/);
});

function simulateRegistration(mode, options = {}) {
  const temp = fs.mkdtempSync(path.join(fixtureRoot, 'tt-store-registration-test-'));
  const { receipt, group } = fixture();
  const { observedAt, cleanupClientSha256, workflowOwnedGroupVerified, independentExpiryVerified, janitorRunId, janitorCommit, ...registered } = receipt;
  const output = path.join(temp, 'outputs.txt');
  const trace = path.join(temp, 'trace.txt');
  for (const file of [files[1], files[3]]) fs.copyFileSync(path.join(infra, file), path.join(temp, file));
  fs.writeFileSync(path.join(temp, 'assert-lab-capacity.ps1'), '');
  fs.writeFileSync(path.join(temp, 'arm-operation.ps1'), String.raw`
      function Invoke-CertOpsArmRequest {
        param($Uri,$Method,$Body,$SubscriptionId,$RefreshAuthentication)
        Add-Content -LiteralPath $env:TT_TRACE -Value 'ARM PUT'
        if($Method -cne 'PUT' -or $Uri.AbsolutePath -cnotmatch '/resourceGroups/tt-certops-1234-2$'){
          throw 'Unexpected ARM request'
        }
        if($env:TT_LOST_REPLY -eq 'true'){throw 'mock lost reply'}
        $body = $Body | ConvertFrom-Json -DateKind String
        if($body.tags.purpose -cne 'certops-adcs-store-registration-pending'){throw 'Cleanup tagged before empty readback'}
        $global:registered.tags = $body.tags
        return @{StatusCode=([int]$env:TT_ARM_STATUS)}
      }
  `);
  try {
    const result = ps(String.raw`
      $ErrorActionPreference='Stop'
      $global:registered = $env:TT_GROUP | ConvertFrom-Json -DateKind String
      function git {
        $global:LASTEXITCODE = 0
        if(($args -join ' ') -cne 'rev-parse HEAD'){throw 'Unexpected git operation'}
        return $env:GITHUB_SHA
      }
      function gh {
        $global:LASTEXITCODE = 0
        switch -Regex ($args[1]){
          '/commits/[a-f0-9]{40}$' {
            return @{sha=($args[1] -split '/')[-1];verified=$true}|ConvertTo-Json -Compress
          }
          '/actions/workflows/certops-adcs-lab-janitor\.yml$' { return $env:TT_JANITOR_STATE }
          '/runs\?' {
            return @{id=6789;head_sha=('f'*40);event='schedule';status='completed';conclusion='success';head_branch='main';
              updated_at=[DateTimeOffset]::UtcNow.AddMinutes(-5).ToString('o')}|ConvertTo-Json -Compress
          }
          default { throw 'Unexpected GitHub operation' }
        }
      }
      function az {
        $global:LASTEXITCODE = 0
        $call = "$($args[0]) $($args[1])"
        Add-Content -LiteralPath $env:TT_TRACE -Value $call
        switch ($call){
          'account show' { return $env:AZURE_SUBSCRIPTION_ID }
          'group exists' { return 'false' }
          'resource list' { return $env:TT_MEMBERS }
          'deployment group' { return '[]' }
          'tag update' { $global:registered.tags.purpose = 'certops-adcs-qualification' }
          'group show' { return $global:registered | ConvertTo-Json -Depth 5 -Compress }
          default { throw 'Unexpected Azure operation' }
        }
      }
      & $env:TT_SCRIPT -Mode $env:TT_MODE
    `, {
      TT_SCRIPT: path.join(temp, files[3]), TT_MODE: mode, TT_TRACE: trace,
      TT_GROUP: JSON.stringify(group), TT_LOST_REPLY: String(options.lost ?? false),
      TT_ARM_STATUS: String(options.armStatus ?? 201), TT_MEMBERS: JSON.stringify(options.members ?? []),
      TT_JANITOR_STATE: options.janitor ?? 'active',
      STORE_GROUP: receipt.resourceGroup, STORE_LOCATION: receipt.location,
      STORE_EXPECTED_SHA: env.GITHUB_SHA, STORE_MEDIA_SOURCE: receipt.mediaSourceCommit,
      STORE_MEDIA_RECEIPT_SHA: receipt.mediaReceiptSha256, STORE_REGISTRATION: JSON.stringify(registered),
      GITHUB_OUTPUT: output, AZURE_CLIENT_ID: mode === 'verify' ? cleanup : provision,
    }, temp);
    return {
      result,
      trace: fs.existsSync(trace) ? fs.readFileSync(trace, 'utf8').trim().split(/\r?\n/) : [],
      output: fs.existsSync(output) ? fs.readFileSync(output, 'utf8').trim().split(/\r?\n/) : [],
    };
  } finally {
    removeFixture(temp);
  }
}

test('provision identity registers only an empty group and fails closed on a lost reply', () => {
  const good = simulateRegistration('register');
  assert.equal(good.result.status, 0, good.result.stderr);
  assert.deepEqual(good.trace, ['account show','group exists','ARM PUT','account show','group show','resource list','deployment group','tag update','group show']);
  const r = JSON.parse(good.output[0].slice('registration='.length));
  assert.equal(Date.parse(r.expiresAt) - Date.parse(r.createdAt), 4 * 3600000);
  assert.match(r.registrationNonce, /^[a-f0-9]{64}$/);
  const lost = simulateRegistration('register', { lost: true });
  assert.notEqual(lost.result.status, 0);
  assert.match(lost.result.stderr, /failed or is uncertain; do not retry/);
  assert.deepEqual(lost.trace, ['account show','group exists','ARM PUT']);
  assert.deepEqual(lost.output, []);
  const collision = simulateRegistration('register', { armStatus: 200 });
  assert.notEqual(collision.result.status, 0);
  assert.match(collision.result.stderr, /not newly created/);
  assert.deepEqual(collision.trace, lost.trace);
  assert.deepEqual(collision.output, []);
  const occupied = simulateRegistration('register', { members: ['/foreign/child'] });
  assert.notEqual(occupied.result.status, 0);
  assert.match(occupied.result.stderr, /empty before the first deployment/);
  assert.doesNotMatch(occupied.trace.join('\n'), /tag update/);
  assert.deepEqual(occupied.output, []);
});

test('independent cleanup identity reads only group expiry and pins the exact receipt', () => {
  const good = simulateRegistration('verify');
  assert.equal(good.result.status, 0, good.result.stderr);
  assert.deepEqual(good.trace, ['account show','group show']);
  const encoded = good.output[0].slice('receipt='.length);
  assert.equal(good.output[1], 'receipt_sha256=' + sha256(encoded));
  const r = JSON.parse(encoded);
  assert.equal(r.cleanupClientSha256, sha256(cleanup));
  assert.equal(r.independentExpiryVerified, true);
  assert.equal(r.janitorRunId, '6789');
  assert.equal(r.janitorCommit, 'f'.repeat(40));
  const disabled = simulateRegistration('verify', { janitor: 'disabled_manually' });
  assert.notEqual(disabled.result.status, 0);
  assert.match(disabled.result.stderr, /janitor is not active/);
  assert.deepEqual(disabled.trace, ['account show']);
  assert.deepEqual(disabled.output, []);
});

test('protected workflow requires independent proof before any VM path and keeps failed cleanup separate', () => {
  const wf = fs.readFileSync(path.join(__dirname,
    '../.github/workflows/certops-adcs-store-noiis-prepare.yml'), 'utf8');
  const [, register, verify, prepare, cleanup] = wf.split(/\n  (?:register|verify|prepare|cleanup-failed):\n/);
  assert.match(register, /github\.ref == 'refs\/heads\/main'/);
  assert.match(register, /environment: certops-adcs-lab/);
  assert.match(register, /store-noiis-registration\.ps1 -Mode register/);
  assert.doesNotMatch(register, /provision-lab\.ps1/);
  assert.match(verify, /needs: register/);
  assert.match(verify, /environment: certops-adcs-cleanup/);
  assert.match(verify, /store-noiis-registration\.ps1 -Mode verify/);
  assert.doesNotMatch(verify, /provision-lab\.ps1/);
  assert.match(prepare, /needs: \[register, verify\]/);
  assert.match(prepare, /needs\.verify\.outputs\.receipt_sha256/);
  assert.match(prepare, /provision-lab\.ps1 .* -Hours 4 -WindowsVersion 2022 .* -StoreNoIisPrepare 1/);
  assert.match(cleanup, /if: always\(\) && needs\.verify\.result == 'success' && needs\.prepare\.result != 'success' && needs\.prepare\.outputs\.cleanup_activation != ''/);
  assert.match(cleanup, /path: qualification-results\/enterprise-adcs-cleanup\.json/);
  assert.match(verify, /qualification-results\/store-noiis-registration\.sha256/);
  assert.match(cleanup, /environment: certops-adcs-cleanup/);
  assert.match(cleanup, /store-noiis-registration\.ps1 -Mode remove/);
});

function simulatePreparation(preexistingDeployment, replaceMember = false) {
  const temp = fs.mkdtempSync(path.join(fixtureRoot, 'tt-store-prepare-test-'));
  const { receipt, group } = fixture();
  const file = path.join(temp, 'registration.json');
  const trace = path.join(temp, 'trace.txt');
  const output = path.join(temp, 'activation.txt');
  const memberId = '44444444-4444-4444-4444-444444444444';
  const guest = JSON.stringify({scope:'store-noiis-clean-member-readiness',windowsBuild:'20348',architecture:'x64',
    localSystem:true,ownedDomain:true,iisAbsent:true,agentServiceAbsent:true,caRpcPing:true});
  const vm = {id:group.id + '/providers/Microsoft.Compute/virtualMachines/windows-agent',
    vmId:memberId,provisioningState:'Succeeded',tags:group.tags};
  const repoFiles = [files[0], files[1]];
  for (const name of repoFiles) fs.copyFileSync(path.join(infra, name), path.join(temp, name));
  for (const stub of ['assert-lab-capacity.ps1','report-error.ps1','login-oidc.ps1']) {
    fs.writeFileSync(path.join(temp, stub), '');
  }
  const stages = {
    'domain-forest.ps1': 'CERTOPS_STAGE=forest-created-reboot-required',
    'domain-ca.ps1': 'CERTOPS_STAGE=enterprise-ca-service-running',
    'domain-member.ps1': 'CERTOPS_STAGE=member-joined-reboot-required',
    'store-noiis-clean-member.ps1': 'CERTOPS_STAGE=store-noiis-clean-member-ready',
  };
  for (const [name, marker] of Object.entries(stages)) fs.writeFileSync(path.join(temp, name), marker);
  fs.writeFileSync(path.join(temp, 'arm-operation.ps1'), String.raw`
    function Invoke-CertOpsArmOperation {
      param($Uri,$Method,$Body,$SubscriptionId,$RefreshAuthentication,$TimeoutSeconds)
      if($Uri -notmatch '/(?:restart\?|runCommands/ttready[a-f0-9]+\?)'){throw 'Unexpected ARM operation'}
      if($SubscriptionId -ne $env:AZURE_SUBSCRIPTION_ID){throw 'Unexpected subscription'}
      return $null
    }
    function Invoke-CertOpsVmRunCommand {
      param($SubscriptionId,$ResourceGroup,$Machine,$Script,$Parameters,$TimeoutSeconds,$RefreshAuthentication)
      if($SubscriptionId -ne $env:AZURE_SUBSCRIPTION_ID -or $ResourceGroup -ne 'tt-certops-1234-2'){
        throw 'Unexpected owned run scope'
      }
      if($Script -ceq 'CERTOPS_STAGE=member-joined-reboot-required' -and 'IisMode=absent' -cnotin $Parameters){
        throw 'No-IIS selector absent'
      }
      if($Script -cnotin @('CERTOPS_STAGE=forest-created-reboot-required','CERTOPS_STAGE=enterprise-ca-service-running',
        'CERTOPS_STAGE=member-joined-reboot-required','CERTOPS_STAGE=store-noiis-clean-member-ready')){
        throw 'Unexpected guest write or service activation'
      }
      Add-Content -LiteralPath $env:TT_TRACE -Value $Script
      if($Script -ceq 'CERTOPS_STAGE=store-noiis-clean-member-ready'){
        return @{value=@(@{message=$Script},@{message=('CERTOPS_STORE_NOIIS_RECEIPT=' + $env:TT_GUEST)})}
      }
      return @{value=@(@{message=$Script})}
    }
  `);
  const bytes = JSON.stringify(receipt);
  fs.writeFileSync(file, bytes);
  try {
    const result = ps(String.raw`
      $global:memberReads = 0
      function az {
        $global:LASTEXITCODE = 0
        $call = "$($args[0]) $($args[1]) $(if($args[0] -eq 'deployment'){$args[2]})".Trim()
        Add-Content -LiteralPath $env:TT_TRACE -Value $call
        switch ($call){
          'account show' { return $env:AZURE_SUBSCRIPTION_ID }
          'group show' { return $env:TT_GROUP }
          'resource list' { return '[]' }
          'deployment group list' { return $env:TT_DEPLOYMENTS }
          'deployment group create' {
            $i=[array]::IndexOf($args,'--subscription')
            if($i -lt 0 -or $args[$i+1] -cne $env:AZURE_SUBSCRIPTION_ID){throw 'No pinned subscription'}
          }
          'deployment group show' { return 'Succeeded' }
          'vm get-instance-view' { return 'ProvisioningState/succeeded' }
          'vm show' {
            $global:memberReads++
            $record = $env:TT_VM | ConvertFrom-Json -DateKind String
            if($global:memberReads -eq 2 -and $env:TT_REPLACE_VM -eq 'true'){$record.vmId='66666666-6666-6666-6666-666666666666'}
            return $record | ConvertTo-Json -Depth 5 -Compress
          }
          default { throw 'Unexpected Azure call in preparation' }
        }
      }
      & $env:TT_PROVISION -ResourceGroup 'tt-certops-1234-2' -Location 'swedencentral' -StoreNoIisPrepare 1 -StoreRegistrationReceipt $env:TT_FILE -StoreRegistrationSha256 $env:TT_DIGEST
    `, {
      RUNNER_TEMP: temp, TT_PROVISION: path.join(temp, files[0]), TT_TRACE: trace, TT_FILE: file,
      TT_DIGEST: sha256(bytes), TT_GROUP: JSON.stringify(group), GITHUB_OUTPUT: output,
      TT_VM: JSON.stringify(vm), TT_REPLACE_VM: String(replaceMember), TT_GUEST: Buffer.from(guest).toString('base64'),
      TT_DEPLOYMENTS: preexistingDeployment ? '["prior-deployment"]' : '[]',
    }, temp);
    const report = path.join(temp, 'qualification-results', 'store-noiis-infrastructure.json');
    const traceLines = fs.existsSync(trace) ? fs.readFileSync(trace, 'utf8').trim().split(/\r?\n/) : [];
    const activation = fs.existsSync(output) ? fs.readFileSync(output, 'utf8').trim() : null;
    return { result, trace: traceLines, activation, memberId, guest, report: fs.existsSync(report) ? JSON.parse(fs.readFileSync(report, 'utf8')) : null };
  } finally {
    removeFixture(temp);
  }
}

test('mocked prepare-only flow works without a collector and never stages or starts the agent', () => {
  const { result, trace, report, activation, memberId, guest } = simulatePreparation(false);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(trace.slice(0, 5), ['account show','group show','resource list','deployment group list','deployment group create']);
  assert.deepEqual(trace.slice(-2), ['CERTOPS_STAGE=store-noiis-clean-member-ready','vm show']);
  assert.equal(trace.filter(entry => entry === 'vm show').length, 2);
  assert.equal(activation, 'cleanup_activation=' + report.registrationSha256);
  assert.equal(report.memberVmId, memberId);
  assert.equal(report.memberReadinessSha256, sha256(guest));
  assert.equal(report.status, 'store-noiis-infrastructure-prepared');
  assert.equal(report.qualificationPassed, false);
  assert.equal(report.agentInstalledByPreparation, false);
});

test('uncertain prior resource reconciliation stops actual provision entry before Bicep or guest activity', () => {
  const { result, trace, report, activation } = simulatePreparation(true);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /empty before the first deployment/);
  assert.deepEqual(trace, ['account show','group show','resource list','deployment group list']);
  assert.equal(activation, null);
  assert.equal(report.status, 'failed');
  assert.equal(report.qualificationPassed, false);
});

test('replaced immutable VM identity cannot yield a guest preparation receipt', () => {
  const { result, report } = simulatePreparation(false, true);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /replaced during guest readiness/);
  assert.equal(report.status, 'failed');
  assert.equal(report.memberReadinessSha256, null);
});
