Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$file = Join-Path $PSScriptRoot 'install-agent.ps1'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'installer parser errors' }
foreach ($name in @('Test-DirectSystemCa', 'Get-WindowsServiceBinPath', 'Get-ServiceCommandNodeInfo', 'Get-ServiceNodePath', 'Get-WindowsServiceEnvironmentValues', 'Test-UnsupportedSystemCaOption')) {
    $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)
    if (-not $fn) { throw "missing function $name" }
    Invoke-Expression $fn.Extent.Text
}
foreach ($tc in @(
    @{version='22.14.0'; expected=$false}, @{version='22.15.0'; expected=$true},
    @{version='22.18.0'; expected=$true}, @{version='22.19.0'; expected=$false},
    @{version='23.7.0'; expected=$false}, @{version='23.8.0'; expected=$true},
    @{version='23.99.0'; expected=$true}, @{version='24.0.0'; expected=$true},
    @{version='24.5.0'; expected=$true}, @{version='24.6.0'; expected=$false},
    @{version='25.0.0'; expected=$false}
)) { if ((Test-DirectSystemCa -Existing @() -NodeVersion ([version]$tc.version)) -ne $tc.expected) { throw "version $($tc.version)" } }
foreach ($tc in @(
    @{options=@('NODE_OPTIONS=--trace-warnings'); expected=$true},
    @{options=@('NODE_OPTIONS=--trace-warnings --use-system-ca'); expected=$true},
    @{options=@('NODE_OPTIONS=--require=example'); expected=$true},
    @{options=@('NODE_OPTIONS=--use-openssl-ca'); expected=$false},
    @{options=@('NODE_OPTIONS=--no-use-system-ca'); expected=$false},
    @{options=@('NODE_USE_SYSTEM_CA=0'); expected=$false},
    @{options=@('NODE_OPTIONS=--require=example --use-system-ca'); expected=$false},
    @{options=@('NODE_OPTIONS=--use-system-ca','node_options=--trace-warnings'); expected=$false}
)) { if ((Test-DirectSystemCa -Existing $tc.options -NodeVersion ([version]'22.18.0')) -ne $tc.expected) { throw 'override or mixed option mismatch' } }
$prior = @('OTHER=value','NODE_OPTIONS=--trace-warnings','NODE_EXTRA_CA_CERTS=C:\private.pem')
$envValues = @(Get-WindowsServiceEnvironmentValues -Existing $prior -ConfigDir 'C:\state' -Token '' -NodeVersion ([version]'22.18.0'))
foreach ($p in $prior) { if ($envValues -cnotcontains $p) { throw 'existing environment changed' } }
if (@($envValues | Where-Object { $_ -match '^NODE_OPTIONS=.*--use-system-ca' }).Count) { throw 'flag unexpectedly added to environment' }
$node = 'C:\Program Files\nodejs\node.exe'
foreach ($origin in @('', 'https://api.example.test')) {
    foreach ($direct in @($false,$true)) {
        $cmd = Get-WindowsServiceBinPath -AppDirectory 'C:\Program Files\Agent' -NodeExecutable $node -Architecture AMD64 -PreparedServerUrl $origin -DirectSystemCa:$direct
        $info = Get-ServiceCommandNodeInfo -ServiceCommand $cmd
        if ($info.NodePath -cne $node -or $info.DirectSystemCa -ne $direct -or (Get-ServiceNodePath $cmd) -cne $node) { throw 'command shape mismatch' }
        if ((Test-UnsupportedSystemCaOption -Existing @() -NodeVersion ([version]'22.14.0') -ServiceCommand $cmd) -ne $direct) { throw 'older-runtime gate mismatch' }
        if (Test-UnsupportedSystemCaOption -Existing @() -NodeVersion ([version]'22.15.0') -ServiceCommand $cmd) { throw 'supported runtime refused' }
    }
}
foreach ($cmd in @('C:\host.exe C:\node.exe C:\agent.js', '"C:\host.exe" "C:\node.exe" "C:\agent.js"')) {
    if ((Get-ServiceNodePath $cmd) -cne 'C:\node.exe') { throw 'old command changed' }
}
foreach ($cmd in @('"C:\host.exe" "C:\node.exe" --require=evil "C:\agent.js"', '"C:\host.exe" "C:\node.exe" --use-system-ca "C:\agent.js')) {
    $rejected = $false; try { [void](Get-ServiceNodePath $cmd) } catch { $rejected = $true }
    if (-not $rejected) { throw 'unsupported command accepted' }
}
Write-Output 'PASS pure version, overrides, four SCM forms and old-runtime checks'
