[CmdletBinding(DefaultParameterSetName='Build')]
param(
    [Parameter(Mandatory)][string]$PolicyPath,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$', Options='None')][string]$ExpectedPolicySha256,
    [Parameter(Mandatory,ParameterSetName='Build')][string]$SourceCheckout,
    [Parameter(Mandatory,ParameterSetName='Build')][string]$GoArchive,
    [Parameter(Mandatory,ParameterSetName='Build')][string]$OfflineModuleCache,
    [Parameter(Mandatory,ParameterSetName='Build')][string]$StageParent,
    [Parameter(ParameterSetName='Build')][string]$SourceSigningPolicy,
    [Parameter(Mandatory,ParameterSetName='Validate')][switch]$ValidatePolicy,
    [Parameter(ParameterSetName='Validate')][string]$InspectLauncherPath
)

$ErrorActionPreference = 'Stop'
$sourceCommit = 'cc754f6e86f1c36d2137a06d9b6b2fe864205ac0'
$goVersion = 'go1.26.11'
$goArchiveSha256 = '71ae086f0137e665f855a811cc119152b6a783e0bbc1b906e709f46d80141eb0'
$modulePath = 'packages/agent/reference/verified-extraction'
$expectedModule = 'tokentimer-verified-extraction/cmd/agent-launcher'
$launcherName = 'tokentimer-agent-launcher.exe'
$hashPattern = '^[a-f0-9]{64}$'

function Get-Sha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Read-Policy([string]$Path) {
    $file = Get-Item -LiteralPath $Path -Force
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $file.Length -lt 2 -or $file.Length -gt 16KB) {
        throw 'Launcher policy must be a bounded regular file'
    }
    $bytes = [IO.File]::ReadAllBytes($file.FullName)
    if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant() -cne $ExpectedPolicySha256) {
        throw 'Launcher policy does not match its independently retained digest'
    }
    $document = [Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString($bytes))
    try {
        $keys = @('publisherLeafSha256','upstreamRuntimePublisherLeafSha256','installerSha256',
            'sourceCommit','version','architecture','publisherNotAfterUtc','firstPartyLeaves')
        $fields = @($document.RootElement.EnumerateObject())
        if ($fields.Count -ne $keys.Count -or (Compare-Object $keys @($fields.Name) -CaseSensitive)) {
            throw 'Unexpected launcher policy fields'
        }
        $policy = @{}
        foreach ($key in $keys) {
            if ($key -eq 'firstPartyLeaves') { continue }
            $policy[$key] = $document.RootElement.GetProperty($key).GetString()
        }
        if ($policy.sourceCommit -cne $sourceCommit -or $policy.version -cne '0.20.0' -or $policy.architecture -cne 'amd64' -or
            @(@('publisherLeafSha256','upstreamRuntimePublisherLeafSha256','installerSha256') | Where-Object {
                $policy[$_] -cnotmatch $hashPattern
            }).Count -ne 0) {
            throw 'Policy does not target the exact reviewed amd64 pilot'
        }
        $expectedPaths = @('scripts/install-agent.ps1','src/acme/windows-command.ps1','src/windows-material/connector.ps1')
        $expectedPaths += @(foreach ($arch in @('amd64','arm64')) {
            foreach ($family in @('tokentimer-adcs-chain','tokentimer-adcs-cmc','tokentimer-agent-host','tokentimer-observed-revocation-windows')) {
                "bin/$family-$arch.exe"
            }
        })
        $leaves = @($document.RootElement.GetProperty('firstPartyLeaves').EnumerateObject())
        if ($leaves.Count -ne $expectedPaths.Count -or (Compare-Object $expectedPaths @($leaves.Name) -CaseSensitive) -or
            @($leaves | Where-Object { $_.Value.GetString() -cne $policy.publisherLeafSha256 }).Count -ne 0) {
            throw 'All eleven authored files must match the measured CMS publisher leaf'
        }
        $expiry = [DateTimeOffset]::ParseExact($policy.publisherNotAfterUtc, 'o', [Globalization.CultureInfo]::InvariantCulture)
        if ($expiry.Offset -ne [TimeSpan]::Zero -or $expiry -le [DateTimeOffset]::UtcNow) {
            throw 'Measured publisher leaf is outside its signing window'
        }
        $policy
    } finally {
        $document.Dispose()
    }
}

$policy = Read-Policy $PolicyPath
$trust = [ordered]@{
    trustedPublisherSHA256 = $policy.publisherLeafSha256
    trustedRuntimeSHA256 = $policy.upstreamRuntimePublisherLeafSha256
    qualifiedInstallerSHA256 = $policy.installerSha256
    qualifiedSourceCommit = $policy.sourceCommit
    qualifiedVersion = $policy.version
    qualifiedArchitecture = $policy.architecture
}

function Assert-LauncherImage([string]$Path) {
    $file = Get-Item -LiteralPath $Path -Force
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $file.Length -lt 64 -or $file.Length -gt 32MB) {
        throw 'Launcher must be a bounded regular file'
    }
    $bytes = [IO.File]::ReadAllBytes($file.FullName)
    $pe = [BitConverter]::ToInt32($bytes, 0x3c)
    if ($bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a -or $pe -lt 64 -or
        $pe -gt $bytes.Length - 6 -or [BitConverter]::ToUInt32($bytes, $pe) -ne 0x4550 -or
        [BitConverter]::ToUInt16($bytes, $pe + 4) -ne 0x8664) {
        throw 'Launcher is not an amd64 Windows PE'
    }
    $binaryText = [Text.Encoding]::Latin1.GetString($bytes)
    if (@($trust.Values | Where-Object { !$binaryText.Contains([string]$_, [StringComparison]::Ordinal) }).Count -ne 0) {
        throw 'Reviewed trust tuple was not embedded into the launcher'
    }
}

if ($PSCmdlet.ParameterSetName -eq 'Validate') {
    if ($InspectLauncherPath) { Assert-LauncherImage $InspectLauncherPath }
    $policy
    return
}

$checkout = (Resolve-Path -LiteralPath $SourceCheckout).Path
$archive = (Resolve-Path -LiteralPath $GoArchive).Path
$cache = (Resolve-Path -LiteralPath $OfflineModuleCache).Path
if (!(Test-Path -LiteralPath $cache -PathType Container)) { throw 'The pinned offline Go module cache is unavailable' }

$gitOptions = @('--no-replace-objects','-C',$checkout)
if ($SourceSigningPolicy) {
    $allowedSigners = (Resolve-Path -LiteralPath $SourceSigningPolicy).Path
    $gitOptions += @('-c',"gpg.ssh.allowedSignersFile=$allowedSigners")
}
& git @gitOptions verify-commit $sourceCommit
if ($LASTEXITCODE -ne 0) { throw 'Exact launcher source signature is not verified locally' }
$files = @(git --no-replace-objects -C $checkout ls-tree -r $sourceCommit -- $modulePath)
if ($LASTEXITCODE -ne 0 -or $files.Count -eq 0 -or @($files | Where-Object {
    $_ -cnotmatch '^100644 blob [a-f0-9]{40}\tpackages/agent/reference/verified-extraction/[A-Za-z0-9_./-]+$'
}).Count -ne 0) {
    throw 'Launcher module in the signed tree contains an unexpected path or entry type'
}

$parent = (Resolve-Path -LiteralPath $StageParent).Path
$stage = & (Join-Path $PSScriptRoot 'windows-signing-pilot-stage.ps1') -RunnerTemp $parent
$gitTar = Join-Path $stage 'launcher-source.tar'
$source = Join-Path $stage 'source'
[IO.Directory]::CreateDirectory($source) | Out-Null
& git --no-replace-objects -C $checkout archive --format=tar "--output=$gitTar" $sourceCommit -- $modulePath
if ($LASTEXITCODE -ne 0) { throw 'Could not export exact launcher Git blobs' }
& (Join-Path $env:SystemRoot 'System32/tar.exe') -xf $gitTar -C $source
if ($LASTEXITCODE -ne 0) { throw 'Could not materialize the reviewed launcher blobs' }
foreach ($entry in $files) {
    $metadata, $path = $entry -split "`t", 2
    $blob = ($metadata -split ' ')[-1]
    $bytes = [IO.File]::ReadAllBytes((Join-Path $source $path))
    $header = [Text.Encoding]::ASCII.GetBytes("blob $($bytes.Length)`0")
    $actual = [Convert]::ToHexString([Security.Cryptography.SHA1]::HashData([byte[]]($header + $bytes))).ToLowerInvariant()
    if ($actual -cne $blob) {
        throw 'An exported launcher source file differs from its signed Git blob'
    }
}
$module = Join-Path $source $modulePath
$goSum = Join-Path $module 'go.sum'
$goSumSha256 = Get-Sha256 $goSum
$moduleSums = @(Get-Content -LiteralPath $goSum)
if (@($moduleSums -cmatch '^golang\.org/x/sys v0\.28\.0(?:/go\.mod)? h1:[A-Za-z0-9+/]{43}=$').Count -ne 2) {
    throw 'Signed source lacks the expected Go module checksums'
}

$toolchain = Join-Path $stage 'go.zip'
Copy-Item -LiteralPath $archive -Destination $toolchain
if ((Get-Sha256 $toolchain) -cne $goArchiveSha256) { throw 'Official Windows Go archive digest mismatch' }
[IO.Compression.ZipFile]::ExtractToDirectory($toolchain, $stage)
$go = Join-Path $stage 'go/bin/go.exe'

$proxy = Join-Path $stage 'proxy'
$proxyPath = Join-Path $proxy 'golang.org/x/sys/@v'
[IO.Directory]::CreateDirectory($proxyPath) | Out-Null
foreach ($extension in @('info','mod','zip')) {
    $file = "v0.28.0.$extension"
    Copy-Item -LiteralPath (Join-Path $cache "cache/download/golang.org/x/sys/@v/$file") -Destination $proxyPath
}

function Invoke-OfflineGo([string[]]$Arguments) {
    $info = [Diagnostics.ProcessStartInfo]::new($go)
    $info.WorkingDirectory = $module
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.Environment.Clear()
    foreach ($name in @('SystemRoot','WINDIR')) {
        $info.Environment[$name] = [Environment]::GetEnvironmentVariable($name)
    }
    $info.Environment['TMP'] = $stage
    $info.Environment['TEMP'] = $stage
    $info.Environment['GOTOOLCHAIN'] = 'local'
    $info.Environment['GOENV'] = 'off'
    $info.Environment['GOWORK'] = 'off'
    $info.Environment['GOPROXY'] = ([Uri]::new($proxy)).AbsoluteUri
    $info.Environment['GOSUMDB'] = 'off'
    $info.Environment['GOMODCACHE'] = Join-Path $stage 'go-modules'
    $info.Environment['GOCACHE'] = Join-Path $stage 'go-cache'
    $info.Environment['GOOS'] = 'windows'
    $info.Environment['GOARCH'] = 'amd64'
    $info.Environment['CGO_ENABLED'] = '0'
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::Start($info)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (!$process.WaitForExit(240000)) {
            $process.Kill($true)
            throw 'Offline Go launcher build timed out'
        }
        $null = $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw "Offline Go $($Arguments[0]) failed ($($process.ExitCode))" }
        $stdout.GetAwaiter().GetResult()
    } finally {
        $process.Dispose()
    }
}

if ((Invoke-OfflineGo @('env','GOVERSION')).Trim() -cne $goVersion) { throw 'Wrong Go launcher toolchain version' }
$null = Invoke-OfflineGo @('mod','download','golang.org/x/sys')
$null = Invoke-OfflineGo @('mod','verify')
if ((Get-Sha256 $goSum) -cne $goSumSha256) { throw 'Dependency verification changed the signed Go checksums' }
$flags = ($trust.GetEnumerator() | ForEach-Object { "-X main.$($_.Key)=$($_.Value)" }) -join ' '
$output = Join-Path $stage $launcherName
$null = Invoke-OfflineGo @('build','-mod=readonly','-trimpath','-buildvcs=false','-ldflags',$flags,'-o',$output,'./cmd/agent-launcher')
$build = Invoke-OfflineGo @('version','-m',$output)
if ($build -cnotmatch "(?m)^.+: $([regex]::Escape($goVersion))\r?$" -or
    $build -cnotmatch "(?m)^[ \t]+path\t$([regex]::Escape($expectedModule))\r?$" -or
    $build -cnotmatch '\bGOOS=windows\b' -or $build -cnotmatch '\bGOARCH=amd64\b' -or $build -cnotmatch '\bCGO_ENABLED=0\b') {
    throw 'Offline build differs from the expected launcher module and target'
}
Assert-LauncherImage $output

[ordered]@{
    sourceCommit = $sourceCommit
    launcherModuleTree = (git --no-replace-objects -C $checkout rev-parse "${sourceCommit}:$modulePath")
    version = $policy.version
    architecture = $policy.architecture
    policySha256 = $ExpectedPolicySha256
    unsignedLauncher = $launcherName
    unsignedLauncherSha256 = Get-Sha256 $output
    goVersion = $goVersion
    goArchiveSha256 = $goArchiveSha256
    publisherNotAfterUtc = $policy.publisherNotAfterUtc
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stage 'unsigned-launcher-receipt.json') -Encoding utf8NoBOM
$stage
