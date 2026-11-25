$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:TT_STOCK_RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:GITHUB_REPOSITORY -ne 'tokentimerch/tokentimer-core' -or
    $env:GITHUB_REF -ne 'refs/heads/feat/certops-stock-cng-calibration') {
    throw 'Use the dedicated GitHub-hosted stock diagnostic only.'
}
$runtime = Get-CimInstance Win32_OperatingSystem
if ($runtime.BuildNumber -ne '20348' -or $runtime.ProductType -ne 3) { throw 'Windows Server 2022 required.' }
$nonce = [guid]::NewGuid().ToString('N')
$runnerTemp = (Resolve-Path -LiteralPath $env:RUNNER_TEMP).Path
if ((Get-Item -LiteralPath $runnerTemp -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw 'Unexpected runner temporary directory.'
}
$folder = Join-Path $runnerTemp "tt-stock-cng-$nonce"
if (Test-Path -LiteralPath $folder) { throw 'Disposable scratch already exists.' }
$null = New-Item -ItemType Directory -Path $folder
$taskName = "TokenTimer-stock-cng-$nonce"
$installedTask = $false
$receipt = $null
$taskResult = $null
try {
    $worker = Join-Path $folder 'worker.ps1'
    $result = Join-Path $folder 'receipt.json'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'certops-stock-cng-calibration-worker.ps1') -Destination $worker
    $deadline = [datetimeoffset]::UtcNow.AddMinutes(4).ToString('o')
    $powershell = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $arguments = '-NoLogo -NoProfile -NonInteractive -File "{0}" -RunNonce {1} -ResultPath "{2}" -ExpiresUtc {3}' -f $worker,$nonce,$result,$deadline
    $action = New-ScheduledTaskAction -Execute $powershell -Argument $arguments
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([timespan]::FromMinutes(2))
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw 'Task already exists.' }
    $null = Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings
    $installedTask = $true
    Start-ScheduledTask -TaskName $taskName
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($clock.Elapsed.TotalSeconds -lt 105) {
        $current = Get-ScheduledTask -TaskName $taskName
        if ($current.State -notin @('Running','Queued') -and (Test-Path -LiteralPath $result -PathType Leaf)) {
            $taskResult = (Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if ($null -eq $taskResult -or (Get-Item -LiteralPath $result).Length -gt 24576) { throw 'No bounded stock task receipt.' }
    $receipt = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
    if ($receipt.scope -cne 'github-hosted-stock-cng-disposable-key-control' -or $receipt.run -cne $nonce -or
        $receipt.nativeAdmission -ne $false) { throw 'Stock receipt does not bind this optional diagnostic.' }
} finally {
    try {
        if ($installedTask) {
            $active = Get-ScheduledTask -TaskName $taskName
            if ($active.State -in @('Running','Queued')) { Stop-ScheduledTask -TaskName $taskName }
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw 'Owned stock task still exists.' }
        }
    } finally {
        $resolved = (Resolve-Path -LiteralPath $folder).Path
        if ($resolved -ine $folder -or !$resolved.StartsWith($runnerTemp+'\tt-stock-cng-', [StringComparison]::OrdinalIgnoreCase) -or
            ((Get-Item -LiteralPath $folder -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Unexpected disposable scratch.'
        }
        foreach ($entry in Get-ChildItem -LiteralPath $folder -Force) {
            if ($entry.Name -notin @('worker.ps1','receipt.json') -or $entry.PSIsContainer -or
                ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unexpected stock scratch file.' }
            Remove-Item -LiteralPath $entry.FullName -Force
        }
        Remove-Item -LiteralPath $folder
    }
}
$reportPath = Join-Path $env:GITHUB_WORKSPACE 'qualification-results'
$null = New-Item -ItemType Directory -Path $reportPath -Force
$receipt | Add-Member -NotePropertyName taskResult -NotePropertyValue $taskResult
$receipt | Add-Member -NotePropertyName taskAndScratchRemoved -NotePropertyValue $true
$report = $receipt | ConvertTo-Json -Depth 8 -Compress
[IO.File]::WriteAllText((Join-Path $reportPath 'stock-cng-calibration.json'),$report,[Text.UTF8Encoding]::new($false))
Write-Output $report
if (!$receipt.nativeDuplicateNteExists -or !$receipt.keyAbsentBefore -or
    !$receipt.keyAbsentAfterCleanup -or !$receipt.originalHandleDeleted) {
    throw 'Stock duplicate and cleanup control did not complete.'
}
