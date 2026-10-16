<#
Read the native IIS endpoint installed by the isolated Online Responder role.
Import defines functions only. This deliberately does not create handlers,
adopt an existing site or serve an arbitrary directory. The caller persists
the exact returned private tuple before later service/worker cleanup.
#>
function Initialize-OwnedOcspIisApi {
 $assembly=Join-Path $env:SystemRoot 'System32\inetsrv\Microsoft.Web.Administration.dll'
 $file=Get-Item -LiteralPath $assembly -Force -ErrorAction Stop
 if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
  throw 'Original native IIS administration assembly required'
 }
 [void][Reflection.Assembly]::LoadFrom($assembly)
}

function Assert-OcspNativePhysicalPath([string]$Path) {
 if(!$Path -or $Path.Length -gt 4096 -or $Path -match '[\x00-\x1f\x7f]') {
  throw 'Bounded native responder physical path required'
 }
 $resolved=[Environment]::ExpandEnvironmentVariables($Path)
 if(![IO.Path]::IsPathRooted($resolved) -or $resolved.StartsWith('\\')) {
  throw 'Local native responder physical path required'
 }
 $full=[IO.Path]::GetFullPath($resolved)
 if($full -ine $resolved) { throw 'Canonical native responder physical path required' }
 $allowed=[IO.Path]::GetFullPath($env:SystemRoot).TrimEnd('\')+'\'
 if(!$full.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)) {
  throw 'Responder content must remain under the original Windows role namespace'
 }
 $current=$full
 while($current.Length -ge $allowed.TrimEnd('\').Length) {
  $entry=Get-Item -LiteralPath $current -Force -ErrorAction Stop
  if(!$entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
   throw 'Native responder directory alias refused'
  }
  if($current.TrimEnd('\') -ieq $allowed.TrimEnd('\')) { break }
  $current=[IO.Path]::GetDirectoryName($current.TrimEnd('\'))
 }
 return $full
}

function Get-OwnedOcspIisSnapshot($Owner) {
 Assert-OwnedOcspDirectory $Owner
 if($Owner.ownership.baseline.iisInitiallyAbsent -ne $true -or
    $Owner.ownership.baseline.httpPortInitiallyUnbound -ne $true) {
  throw 'Original absent IIS and unbound endpoint required'
 }
 Initialize-OwnedOcspIisApi
 $manager=[Microsoft.Web.Administration.ServerManager]::new()
 try {
  $sites=@($manager.Sites)
  if($sites.Count -ne 1) { throw 'Exactly one freshly installed native IIS site required' }
  $site=$sites[0]
  if($site.Name -cne 'Default Web Site' -or $site.Id -le 0 -or !$site.ServerAutoStart) {
   throw 'Fresh native responder site identity mismatch'
  }
  $bindings=@($site.Bindings)
  if($bindings.Count -ne 1 -or $bindings[0].Protocol -cne 'http' -or
     $bindings[0].BindingInformation -cne '*:80:') {
   throw 'Fresh native responder HTTP binding mismatch'
  }
  $routes=@()
  foreach($application in $site.Applications) {
   if($application.Path -cnotin @('/','/ocsp')) {
    throw 'Unexpected application on fresh responder site'
   }
   foreach($directory in $application.VirtualDirectories) {
    $route=$application.Path.TrimEnd('/')+$directory.Path
    if($route -ceq '/ocsp') {
     $physical=Assert-OcspNativePhysicalPath $directory.PhysicalPath
     $routes+=@{
      applicationPath=[string]$application.Path
      virtualDirectoryPath=[string]$directory.Path
      applicationPool=[string]$application.ApplicationPoolName
      physicalPath=$physical
      physicalDirectoryIdentity=[TTQualificationOcspReceipt]::DirectoryIdentity($physical)
     }
    } elseif($route -cne '/') {
     throw 'Unexpected virtual directory on fresh responder site'
    }
   }
  }
  if($routes.Count -ne 1 -or !$routes[0].applicationPool -or
     $routes[0].applicationPool.Length -gt 128) {
   throw 'Exactly one native Online Responder route and pool required'
  }
  $pool=@($manager.ApplicationPools | Where-Object Name -CEQ $routes[0].applicationPool)
  if($pool.Count -ne 1) { throw 'Exact native responder application pool required' }
  return @{
   siteName=[string]$site.Name;siteId=[long]$site.Id
   protocol='http';bindingInformation='*:80:'
   applicationPath=$routes[0].applicationPath
   virtualDirectoryPath=$routes[0].virtualDirectoryPath
   applicationPool=$routes[0].applicationPool
   physicalPath=$routes[0].physicalPath
   physicalDirectoryIdentity=$routes[0].physicalDirectoryIdentity
  }
 } finally { $manager.Dispose() }
}

function Stop-OwnedOcspIis($Owner,$OriginalSnapshot) {
 Assert-OwnedOcspDirectory $Owner
 if($Owner.ownership.baseline.installedFeatures -contains 'WAS' -or
    $Owner.ownership.baseline.installedFeatures -contains 'Web-Server') {
  throw 'Never stop an originally installed IIS activation dependency'
 }
 $actual=Get-OwnedOcspIisSnapshot $Owner
 foreach($name in @('siteName','siteId','protocol','bindingInformation','applicationPath','virtualDirectoryPath','applicationPool','physicalPath','physicalDirectoryIdentity')) {
  if($actual[$name] -cne $OriginalSnapshot.$name) {
   throw 'Original native responder IIS tuple changed before stop'
  }
 }
 if(!('RetainedFixtureProcess' -as [type]) -or !$script:OcspWaitSourceHash) {
  throw 'Candidate-bound native retained process waiter required'
 }
 $manager=[Microsoft.Web.Administration.ServerManager]::new()
 $handles=@()
 try {
  $workers=@($manager.WorkerProcesses)
  if($workers.Count -gt 1) { throw 'Unexpected concurrent IIS workers on fresh responder' }
  $all=@(Get-CimInstance Win32_Process -Filter "Name='w3wp.exe'" -ErrorAction Stop)
  if($all.Count -ne $workers.Count) { throw 'Unattributed native IIS worker prevents stop' }
  foreach($worker in $workers) {
   if($worker.AppPoolName -cne $actual.applicationPool) {
    throw 'Foreign application pool worker cannot be stopped'
   }
   $rows=@($all | Where-Object ProcessId -EQ $worker.ProcessId)
   if($rows.Count -ne 1 -or !$rows[0].CreationDate) {
    throw 'Exact native worker process identity required'
   }
   $process=$rows[0]
   $expectedImage=Join-Path $env:SystemRoot 'System32\inetsrv\w3wp.exe'
   if($process.ExecutablePath -ine $expectedImage) { throw 'Original IIS worker image required' }
   $ownerSid=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop
   if($ownerSid.ReturnValue -ne 0 -or !$ownerSid.Sid) { throw 'Actual IIS worker token required' }
   $handle=[RetainedFixtureProcess]::new([uint32]$process.ProcessId)
   $handles+=@{handle=$handle;pid=[uint32]$process.ProcessId}
   $created=$process.CreationDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.ffffffZ',[Globalization.CultureInfo]::InvariantCulture)
   if($handle.Exited -or $handle.CreatedMicroseconds -cne $created -or
      $handle.Image -ine $expectedImage -or $handle.Sid -cne $ownerSid.Sid) {
    throw 'Retained IIS worker identity mismatch'
   }
   $fresh=@(Get-CimInstance Win32_Process -Filter ('ProcessId='+[uint32]$process.ProcessId) -ErrorAction Stop)
   if($fresh.Count -ne 1 -or $fresh[0].CreationDate -ne $process.CreationDate -or
      $fresh[0].ParentProcessId -ne $process.ParentProcessId -or
      $fresh[0].CommandLine -cne $process.CommandLine) {
    throw 'IIS worker changed during retained handle capture'
   }
  }
  # Initial admission proved IIS/WAS and the HTTP endpoint absent. Only this
  # role's new services are stopped; shared svchost processes are never killed
  # or assumed to exit. Every actual worker is independently handle-drained.
  Stop-Service -Name W3SVC -ErrorAction Stop
  Stop-Service -Name WAS -ErrorAction Stop
  foreach($entry in $handles) { $entry.handle.Wait() }
  foreach($entry in $handles) {
   if(!$entry.handle.Exited) { throw 'Exact retained IIS worker did not exit' }
  }
  $remaining=@(Get-CimInstance Win32_Process -Filter "Name='w3wp.exe'" -ErrorAction Stop)
  if($remaining.Count -ne 0) { throw 'Unexpected native IIS worker remains' }
  foreach($name in @('W3SVC','WAS')) {
   $service=@(Get-CimInstance Win32_Service -Filter ("Name='"+$name+"'") -ErrorAction Stop)
   if($service.Count -ne 1 -or $service[0].State -cne 'Stopped') {
    throw 'Owned native IIS service stop unproven'
   }
   Set-Service -Name $name -StartupType Disabled -ErrorAction Stop
   $disabled=@(Get-CimInstance Win32_Service -Filter ("Name='"+$name+"'") -ErrorAction Stop)
   if($disabled.Count -ne 1 -or $disabled[0].State -cne 'Stopped' -or
      $disabled[0].StartMode -cne 'Disabled') {
    throw 'Owned native IIS disable readback failed'
   }
  }
  $deadline=[Diagnostics.Stopwatch]::StartNew()
  do {
   $listeners=@(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object LocalPort -EQ 80)
   if($listeners.Count -eq 0) { break }
   if($deadline.Elapsed.TotalSeconds -ge 30) { throw 'Owned HTTP endpoint remains listening' }
   Start-Sleep -Milliseconds 100
  } while($true)
  return @{
   actualWorkersDrained=$true;ownedIisServicesStopped=$true
   sharedServiceHostTerminationQualified=$false;nativeHttpEndpointAbsent=$true
  }
 } finally {
  foreach($entry in $handles) { $entry.handle.Dispose() }
  $manager.Dispose()
 }
}
