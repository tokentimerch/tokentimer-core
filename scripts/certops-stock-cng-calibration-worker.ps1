[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$RunNonce,
    [Parameter(Mandatory)][string]$ResultPath,
    [Parameter(Mandatory)][datetimeoffset]$ExpiresUtc
)
$ErrorActionPreference = 'Stop'
$expires = $ExpiresUtc
$vmId = $null
$physicalFqdn = $env:COMPUTERNAME
$work = (Resolve-Path -LiteralPath $PSScriptRoot).Path
if ((Split-Path -Leaf $work) -cne "tt-stock-cng-$RunNonce" -or
    [IO.Path]::GetFullPath($ResultPath) -ine (Join-Path $work 'receipt.json') -or
    (Test-Path -LiteralPath $ResultPath) -or
    $expires -gt [datetimeoffset]::UtcNow.AddMinutes(5)) {
    throw 'Invalid disposable stock task or receipt binding.'
}
$securityProvider = 'Microsoft-Windows-Security-Auditing'
$securityProviderGuid = [guid]'54849625-5478-4994-a5ba-3e3b0328c30d'
$systemIntegrity = [guid]'0cce9212-69ae-11d9-bed3-505054503030'
$systemCategory = [guid]'69979848-797a-11d9-bed3-505054503030'
$softwareKsp = 'Microsoft Software Key Storage Provider'
$nteExists = [Convert]::ToUInt32('8009000f', 16)
$nteBadKeyset = [Convert]::ToUInt32('80090016', 16)

function Assert-Stock5061Member([string]$Nonce) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        if (![Environment]::Is64BitProcess -or $identity.User.Value -cne 'S-1-5-18' -or
            $Nonce -cnotmatch '^[a-f0-9]{32}$' -or [datetimeoffset]::UtcNow.AddSeconds(45) -ge $expires) {
            throw 'Expected an x64 LocalSystem stock task within its lease.'
        }
    } finally { $identity.Dispose() }
    $computer = Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 10
    $os = Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 10
    if ($computer.DNSHostName -ine $physicalFqdn -or $computer.PartOfDomain -or
        $computer.DomainRole -ne 2 -or $os.BuildNumber -ne '20348' -or $os.ProductType -ne 3 -or
        @(Get-Service -Name 'TokenTimer*' -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'Expected stock Windows Server 2022 without an installed agent.'
    }
}
function Initialize-Stock5061Native {
    if ('TokenTimerLab.StockSecurity5061Native' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
namespace TokenTimerLab {
    public static class StockSecurity5061Native {
        [DllImport("kernel32.dll", ExactSpelling = true)]
        public static extern void GetSystemTimePreciseAsFileTime(out long fileTime);
    }
}
'@
}

function Get-Stock5061Utc {
    $fileTime = [long]0
    [TokenTimerLab.StockSecurity5061Native]::GetSystemTimePreciseAsFileTime([ref]$fileTime)
    return [datetimeoffset]::new([datetime]::FromFileTimeUtc($fileTime))
}

function Assert-Stock5061Unimpersonated {
    $impersonating = [Security.Principal.WindowsIdentity]::GetCurrent($true)
    if ($null -ne $impersonating) {
        $impersonating.Dispose()
        throw 'Expected the original process token without thread impersonation.'
    }
}

function Initialize-Stock5061AuditEnumeration {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
namespace TokenTimerLab {
    public static class Stock5061AuditEnumeration {
        private const uint MaxEnumeratedUsers = 128;

        [StructLayout(LayoutKind.Sequential)]
        private struct PolicyAuditSidArray {
            public uint Count;
            public IntPtr Sids;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct AuditPolicyInformation {
            public Guid Subcategory;
            public uint Flags;
            public Guid Category;
        }

        public sealed class EnumerationReadback {
            public bool Succeeded;
            public int Win32Error;
            public bool? CurrentSidPresent;
        }

        public sealed class SystemReadback {
            public bool Succeeded;
            public int Win32Error;
            public uint? Flags;
        }

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool AuditEnumeratePerUserPolicy(out IntPtr entry);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool AuditQuerySystemPolicy(ref Guid subcategory, uint count, out IntPtr entry);

        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern void AuditFree(IntPtr entry);

        public static bool? DecodeSidArray(IntPtr entry, SecurityIdentifier target) {
            if (entry == IntPtr.Zero || target == null) return null;
            var layout = typeof(PolicyAuditSidArray);
            if (IntPtr.Size != 8 || Marshal.SizeOf(layout) != 16 ||
                Marshal.OffsetOf(layout, "Count").ToInt32() != 0 || Marshal.OffsetOf(layout, "Sids").ToInt32() != 8)
                throw new InvalidOperationException("Unexpected SDK SID array layout");
            var row = (PolicyAuditSidArray)Marshal.PtrToStructure(entry, layout);
            if (row.Count > MaxEnumeratedUsers || (row.Count != 0 && row.Sids == IntPtr.Zero)) return null;
            var seen = new HashSet<SecurityIdentifier>();
            bool matched = false;
            for (int i = 0; i < row.Count; i++) {
                IntPtr sidPointer = Marshal.ReadIntPtr(row.Sids, checked(i * IntPtr.Size));
                if (sidPointer == IntPtr.Zero) return null;
                SecurityIdentifier sid;
                try { sid = new SecurityIdentifier(sidPointer); }
                catch (ArgumentException) { return null; }
                if (!seen.Add(sid)) return null;
                if (target.Equals(sid)) matched = true;
            }
            return matched;
        }

        public static uint? DecodeSystemRecord(IntPtr entry, Guid subcategory, Guid category) {
            if (entry == IntPtr.Zero) return null;
            var layout = typeof(AuditPolicyInformation);
            if (Marshal.SizeOf(layout) != 36 || Marshal.OffsetOf(layout, "Subcategory").ToInt32() != 0 ||
                Marshal.OffsetOf(layout, "Flags").ToInt32() != 16 || Marshal.OffsetOf(layout, "Category").ToInt32() != 20)
                throw new InvalidOperationException("Unexpected SDK audit record layout");
            var row = (AuditPolicyInformation)Marshal.PtrToStructure(entry, layout);
            if (row.Subcategory != subcategory || row.Category != category || row.Flags > 4) return null;
            return row.Flags;
        }

        public static EnumerationReadback Enumerate(SecurityIdentifier target) {
            IntPtr entry = IntPtr.Zero;
            bool succeeded = AuditEnumeratePerUserPolicy(out entry);
            int error = succeeded ? 0 : Marshal.GetLastWin32Error();
            try {
                var output = new EnumerationReadback { Succeeded = succeeded, Win32Error = error };
                if (succeeded) output.CurrentSidPresent = DecodeSidArray(entry, target);
                return output;
            } finally {
                if (succeeded && entry != IntPtr.Zero) AuditFree(entry);
            }
        }

        public static SystemReadback ReadSystem(Guid subcategory, Guid category) {
            IntPtr entry = IntPtr.Zero;
            bool succeeded = AuditQuerySystemPolicy(ref subcategory, 1, out entry);
            int error = succeeded ? 0 : Marshal.GetLastWin32Error();
            try {
                var output = new SystemReadback { Succeeded = succeeded, Win32Error = error };
                if (succeeded) output.Flags = DecodeSystemRecord(entry, subcategory, category);
                return output;
            } finally {
                if (succeeded && entry != IntPtr.Zero) AuditFree(entry);
            }
        }
    }
}
'@
}

function Test-Stock5061EnumerationAndSystem($Enumeration, $Before, $After, [bool]$SecurityEnabled) {
    return $SecurityEnabled -and $Enumeration.Succeeded -and $Enumeration.Win32Error -eq 0 -and
        $null -ne $Enumeration.CurrentSidPresent -and !$Enumeration.CurrentSidPresent -and
        $Before.Succeeded -and $Before.Win32Error -eq 0 -and $Before.Flags -eq 3 -and
        $After.Succeeded -and $After.Win32Error -eq 0 -and $After.Flags -eq 3
}

function Get-Stock5061Audit([Security.Principal.WindowsIdentity]$Identity) {
    Assert-Stock5061Unimpersonated
    if ($null -eq $Identity -or $Identity.User.Value -cne 'S-1-5-18') { throw 'The audit reads require the retained LocalSystem process token.' }
    $before = [TokenTimerLab.Stock5061AuditEnumeration]::ReadSystem($systemIntegrity, $systemCategory)
    $enumeration = [TokenTimerLab.Stock5061AuditEnumeration]::Enumerate($Identity.User)
    $after = [TokenTimerLab.Stock5061AuditEnumeration]::ReadSystem($systemIntegrity, $systemCategory)
    Assert-Stock5061Unimpersonated
    $securityEnabled = [bool](Get-WinEvent -ListLog Security -ErrorAction Stop).IsEnabled
    if (!(Test-Stock5061EnumerationAndSystem $enumeration $before $after $securityEnabled)) {
        throw 'Exact bounded enumeration and paired System Integrity mask 3 are required.'
    }
    return [int]$after.Flags
}

function Get-Stock5061RecordFloor {
    $query = [Diagnostics.Eventing.Reader.EventLogQuery]::new('Security', [Diagnostics.Eventing.Reader.PathType]::LogName)
    $query.ReverseDirection = $true
    $reader = [Diagnostics.Eventing.Reader.EventLogReader]::new($query)
    try {
        $entry = $reader.ReadEvent([timespan]::FromSeconds(2))
        if ($null -eq $entry) { throw 'Cannot read a pre-canary Security record floor.' }
        try {
            if ($entry.MachineName -ine $physicalFqdn -or $entry.RecordId -le 0) { throw 'Pre-canary Security source identity differs.' }
            return [long]$entry.RecordId
        } finally { $entry.Dispose() }
    } finally { $reader.Dispose() }
}

function Test-Stock5061CryptographicStatus([Exception]$Exception, [uint32]$Expected) {
    for ($depth = 0; $depth -lt 8 -and $null -ne $Exception; $depth++) {
        if ($Exception -is [Security.Cryptography.CryptographicException] -and
            [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$Exception.HResult), 0) -eq $Expected) { return $true }
        $Exception = $Exception.InnerException
    }
    return $false
}

function Test-Stock5061KeyAbsent([string]$KeyName, [Security.Cryptography.CngProvider]$Provider) {
    $readOnlyHandle = $null
    try {
        $readOnlyHandle = [Security.Cryptography.CngKey]::Open($KeyName, $Provider, [Security.Cryptography.CngKeyOpenOptions]::MachineKey)
        return $false
    } catch {
        if (Test-Stock5061CryptographicStatus $_.Exception $nteBadKeyset) { return $true }
        throw 'Cannot prove exact Software KSP name absence.'
    } finally {
        if ($null -ne $readOnlyHandle) { $readOnlyHandle.Dispose() }
    }
}

function Get-Stock5061Hash([byte[]]$Bytes) {
    $digest = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($digest.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $digest.Dispose() }
}

function Get-Stock5061EventChild($Node, $Namespaces, [string]$Name) {
    $children = @($Node.SelectNodes("e:$Name", $Namespaces))
    if ($children.Count -ne 1) { throw 'Missing or duplicate Security event metadata.' }
    return $children[0]
}

function Match-Stock5061Event([string]$XmlText, [long]$Floor, [string]$KeyName,
    [datetimeoffset]$CreateFrom, [datetimeoffset]$CreateThrough, [datetimeoffset]$RepeatFrom, [datetimeoffset]$RepeatThrough) {
    $encoding = [Text.UTF8Encoding]::new($false, $true)
    if ($XmlText.Length -eq 0 -or $encoding.GetByteCount($XmlText) -gt 262144) { throw 'Security XML exceeds its bound.' }
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 262144
    $source = [IO.StringReader]::new($XmlText)
    $reader = [Xml.XmlReader]::Create($source, $settings)
    $xml = [Xml.XmlDocument]::new()
    $xml.XmlResolver = $null
    try { $xml.Load($reader) } finally { $reader.Dispose(); $source.Dispose() }
    $ns = [Xml.XmlNamespaceManager]::new($xml.NameTable)
    $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
    $system = @($xml.SelectNodes('/e:Event/e:System', $ns))
    if ($system.Count -ne 1) { throw 'Security event lacks one canonical System block.' }
    $provider = Get-Stock5061EventChild $system[0] $ns 'Provider'
    if ($provider.GetAttribute('Name') -cne $securityProvider -or $provider.GetAttribute('Guid').Trim('{}') -ine $securityProviderGuid.ToString() -or
        (Get-Stock5061EventChild $system[0] $ns 'Channel').InnerText -cne 'Security' -or
        (Get-Stock5061EventChild $system[0] $ns 'EventID').InnerText -cne '5061' -or
        (Get-Stock5061EventChild $system[0] $ns 'Version').InnerText -cne '0' -or
        (Get-Stock5061EventChild $system[0] $ns 'Computer').InnerText -ine $physicalFqdn) { return }
    $recordId = [long]0
    $recordText = (Get-Stock5061EventChild $system[0] $ns 'EventRecordID').InnerText
    if ($recordText -cnotmatch '^[1-9][0-9]{0,18}$' -or ![long]::TryParse($recordText, [ref]$recordId) -or $recordId -le $Floor) { return }
    $fields = @{}
    foreach ($field in $xml.SelectNodes('/e:Event/e:EventData/e:Data', $ns)) {
        $name = $field.GetAttribute('Name')
        if ($fields.ContainsKey($name)) { throw 'Duplicate Security event field.' }
        $fields[$name] = $field.InnerText
    }
    if ($fields.KeyName -cne $KeyName -or $fields.Operation -cne '%%2481') { return }
    if ($fields.ProviderName -cne $softwareKsp -or $fields.SubjectUserSid -cne 'S-1-5-18' -or
        $fields.KeyType -cne '%%2499' -or $fields.AlgorithmName -cne 'RSA' -or $fields.ReturnCode -cnotmatch '^0[xX][0-9a-fA-F]{1,8}$') {
        throw 'Named creation event has unexpected key custody, algorithm or status.'
    }
    $at = [datetimeoffset]::MinValue
    $rawTime = (Get-Stock5061EventChild $system[0] $ns 'TimeCreated').GetAttribute('SystemTime')
    if ($rawTime -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7}0{0,2})?Z$' -or
        ![datetimeoffset]::TryParse($rawTime, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None, [ref]$at)) { throw 'Malformed Security event clock.' }
    $keyword = (Get-Stock5061EventChild $system[0] $ns 'Keywords').InnerText
    if ($keyword -cnotmatch '^0[xX][0-9a-fA-F]{1,16}$') { throw 'Malformed Security audit keyword.' }
    $bits = [Convert]::ToUInt64($keyword.Substring(2), 16)
    $success = ($bits -band [uint64][Diagnostics.Eventing.Reader.StandardEventKeywords]::AuditSuccess) -ne 0
    $failure = ($bits -band [uint64][Diagnostics.Eventing.Reader.StandardEventKeywords]::AuditFailure) -ne 0
    $code = [Convert]::ToUInt32($fields.ReturnCode.Substring(2), 16)
    if ($code -eq 0 -and $success -and !$failure -and $at -ge $CreateFrom -and $at -le $CreateThrough) {
        $kind = 'initial-create-success'
    } elseif ($code -eq $nteExists -and $failure -and !$success -and $at -ge $RepeatFrom -and $at -le $RepeatThrough) {
        $kind = 'repeat-create-no-overwrite-refused'
    } else { throw 'Named create does not match the bounded success or no-overwrite failure.' }
    return [pscustomobject]@{
        kind = $kind; recordId = [string]$recordId; eventUtc = $at.ToString('o');
        operation = '%%2481'; keyType = '%%2499'; returnCode = ('0x{0:x}' -f $code);
        rawXmlSha256 = (Get-Stock5061Hash ($encoding.GetBytes($XmlText)))
    }
}

function Assert-Stock5061Pair([object[]]$Events) {
    if ($Events.Count -ne 2 -or $Events[0].kind -cne 'initial-create-success' -or
        $Events[1].kind -cne 'repeat-create-no-overwrite-refused' -or [long]$Events[1].recordId -le [long]$Events[0].recordId -or
        [datetimeoffset]$Events[1].eventUtc -le [datetimeoffset]$Events[0].eventUtc) {
        throw 'One ordered success and exact no-overwrite failure were not observed in the same bounded query.'
    }
}

function Read-Stock5061Pair([long]$Floor, [string]$KeyName, [datetimeoffset]$CreateFrom, [datetimeoffset]$CreateThrough,
    [datetimeoffset]$RepeatFrom, [datetimeoffset]$RepeatThrough) {
    if ($KeyName -cnotmatch '^tokentimer-audit-calibration-[a-f0-9]{32}$') { throw 'Unscoped key query.' }
    $xpath = "*[System[EventRecordID > $Floor and EventID=5061 and Provider[@Name='$securityProvider']] and EventData[Data[@Name='KeyName']='$KeyName']]"
    $query = [Diagnostics.Eventing.Reader.EventLogQuery]::new('Security', [Diagnostics.Eventing.Reader.PathType]::LogName, $xpath)
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $totalRead = 0
    while ($timer.ElapsedMilliseconds -lt 8000 -and [datetimeoffset]::UtcNow.AddSeconds(20) -lt $expires) {
        $reader = [Diagnostics.Eventing.Reader.EventLogReader]::new($query)
        $matchedRows = [Collections.Generic.List[object]]::new()
        $previous = $Floor
        $endOfQuery = $false
        try {
            while ($timer.ElapsedMilliseconds -lt 8000 -and [datetimeoffset]::UtcNow.AddSeconds(20) -lt $expires) {
                $entry = $reader.ReadEvent([timespan]::FromMilliseconds(250))
                if ($null -eq $entry) { $endOfQuery = $true; break }
                try {
                    if ((++$totalRead) -gt 512 -or $entry.RecordId -le $previous) { throw 'Security query record bound or ordering failed.' }
                    $previous = [long]$entry.RecordId
                    $match = Match-Stock5061Event ($entry.ToXml()) $Floor $KeyName $CreateFrom $CreateThrough $RepeatFrom $RepeatThrough
                    if ($null -ne $match) { $matchedRows.Add($match) }
                } finally { $entry.Dispose() }
            }
        } finally { $reader.Dispose() }
        if (!$endOfQuery) { throw 'Scoped Security query did not drain within its bounds.' }
        # A newly opened full snapshot may see a late visible event. Never merge
        # rows across snapshots or change the pre-operation floor or windows.
        if ($matchedRows.Count -ge 2) {
            $events = $matchedRows.ToArray()
            Assert-Stock5061Pair $events
            return $events
        }
        Start-Sleep -Milliseconds 150
    }
    throw 'One ordered success and exact no-overwrite failure were not observed in the same bounded query.'
}

# Read-only companion diagnostic for an already approved stock key operation.
# Capture the floor in the same original LocalSystem process before the operation.
# This module never changes the channel and cannot admit Security 5061.
$script:ProtectedNCryptChannel = 'Microsoft-Windows-Crypto-NCrypt/Operational'
$script:ProtectedNCryptProvider = 'Microsoft-Windows-Crypto-NCrypt'
$script:ProtectedNCryptGuid = '{e8ed09dc-100c-45e2-9fc8-b53399ec1f70}'

function Get-ProtectedNCryptCaller {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        if ($identity.User.Value -cne 'S-1-5-18' -or [int]$identity.ImpersonationLevel -ne 0) {
            throw [UnauthorizedAccessException]::new('Unimpersonated LocalSystem required.')
        }
    } finally { $identity.Dispose() }
    $process = [Diagnostics.Process]::GetCurrentProcess()
    try {
        [pscustomobject]@{
            processId = [uint32]$process.Id
            creationUtc = [datetimeoffset]$process.StartTime.ToUniversalTime()
            imagePath = $process.MainModule.FileName
        }
    } finally { $process.Dispose() }
}

function Open-ProtectedNCryptDiagnostic {
    param(
        [Parameter(Mandatory)][ValidatePattern('^tokentimer-audit-calibration-[a-f0-9]{32}$')][string]$KeyName,
        [Parameter(Mandatory)][datetimeoffset]$LeaseExpires
    )
    $caller = Get-ProtectedNCryptCaller
    if ([datetimeoffset]::UtcNow.AddSeconds(15) -ge $LeaseExpires) { throw 'Protected stock lease is too short.' }
    try {
        $config = [Diagnostics.Eventing.Reader.EventLogConfiguration]::new($script:ProtectedNCryptChannel)
        try {
            if (!$config.IsEnabled) { return [pscustomobject]@{ available=$false; reason='channel-disabled' } }
        } finally { $config.Dispose() }
        $query = [Diagnostics.Eventing.Reader.EventLogQuery]::new($script:ProtectedNCryptChannel, 'LogName', '*')
        $query.ReverseDirection = $true
        $reader = [Diagnostics.Eventing.Reader.EventLogReader]::new($query)
        try {
            $entry = $reader.ReadEvent([timespan]::FromMilliseconds(500))
            $floor = 0L
            if ($null -ne $entry) {
                try { $floor = [long]$entry.RecordId } finally { $entry.Dispose() }
                if ($floor -le 0) { throw 'Invalid original channel record floor.' }
            }
        } finally { $reader.Dispose() }
    } catch [TimeoutException] {
        return [pscustomobject]@{ available=$false; reason='floor-read-timeout' }
    } catch [UnauthorizedAccessException] {
        return [pscustomobject]@{ available=$false; reason='channel-read-denied' }
    } catch [Diagnostics.Eventing.Reader.EventLogException] {
        return [pscustomobject]@{ available=$false; reason='channel-read-unavailable' }
    }
    [pscustomobject]@{ available=$true; keyName=$KeyName; floor=$floor; caller=$caller
        sampledUtc=[datetimeoffset]::UtcNow; leaseExpires=$LeaseExpires }
}

function ConvertFrom-ProtectedNCryptDiagnosticXml {
    param(
        [Parameter(Mandatory)][string]$Xml,
        [Parameter(Mandatory)]$Baseline,
        [Parameter(Mandatory)][datetimeoffset]$RepeatFrom,
        [Parameter(Mandatory)][datetimeoffset]$RepeatThrough
    )
    if ($Xml.Length -gt 32768) { throw 'Operational XML exceeds its bound.' }
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 32768
    $input = [IO.StringReader]::new($Xml)
    $reader = [Xml.XmlReader]::Create($input,$settings)
    $doc = [Xml.XmlDocument]::new()
    $doc.XmlResolver = $null
    try { $doc.Load($reader) } finally { $reader.Dispose(); $input.Dispose() }
    $ns = [Xml.XmlNamespaceManager]::new($doc.NameTable)
    $ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
    $system = $doc.SelectSingleNode('/e:Event/e:System',$ns)
    if ($null -eq $system) { throw 'Missing original Operational event system record.' }
    $provider = $system.SelectSingleNode('e:Provider',$ns)
    $execution = $system.SelectSingleNode('e:Execution',$ns)
    $timestamp = $system.SelectSingleNode('e:TimeCreated',$ns)
    if ($null -eq $provider -or $null -eq $execution -or $null -eq $timestamp -or
        $provider.GetAttribute('Name') -cne $script:ProtectedNCryptProvider -or
        $provider.GetAttribute('Guid') -ine $script:ProtectedNCryptGuid -or
        $system.SelectSingleNode('e:EventID',$ns).InnerText -cne '4' -or
        $system.SelectSingleNode('e:Channel',$ns).InnerText -cne $script:ProtectedNCryptChannel) {
        throw 'Wrong Crypto-NCrypt Operational event identity.'
    }
    $rid = 0L
    [uint32]$pidValue = 0
    $eventTime = [datetimeoffset]::MinValue
    if (![long]::TryParse($system.SelectSingleNode('e:EventRecordID',$ns).InnerText,[ref]$rid) -or $rid -le $Baseline.floor -or
        ![uint32]::TryParse($execution.GetAttribute('ProcessID'),[ref]$pidValue) -or $pidValue -ne $Baseline.caller.processId -or
        ![datetimeoffset]::TryParse($timestamp.GetAttribute('SystemTime'),[ref]$eventTime) -or
        $eventTime -lt $RepeatFrom -or $eventTime -gt $RepeatThrough -or $eventTime -lt $Baseline.caller.creationUtc) {
        throw 'Operational record, original process, or duplicate time window differs.'
    }
    $security = $system.SelectSingleNode('e:Security',$ns)
    if ($null -ne $security -and $security.HasAttribute('UserID') -and $security.GetAttribute('UserID') -cne 'S-1-5-18') {
        throw 'Operational record names another security principal.'
    }
    $fields = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    foreach ($item in $doc.SelectNodes('/e:Event/e:EventData/e:Data',$ns)) {
        $field = $item.GetAttribute('Name')
        if (!$field -or $fields.Count -ge 16 -or $fields.ContainsKey($field)) { throw 'Ambiguous Operational payload fields.' }
        $fields.Add($field,$item.InnerText)
    }
    foreach ($field in 'ProviderName','KeyName','AlgorithmName','Flags','Status','ProcessName') {
        if (!$fields.ContainsKey($field)) { throw 'Incomplete Operational payload.' }
    }
    if ($fields['ProviderName'] -cne 'Microsoft Software Key Storage Provider' -or
        $fields['KeyName'] -cne $Baseline.keyName -or $fields['AlgorithmName'] -cne 'RSA' -or
        $fields['Flags'] -notmatch '^0x0*20$' -or $fields['Status'] -notmatch '^0x8009000f$') {
        throw 'Duplicate operation did not match exact named RSA machine create without overwrite.'
    }
    $image = $Baseline.caller.imagePath
    $reportedImage = $fields['ProcessName']
    if ($reportedImage -ine $image -and $reportedImage -ine [IO.Path]::GetFileName($image) -and
        $reportedImage -ine ('\??\'+$image)) { throw 'Operational event names a different caller image.' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Xml))).Replace('-','').ToLowerInvariant()
    } finally { $sha.Dispose() }
    [pscustomobject]@{ recordId=[string]$rid; eventUtc=$eventTime.ToUniversalTime().ToString('o'); eventSha256=$digest }
}

function Read-ProtectedNCryptDuplicateDiagnostic {
    param(
        [Parameter(Mandatory)]$Baseline,
        [Parameter(Mandatory)][datetimeoffset]$RepeatFrom,
        [Parameter(Mandatory)][datetimeoffset]$RepeatThrough
    )
    if (!$Baseline.available -or $Baseline.keyName -cnotmatch '^tokentimer-audit-calibration-[a-f0-9]{32}$' -or
        $Baseline.floor -lt 0 -or $RepeatFrom -lt $Baseline.sampledUtc -or $RepeatThrough -lt $RepeatFrom -or
        ($RepeatThrough - $RepeatFrom).TotalSeconds -gt 5 -or [datetimeoffset]::UtcNow.AddSeconds(7) -ge $Baseline.leaseExpires) {
        throw 'Original available channel and bounded duplicate operation required.'
    }
    $actual = Get-ProtectedNCryptCaller
    if ($actual.processId -ne $Baseline.caller.processId -or $actual.creationUtc -ne $Baseline.caller.creationUtc -or
        $actual.imagePath -ine $Baseline.caller.imagePath) { throw 'Original stock caller lifetime is gone.' }
    $filter = "*[System[EventID=4 and EventRecordID > $($Baseline.floor)] and EventData[Data[@Name='KeyName']='$($Baseline.keyName)']]"
    $query = [Diagnostics.Eventing.Reader.EventLogQuery]::new($script:ProtectedNCryptChannel,'LogName',$filter)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $match = $null
    while ($watch.ElapsedMilliseconds -lt 3500) {
        $reader = [Diagnostics.Eventing.Reader.EventLogReader]::new($query)
        try {
            $count = 0
            $match = $null
            $ended = $false
            while ($watch.ElapsedMilliseconds -lt 3500) {
                $entry = $reader.ReadEvent([timespan]::FromMilliseconds(200))
                if ($null -eq $entry) { $ended = $true; break }
                try {
                    if ((++$count) -gt 16 -or $null -ne $match) { throw 'Ambiguous scoped Operational duplicate events.' }
                    $match = ConvertFrom-ProtectedNCryptDiagnosticXml ($entry.ToXml()) $Baseline $RepeatFrom $RepeatThrough
                } finally { $entry.Dispose() }
            }
            if (!$ended) { throw 'Scoped Operational snapshot could not be fully read.' }
        } finally { $reader.Dispose() }
        if ($null -ne $match) { break }
        Start-Sleep -Milliseconds 125
    }
    [pscustomobject]@{
        scope='stock-ncrypt-operational-duplicate-diagnostic'
        operationalEvent4Observed=($null -ne $match)
        record=$match
        security5061FailureProven=$false
        nativeAdmission=$false
    }
}

function Read-Stock5061Outcome {
    param([long]$Floor,[string]$KeyName,[string]$Computer,[datetimeoffset]$WindowFrom,
        [datetimeoffset]$WindowThrough,[datetimeoffset]$RepeatFrom,[datetimeoffset]$RepeatThrough)
    if ($Floor -lt 0 -or $KeyName -cnotmatch '^tokentimer-audit-calibration-[a-f0-9]{32}$' -or
        $WindowThrough -lt $WindowFrom -or ($WindowThrough - $WindowFrom).TotalSeconds -gt 45 -or
        $RepeatFrom -lt $WindowFrom -or $RepeatThrough -lt $RepeatFrom -or $RepeatThrough -gt $WindowThrough) {
        throw 'Invalid bounded Security outcome window.'
    }
    $filter = "*[System[EventID=5061 and EventRecordID > $Floor and Provider[@Name='$securityProvider']]]"
    $query = [Diagnostics.Eventing.Reader.EventLogQuery]::new('Security','LogName',$filter)
    $reader = [Diagnostics.Eventing.Reader.EventLogReader]::new($query)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $report = [ordered]@{ scope='stock-5061-outcome'; namedCreateSuccess=0; namedFailures=@()
        duplicateExactName=0; duplicateAbsentName=0; duplicateOtherName=0
        nativeAdmission=$false }
    $seen = 0
    $last = $Floor
    try {
        while ($clock.ElapsedMilliseconds -lt 3500) {
            $entry = $reader.ReadEvent([timespan]::FromMilliseconds(250))
            if ($null -eq $entry) { return [pscustomobject]$report }
            try {
                if ((++$seen) -gt 128 -or $entry.RecordId -le $last -or $entry.MachineName -ine $Computer) {
                    throw 'Scoped 5061 record count, ordering or host changed.'
                }
                $last = [long]$entry.RecordId
                if ($null -eq $entry.TimeCreated) { throw 'Scoped 5061 timestamp unavailable.' }
                $time = [datetimeoffset]$entry.TimeCreated
                if ($time -lt $WindowFrom -or $time -gt $WindowThrough) { continue }
                $row = ConvertFrom-Stock5061OutcomeXml ($entry.ToXml())
                if ($row.ProviderName -cne $softwareKsp -or $row.SubjectUserSid -cne 'S-1-5-18' -or
                    $row.KeyType -cne '%%2499') { continue }
                $failed = (([int64]$entry.Keywords -band [int64][Diagnostics.Eventing.Reader.StandardEventKeywords]::AuditFailure) -ne 0)
                $succeeded = (([int64]$entry.Keywords -band [int64][Diagnostics.Eventing.Reader.StandardEventKeywords]::AuditSuccess) -ne 0)
                $same = ($row.KeyName -ceq $KeyName)
                if ($same -and $succeeded -and !$failed -and $row.Operation -ceq '%%2481' -and $row.ReturnCode -ieq '0x0' -and $row.AlgorithmName -ceq 'RSA') {
                    $report.namedCreateSuccess++
                }
                if ($same -and $failed -and !$succeeded -and $row.Operation -match '^%%[0-9]{3,6}$' -and $row.ReturnCode -match '^0x[0-9a-f]{1,8}$') {
                    if ($report.namedFailures.Count -ge 16) { throw 'Too many failures for the exact disposable name.' }
                    $report.namedFailures += [ordered]@{ recordId=[string]$last; operation=$row.Operation
                        returnCode=$row.ReturnCode.ToLowerInvariant(); eventUtc=$time.ToUniversalTime().ToString('o') }
                }
                if ($failed -and !$succeeded -and $row.Operation -ceq '%%2481' -and
                    $row.ReturnCode -ieq '0x8009000f' -and $time -ge $RepeatFrom -and $time -le $RepeatThrough) {
                    if ($same) { $report.duplicateExactName++ }
                    elseif ([string]::IsNullOrWhiteSpace($row.KeyName)) { $report.duplicateAbsentName++ }
                    else { $report.duplicateOtherName++ }
                }
            } finally { $entry.Dispose() }
        }
    } finally { $reader.Dispose() }
    throw 'Bounded Security outcome snapshot did not drain.'
}

function ConvertFrom-Stock5061OutcomeXml([string]$Xml) {
    if (!$Xml -or $Xml.Length -gt 32768) { throw 'Malformed Security outcome XML.' }
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 32768
    $text = [IO.StringReader]::new($Xml)
    $input = [Xml.XmlReader]::Create($text,$settings)
    $doc = [Xml.XmlDocument]::new()
    $doc.XmlResolver = $null
    try { $doc.Load($input) } finally { $input.Dispose(); $text.Dispose() }
    $ns = [Xml.XmlNamespaceManager]::new($doc.NameTable)
    $ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
    $fields = @{}
    foreach ($field in $doc.SelectNodes('/e:Event/e:EventData/e:Data',$ns)) {
        $name = $field.GetAttribute('Name')
        if (!$name -or $fields.ContainsKey($name) -or $fields.Count -ge 32) { throw 'Ambiguous Security outcome field.' }
        $fields[$name] = $field.InnerText
    }
    $fields
}


function Read-NamedStock5061Rows([long]$Floor,[string]$KeyName,[string]$Computer) {
    if ($Floor -lt 0 -or $KeyName -cnotmatch '^tokentimer-audit-calibration-[a-f0-9]{32}$') {
        throw 'Expected exact disposable Security name and original floor.'
    }
    $filter = "*[System[EventID=5061 and EventRecordID > $Floor and Provider[@Name='$securityProvider']] and EventData[Data[@Name='KeyName']='$KeyName']]"
    $query = [Diagnostics.Eventing.Reader.EventLogQuery]::new('Security','LogName',$filter)
    $reader = [Diagnostics.Eventing.Reader.EventLogReader]::new($query)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $rows = @()
    $last = $Floor
    try {
        while ($clock.ElapsedMilliseconds -lt 2500) {
            $entry = $reader.ReadEvent([timespan]::FromMilliseconds(250))
            if ($null -eq $entry) { return [pscustomobject]@{ available=$true; rows=$rows } }
            try {
                if ($rows.Count -ge 16 -or $entry.RecordId -le $last -or $entry.MachineName -ine $Computer -or $null -eq $entry.TimeCreated) {
                    throw 'Exact named 5061 source, position or count changed.'
                }
                $last = [long]$entry.RecordId
                $row = ConvertFrom-Stock5061OutcomeXml ($entry.ToXml())
                if ($row.KeyName -cne $KeyName -or $row.Operation -notmatch '^%%[0-9]{3,6}$' -or
                    $row.ReturnCode -notmatch '^0x[0-9a-f]{1,8}$') { throw 'Unexpected scoped 5061 fields.' }
                $rows += [ordered]@{ recordId=[string]$last; eventUtc=([datetimeoffset]$entry.TimeCreated).ToUniversalTime().ToString('o')
                    operation=$row.Operation; returnCode=$row.ReturnCode.ToLowerInvariant()
                    softwareKsp=($row.ProviderName -ceq $softwareKsp); originalLocalSystem=($row.SubjectUserSid -ceq 'S-1-5-18')
                    rsa=($row.AlgorithmName -ceq 'RSA'); machineKey=($row.KeyType -ceq '%%2499')
                    auditSuccess=(([int64]$entry.Keywords -band [int64][Diagnostics.Eventing.Reader.StandardEventKeywords]::AuditSuccess) -ne 0)
                    auditFailure=(([int64]$entry.Keywords -band [int64][Diagnostics.Eventing.Reader.StandardEventKeywords]::AuditFailure) -ne 0) }
            } finally { $entry.Dispose() }
        }
    } finally { $reader.Dispose() }
    throw 'Exact named Security snapshot did not drain.'
}


$stage = 'stock-standalone-member'
$opBaseline = $null
$opReceipt = [pscustomobject]@{ available=$false; reason='not-observed' }
$shapeReceipt = [pscustomobject]@{ available=$false; reason='not-observed' }
$nativeDuplicate = $false
$namedReceipt = [pscustomobject]@{ available=$false; reason='not-read' }
$originalKey = $null
$ownedHandleDeleted = $false
$absentBefore = $false
$absentAfter = $false
$auditBefore = $null
$auditAfter = $null
$auditIdentity = $null
try {
    Assert-Stock5061Member $RunNonce
    $stage = 'native-readonly-helpers'
    Initialize-Stock5061Native
    Initialize-Stock5061AuditEnumeration
    $started = Get-Stock5061Utc
    $keyName = "tokentimer-audit-calibration-$RunNonce"
    $keyProvider = [Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
    $stage = 'effective-audit'
    Assert-Stock5061Unimpersonated
    $auditIdentity = [Security.Principal.WindowsIdentity]::GetCurrent([Security.Principal.TokenAccessLevels]::Query)
    $auditBefore = Get-Stock5061Audit $auditIdentity
    if ($auditBefore -ne 3 -or !(Get-WinEvent -ListLog Security -ErrorAction Stop).IsEnabled) { throw 'Effective System Integrity Success and Failure required.' }
    $stage = 'record-floor'
    $floor = Get-Stock5061RecordFloor
    $stage = 'pre-absence'
    $absentBefore = Test-Stock5061KeyAbsent $keyName $keyProvider
    if (!$absentBefore) { throw 'Existing named key is outside this fixture.' }
    $stage = 'record-floor'
    try {
        $opBaseline = Open-ProtectedNCryptDiagnostic $keyName $expires
        if (!$opBaseline.available) { $opReceipt = $opBaseline }
    } catch {
        $opReceipt = [pscustomobject]@{ available=$false; reason='operational-preflight-refused' }
    }

    if ([datetimeoffset]::UtcNow.AddSeconds(45) -ge $expires) { throw 'Too little lease remains for calibration.' }
    $parameters = [Security.Cryptography.CngKeyCreationParameters]::new()
    $parameters.Provider = $keyProvider
    $parameters.KeyCreationOptions = [Security.Cryptography.CngKeyCreationOptions]::MachineKey
    $parameters.ExportPolicy = [Security.Cryptography.CngExportPolicies]::None
    $parameters.Parameters.Add([Security.Cryptography.CngProperty]::new('Length', [BitConverter]::GetBytes(2048),
        [Security.Cryptography.CngPropertyOptions]::None))
    try {
        $stage = 'one-named-machine-create'
        $createFrom = Get-Stock5061Utc
        $originalKey = [Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::Rsa, $keyName, $parameters)
        $createThrough = Get-Stock5061Utc
        if ($null -eq $originalKey -or !$originalKey.IsMachineKey -or $originalKey.IsEphemeral -or $originalKey.KeyName -cne $keyName -or
            $originalKey.Provider.Provider -cne $softwareKsp -or [int]$originalKey.ExportPolicy -ne 0 -or $originalKey.KeySize -ne 2048) {
            throw 'Original retained named nonexportable machine key differs.'
        }
        $stage = 'repeat-without-overwrite'
        if (Test-Stock5061KeyAbsent $keyName $keyProvider) { throw 'Original named key is not present for the duplicate request.' }
        $repeatFrom = Get-Stock5061Utc
        try {
            $unexpected = [Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::Rsa, $keyName, $parameters)
            if ($null -ne $unexpected) { $unexpected.Dispose() }
            throw 'Unexpected return from duplicate create.'
        } catch {
            if (!(Test-Stock5061CryptographicStatus $_.Exception $nteExists)) { throw 'Duplicate did not return exact NTE_EXISTS.' }
            $nativeDuplicate = $true
        }
        $repeatThrough = Get-Stock5061Utc
    } finally {
        # Cleanup targets only the original retained handle. Never delete a reopened name.
        $operationStage = $stage
        $stage = 'original-handle-cleanup'
        try {
            if ($null -ne $originalKey) {
                try { $originalKey.Delete(); $ownedHandleDeleted = $true }
                finally { $originalKey.Dispose() }
            }
        } finally { $absentAfter = Test-Stock5061KeyAbsent $keyName $keyProvider }
        if (!$absentAfter) { throw 'Exact post-cleanup Software KSP name is not absent.' }
        $stage = $operationStage
    }
    if (!$ownedHandleDeleted -or $createThrough -lt $createFrom -or $repeatFrom -lt $createThrough -or $repeatThrough -lt $repeatFrom) {
        throw 'Original handle deletion or exact operation timing was not established.'
    }
    if ($null -ne $opBaseline -and $opBaseline.available) {
        try { $opReceipt = Read-ProtectedNCryptDuplicateDiagnostic $opBaseline $repeatFrom $repeatThrough }
        catch { $opReceipt = [pscustomobject]@{ available=$false; reason='operational-observation-refused' } }
    }
    try { $shapeReceipt = Read-Stock5061Outcome $floor $keyName $physicalFqdn $started (Get-Stock5061Utc) $repeatFrom $repeatThrough }
    catch { $shapeReceipt = [pscustomobject]@{ available=$false; reason='security-outcome-read-refused'; errorType=$_.Exception.GetBaseException().GetType().Name; hresult=$_.Exception.GetBaseException().HResult } }
    $stage = 'final-readbacks'
    $auditAfter = Get-Stock5061Audit $auditIdentity
    if ($auditAfter -ne $auditBefore -or !(Get-WinEvent -ListLog Security -ErrorAction Stop).IsEnabled -or
        !(Test-Stock5061KeyAbsent $keyName $keyProvider) -or [datetimeoffset]::UtcNow -ge $expires) {
        throw 'Final key absence, effective audit or lease readback failed.'
    }
    $stage = 'bounded-5061-pair'
    try {
        $events = @(Read-Stock5061Pair $floor $keyName $createFrom $createThrough $repeatFrom $repeatThrough)
    } finally {
        try { $namedReceipt = Read-NamedStock5061Rows $floor $keyName $physicalFqdn }
        catch { $namedReceipt = [pscustomobject]@{ available=$false; reason='named-stock-read-refused'
            errorType=$_.Exception.GetBaseException().GetType().Name; hresult=$_.Exception.GetBaseException().HResult } }
    }
} catch {
    $status = [ordered]@{
        scope = 'github-hosted-stock-cng-disposable-key-control'; status = 'refused'; run = $RunNonce; vmId = $vmId;
        stage = $stage; keyAbsentBefore = $absentBefore; keyAbsentAfterCleanup = $absentAfter; originalHandleDeleted = $ownedHandleDeleted;
        auditBefore = $auditBefore; auditAfter = $auditAfter; continuityProven = $false; coverageComplete = $false; nativeDuplicateNteExists = $nativeDuplicate; operational = $opReceipt; securityShape = $shapeReceipt; namedSecurity = $namedReceipt; nativeAdmission = $false
    }
    [IO.File]::WriteAllText($ResultPath, ($status | ConvertTo-Json -Depth 8 -Compress), [Text.UTF8Encoding]::new($false))
    throw 'Stock 5061 calibration refused. Review only the sanitized stage and cleanup readback.'
} finally {
    if ($null -ne $auditIdentity) { $auditIdentity.Dispose() }
}

$receipt = [ordered]@{
    scope = 'github-hosted-stock-cng-disposable-key-control'; status = 'passed'; run = $RunNonce;
    vmId = $vmId; physicalFqdn = $physicalFqdn; keyNameSha256 = (Get-Stock5061Hash ([Text.Encoding]::UTF8.GetBytes($keyName)));
    provider = $softwareKsp; machineKey = $true; nonexportable = $true; keySizeBits = 2048;
    firstRecordFloor = [string]$floor; events = $events; auditBefore = $auditBefore; auditAfter = $auditAfter;
    auditProofScope = 'bounded-enumeration-and-paired-system-snapshots'; directEffectiveTokenQueryProven = $false;
    keyAbsentBefore = $absentBefore; keyAbsentAfterCleanup = $absentAfter; originalHandleDeleted = $ownedHandleDeleted;
    startedUtc = $started.ToString('o'); completedUtc = (Get-Stock5061Utc).ToString('o');
    continuityProven = $false; lossFree = $false; coverageComplete = $false; nativeDuplicateNteExists = $nativeDuplicate; operational = $opReceipt; securityShape = $shapeReceipt; namedSecurity = $namedReceipt; nativeAdmission = $false
}
[IO.File]::WriteAllText($ResultPath, ($receipt | ConvertTo-Json -Depth 8 -Compress), [Text.UTF8Encoding]::new($false))
