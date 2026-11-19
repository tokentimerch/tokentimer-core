[CmdletBinding(DefaultParameterSetName='Create')]
param(
    [Parameter(Mandatory)][string]$RunnerTemp,
    [Parameter(Mandatory,ParameterSetName='Verify')][string]$VerifyStage
)

$ErrorActionPreference = 'Stop'
$owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
$allowed = @($owner.Value, 'S-1-5-18', 'S-1-5-32-544')
$servicing = [Security.Principal.NTAccount]::new('NT SERVICE', 'TrustedInstaller')
$allowedAncestors = $allowed + @($servicing.Translate([Security.Principal.SecurityIdentifier]).Value)
$access = [Security.AccessControl.AccessControlType]::Allow
$inheritedChildren = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
$parentMutation = [Security.AccessControl.FileSystemRights]'Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'

function Assert-TrustedDirectory([string]$LiteralPath, [bool]$Private) {
    $item = Get-Item -LiteralPath $LiteralPath -Force
    if (!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Signing stage path traverses a reparse point or non-directory'
    }
    $acl = [IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]$item.FullName)
    $scope = [Security.Principal.SecurityIdentifier]
    $directoryOwner = $acl.GetOwner($scope).Value
    if ($directoryOwner -notin $allowedAncestors) { throw 'Signing stage directory has an unexpected owner' }
    $rules = @($acl.GetAccessRules($true, $true, $scope))
    if ($Private) {
        if (!$acl.AreAccessRulesProtected -or $directoryOwner -ne $owner.Value -or
            $rules.Count -ne 3 -or @($rules.IdentityReference.Value | Select-Object -Unique).Count -ne 3) {
            throw 'Signing stage does not have the expected isolated ACL'
        }
        foreach ($rule in $rules) {
            if ($rule.IdentityReference.Value -notin $allowed -or $rule.AccessControlType -ne $access -or
                $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
                $rule.InheritanceFlags -ne $inheritedChildren -or $rule.PropagationFlags -ne 0 -or $rule.IsInherited) {
                throw 'Signing stage ACL grants unexpected access'
            }
        }
        return
    }

    foreach ($rule in $rules) {
        if ($rule.IdentityReference.Value -notin $allowedAncestors -and $rule.AccessControlType -eq $access -and
            !($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
            ($rule.FileSystemRights -band $parentMutation)) {
            throw 'An untrusted principal can replace a signing-stage ancestor'
        }
    }
}

function Assert-TrustedAncestors([IO.DirectoryInfo]$Directory) {
    for ($cursor = $Directory; $null -ne $cursor; $cursor = $cursor.Parent) {
        Assert-TrustedDirectory $cursor.FullName $false
    }
}

if (![IO.Path]::IsPathFullyQualified($RunnerTemp)) { throw 'Runner temp directory must be absolute' }
$runner = [IO.DirectoryInfo]::new([IO.Path]::GetFullPath($RunnerTemp))
$localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
$alternateParent = $null
if ($localAppData -and [IO.Path]::IsPathFullyQualified($localAppData)) {
    $alternateParent = [IO.DirectoryInfo]::new([IO.Path]::GetFullPath($localAppData))
}

if ($PSCmdlet.ParameterSetName -eq 'Verify') {
    if (![IO.Path]::IsPathFullyQualified($VerifyStage)) { throw 'Signing stage must be absolute' }
    $stage = [IO.DirectoryInfo]::new([IO.Path]::GetFullPath($VerifyStage))
    if ($stage.Parent.FullName -ine $runner.FullName -and
        (!$alternateParent -or $stage.Parent.FullName -ine $alternateParent.FullName)) {
        throw 'Signing stage is outside the two approved parent directories'
    }
    if ($stage.Name -cnotmatch '^windows-signing-pilot-[a-f0-9]{32}$') { throw 'Invalid signing stage name' }
    Assert-TrustedAncestors $stage.Parent
    Assert-TrustedDirectory $stage.FullName $true
    return
}

# The hosted work volume can have an unexpected owner. The current user's
# local app data is eligible only after the same owner, ACL and reparse checks.
try {
    Assert-TrustedAncestors $runner
} catch {
    if (!$alternateParent -or $alternateParent.FullName -ieq $runner.FullName) { throw }
    Assert-TrustedAncestors $alternateParent
    $runner = $alternateParent
}

$name = 'windows-signing-pilot-' + [Guid]::NewGuid().ToString('N')
$stage = [IO.DirectoryInfo]::new((Join-Path $runner.FullName $name))
if ($stage.Exists) { throw 'Signing stage already exists' }
$stageAcl = [Security.AccessControl.DirectorySecurity]::new()
$stageAcl.SetOwner($owner)
$stageAcl.SetAccessRuleProtection($true, $false)
foreach ($sidText in $allowed) {
    $sid = [Security.Principal.SecurityIdentifier]::new($sidText)
    $stageAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $sid, [Security.AccessControl.FileSystemRights]::FullControl, $inheritedChildren,
        [Security.AccessControl.PropagationFlags]::None, $access
    ))
}
[IO.FileSystemAclExtensions]::Create($stage, $stageAcl)
Assert-TrustedDirectory $stage.FullName $true
$stage.FullName
