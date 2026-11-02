<# Compile/parser controls only. Never opens a native handle or invokes a constructor. #>
$ErrorActionPreference='Stop'
$file=Join-Path $PSScriptRoot '../tests/e2e/helpers/certops-windows-source-junction-hold.ps1'
$tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'PowerShell syntax errors'}
$text=[IO.File]::ReadAllText($file);$matches=[regex]::Matches($text,"(?s)Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@")
if($matches.Count-ne1){throw 'One fixture C# declaration required'}
Add-Type -TypeDefinition $matches[0].Groups[1].Value
function Buffer([string]$path){$value=[Text.Encoding]::Unicode.GetBytes($path);$bytes=[byte[]]::new(16+$value.Length);[BitConverter]::GetBytes([uint32]2684354563).CopyTo($bytes,0);[BitConverter]::GetBytes([uint16]($bytes.Length-8)).CopyTo($bytes,4);[BitConverter]::GetBytes([uint16]$value.Length).CopyTo($bytes,10);$value.CopyTo($bytes,16);return ,$bytes}
$valid=Buffer '\??\C:\owned\target'
if([OwnedSourceJunction]::ParseTarget($valid,$valid.Length) -cne 'C:\owned\target'){throw 'Exact owned target parser failed'}
foreach($kind in @('tag','odd-offset','odd-length','overflow','truncated','unc')){
 $bad=$valid.Clone();$length=$bad.Length
 switch($kind){'tag'{$bad[0]=0}'odd-offset'{$bad[8]=1}'odd-length'{$bad[10]=1}'overflow'{$bad[10]=254;$bad[11]=127}'truncated'{$length=15}'unc'{$bad=Buffer '\??\UNC\foreign\share';$length=$bad.Length}}
 $refused=$false;try{[void][OwnedSourceJunction]::ParseTarget($bad,$length)}catch{$refused=$true};if(!$refused){throw 'Invalid mount point data accepted'}
}
'Source junction types compiled and pure adversaries passed without native invocation'
