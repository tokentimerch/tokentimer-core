<#
Disposable CA officer fault: replace the SAN of one independently owned pending
request. No CA policy, template, requester, key or permissions are changed.
The caller owns denial/revocation and unaccepted-key cleanup on every outcome.
#>
param(
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{10}$')][string]$RunId,
  [Parameter(Mandatory)][ValidatePattern('^certops-adcs-[a-f0-9]{10}-[a-z0-9]+\.example\.test$')][string]$CommonName,
  [Parameter(Mandatory)][ValidateRange(1,4294967295)][long]$RequestId,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$CsrDerSha256,
  [Parameter(Mandatory)][ValidatePattern('^\d+(\.\d+)+$')][string]$TemplateOid)
$ErrorActionPreference='Stop'
if($CommonName -cnotmatch "^certops-adcs-$RunId-[a-z0-9]+\.example\.test$"){throw 'Foreign request run'}
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test' -or -not $env:CERTOPS_ADCS_OFFICER_PASSWORD){throw 'SAN fault requires disposable forest credentials'}
$credential=[PSCredential]::new('TTQUAL\tt-lab-admin',(ConvertTo-SecureString $env:CERTOPS_ADCS_OFFICER_PASSWORD -AsPlainText -Force))
Invoke-Command -ComputerName 'tt-ca.lab.certops.test' -Credential $credential -ArgumentList $RunId,$CommonName,$RequestId,$CsrDerSha256,$TemplateOid -ScriptBlock {
  param($RunId,$CommonName,$RequestId,$CsrDerSha256,$TemplateOid)
  $ErrorActionPreference='Stop'
  if($env:COMPUTERNAME -ine 'TT-CA' -or (Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Foreign CA host'}
  # Public temporary bytes only. Retained no-delete-sharing handles prevent
  # replacement; deletion targets the original kernel handle, never a path.
  $publicFileSource=@'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
public sealed class TTSanPublicFile : IDisposable {
 [StructLayout(LayoutKind.Sequential)] struct Info { public uint Attr; public System.Runtime.InteropServices.ComTypes.FILETIME C,A,W; public uint Vol,High,Low,Links,IdHigh,IdLow; }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string p,uint a,uint s,IntPtr sec,uint c,uint f,IntPtr t);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info i);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle h,int kind,ref byte value,uint size);
 SafeFileHandle parent; FileStream file,guard; string path,guardPath,parentId,fileId,guardId,hash; bool deleted;
 static string Identity(SafeFileHandle h,bool directory){Info i;if(h.IsInvalid||!GetFileInformationByHandle(h,out i)||(i.Attr&0x400)!=0||((i.Attr&0x10)!=0)!=directory)throw new IOException("Unsafe public SAN file identity");return i.Vol.ToString("x8")+":"+i.IdHigh.ToString("x8")+i.IdLow.ToString("x8");}
 static SafeFileHandle Open(string p,bool directory){var h=CreateFile(p,0x80000000,7,IntPtr.Zero,3,(directory?0x02000000u:0u)|0x00200000u,IntPtr.Zero);if(h.IsInvalid){h.Dispose();throw new IOException("Public SAN identity open failed");}return h;}
 static FileStream NewFile(string p){var h=CreateFile(p,0xC0010000,1,IntPtr.Zero,1,0x00200000,IntPtr.Zero);if(h.IsInvalid){h.Dispose();throw new IOException("Refusing existing public SAN file");}return new FileStream(h,FileAccess.ReadWrite);}
 static string Digest(FileStream s){s.Flush();s.Position=0;using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(s)).Replace("-","").ToLowerInvariant();}
 static void DeleteHandle(FileStream s){byte yes=1;if(!SetFileInformationByHandle(s.SafeFileHandle,4,ref yes,1))throw new IOException("Public SAN handle deletion failed");}
 public static TTSanPublicFile Create(string p,byte[] bytes){
  var o=new TTSanPublicFile();o.path=Path.GetFullPath(p);o.guardPath=o.path+".owner.json";
  try {
   var directory=Path.GetDirectoryName(o.path);o.parent=CreateFile(directory,0x80000000,1,IntPtr.Zero,3,0x02200000,IntPtr.Zero);o.parentId=Identity(o.parent,true);
   o.guard=NewFile(o.guardPath);o.guardId=Identity(o.guard.SafeFileHandle,false);
   o.file=NewFile(o.path);o.file.Write(bytes,0,bytes.Length);o.fileId=Identity(o.file.SafeFileHandle,false);o.hash=Digest(o.file);o.file.Dispose();o.file=null;
   // The actual certutil reader does not share DELETE/WRITE access. Keep a
   // read-only no-delete-sharing handle during that read instead.
   var reader=CreateFile(o.path,0x80000000,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero);o.file=new FileStream(reader,FileAccess.Read);
   if(Identity(o.file.SafeFileHandle,false)!=o.fileId||Digest(o.file)!=o.hash)throw new IOException("Preserve replaced public SAN creation");
   var receipt=System.Text.Encoding.ASCII.GetBytes("{\"kind\":\"owned-public-san-file\",\"parent\":\""+o.parentId+"\",\"file\":\""+o.fileId+"\",\"sha256\":\""+o.hash+"\"}");o.guard.Write(receipt,0,receipt.Length);o.guard.Flush();return o;
  } catch {o.Dispose();throw;}
 }
 public void VerifyAndDelete(){
  if(deleted)throw new IOException("Public SAN receipt already released");
  using(var p=Open(Path.GetDirectoryName(path),true))using(var f=Open(path,false))using(var g=Open(guardPath,false)){
   if(Identity(p,true)!=parentId||Identity(f,false)!=fileId||Identity(g,false)!=guardId||Identity(parent,true)!=parentId||Identity(file.SafeFileHandle,false)!=fileId||Digest(file)!=hash)throw new IOException("Preserve replaced public SAN file or receipt");
  }
  // Reacquire exclusive DELETE access only after the reader is done. A
  // replacement in this bounded gap is detected by original file ID+hash.
  file.Dispose();file=null;
  var deletion=CreateFile(path,0x80010000,0,IntPtr.Zero,3,0x00200000,IntPtr.Zero);file=new FileStream(deletion,FileAccess.Read);
  if(Identity(file.SafeFileHandle,false)!=fileId||Digest(file)!=hash||Identity(parent,true)!=parentId)throw new IOException("Preserve replaced public SAN deletion candidate");
  DeleteHandle(file);DeleteHandle(guard);deleted=true;
 }
 public void Dispose(){if(file!=null)file.Dispose();if(guard!=null)guard.Dispose();if(parent!=null)parent.Dispose();}
}
'@
  if(-not ('TTSanPublicFile' -as [type])){Add-Type -TypeDefinition $publicFileSource}
  $view=New-Object -ComObject CertificateAuthority.View;$ownedFile=$null
  $file="C:\ttqualification\san-mismatch-$RunId-$RequestId.der"
  try {
    $null=$view.OpenConnection('tt-ca.lab.certops.test\TTQualificationRoot')
    $names=@('RequestID','CommonName','RequesterName','Disposition','RawRequest','CertificateTemplate');$view.SetResultColumnCount($names.Count)
    foreach($name in $names){$view.SetResultColumn($view.GetColumnIndex($false,$name))}
    $view.SetRestriction($view.GetColumnIndex($false,'RequestID'),1,0,[uint32]$RequestId)
    $rows=$view.OpenView();if($rows.Next() -eq -1){throw 'Owned pending request absent'}
    $columns=$rows.EnumCertViewColumn();$values=@();while($columns.Next() -ne -1){$values+=,$columns.GetValue($(if($values.Count -eq 4){1}else{0}))}
    if($values.Count -ne 6 -or [long]$values[0] -ne $RequestId -or $values[1] -cne $CommonName -or $values[2] -ine 'TTQUAL\tt-agent$' -or [int]$values[3] -ne 9 -or [string]$values[5] -cne $TemplateOid -or $rows.Next() -ne -1){throw 'Foreign or non-pending request/template'}
    $csr=[Convert]::FromBase64String([string]$values[4]);if($csr.Length -lt 100 -or $csr.Length -gt 65536){throw 'Public CSR size'}
    $hash=[Security.Cryptography.SHA256]::Create();try{$actual=([BitConverter]::ToString($hash.ComputeHash($csr))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
    if($actual -cne $CsrDerSha256){throw 'Owned pending public CSR DER mismatch'}
    $wrong="certops-adcs-$RunId-wrongsan.example.test";if($wrong -ceq $CommonName){throw 'Distinct SAN required'}
    $name=[Text.Encoding]::ASCII.GetBytes($wrong);if($name.Length -ge 128 -or $name.Length+2 -ge 128){throw 'Bounded literal SAN length'}
    $der=[byte[]](@(48,($name.Length+2),130,$name.Length)+$name)
    $directory=Get-Item -LiteralPath 'C:\ttqualification';if(-not $directory.PSIsContainer -or ($directory.Attributes-band [IO.FileAttributes]::ReparsePoint)){throw 'Unsafe public fault directory'}
    $ownedFile=[TTSanPublicFile]::Create($file,$der)
    & certutil.exe -config 'tt-ca.lab.certops.test\TTQualificationRoot' -setextension "$RequestId" '2.5.29.17' 0 "@$file" | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Owned native SAN extension mutation failed'}
    @{requestId=$RequestId;wrongDnsName=$wrong;csrDerSha256=$actual;templateOid=$TemplateOid;nativePendingOwnershipVerified=$true}|ConvertTo-Json -Compress
  } finally {
    try{if($ownedFile){$ownedFile.VerifyAndDelete()}}finally{if($ownedFile){$ownedFile.Dispose()};if($view){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)}}
  }
}
