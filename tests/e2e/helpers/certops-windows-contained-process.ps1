<# Test-only suspended native process containment. Public launch arguments are sealed;
private bootstrap environment is inherited, never serialized. Exact retained native
job/root/parent handles govern closure. Wrapper exit alone never proves drainage. #>
[CmdletBinding(DefaultParameterSetName="Launch")]
param(
 [Parameter(Mandatory,ParameterSetName="Observe")][int]$ObserveProcessId,
 [Parameter(Mandatory,ParameterSetName="Launch")][string]$ProtocolDirectory,
 [Parameter(Mandatory,ParameterSetName="Launch")][ValidatePattern('^[a-f0-9]{32}$')][string]$Token,
 [Parameter(Mandatory,ParameterSetName="Launch")][int]$OwnerProcessId,
 [Parameter(Mandatory,ParameterSetName="Launch")][ValidatePattern('^[a-f0-9]{64}$')][string]$OwnerSha256
)
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
public sealed class ContainedNativeJob : IDisposable  {
    [StructLayout(LayoutKind.Sequential)] struct IO  {
        public ulong ReadOperationCount,WriteOperationCount,OtherOperationCount,ReadTransferCount,WriteTransferCount,OtherTransferCount;
    }
    [StructLayout(LayoutKind.Sequential)] struct BasicLimit  {
        public long PerProcessUserTimeLimit,PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize,MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass,SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)] struct ExtendedLimit  {
        public BasicLimit Basic;
        public IO Io;
        public UIntPtr ProcessMemoryLimit,JobMemoryLimit,PeakProcessMemoryUsed,PeakJobMemoryUsed;
    }
    [StructLayout(LayoutKind.Sequential)] struct Accounting  {
        public long TotalUserTime,TotalKernelTime,ThisPeriodTotalUserTime,ThisPeriodTotalKernelTime;
        public uint PageFaultCount,TotalProcesses,ActiveProcesses,TotalTerminatedProcesses;
    }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Startup  {
        public int cb;
        public string reserved,desktop,title;
        public uint x,y,xSize,ySize,xCountChars,yCountChars,fillAttribute,flags;
        public short showWindow,reserved2;
        public IntPtr reservedPtr,input,output,error;
    }
    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes  {
        public int length;
        public IntPtr descriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool inherit;
    }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo  {
        public IntPtr process,thread;
        public uint processId,threadId;
    }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes,string name);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,ref ExtendedLimit info,uint size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int kind,out Accounting info,uint size,IntPtr returned);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string application,System.Text.StringBuilder command,IntPtr processAttributes,IntPtr threadAttributes,bool inherit,uint flags,IntPtr environment,string directory,ref Startup startup,out ProcessInfo process);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFile(string name,uint access,uint share,ref SecurityAttributes attributes,uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    IntPtr job=IntPtr.Zero,process=IntPtr.Zero,thread=IntPtr.Zero;
    public uint ProcessId  {
        get;
        private set;
    }
    static void Require(bool ok) {
        if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    public static void AssertAbi() {
        if(IntPtr.Size!=8 || Marshal.SizeOf(typeof(Startup))!=104 || Marshal.SizeOf(typeof(ProcessInfo))!=24 || Marshal.SizeOf(typeof(Accounting))!=48 || Marshal.SizeOf(typeof(ExtendedLimit))!=144 || Marshal.SizeOf(typeof(BasicLimit))!=64 || Marshal.SizeOf(typeof(SecurityAttributes))!=24 || Marshal.OffsetOf(typeof(Startup),"input").ToInt64()!=80 || Marshal.OffsetOf(typeof(ProcessInfo),"processId").ToInt64()!=16 || Marshal.OffsetOf(typeof(Accounting),"ActiveProcesses").ToInt64()!=40 || Marshal.OffsetOf(typeof(ExtendedLimit),"ProcessMemoryLimit").ToInt64()!=112)throw new Exception("Unsupported native process-job ABI");
    }
    public ContainedNativeJob(string executable,string commandLine,string directory) : this(executable,commandLine,directory,null,null) {}
    public ContainedNativeJob(string executable,string commandLine,string directory,string outputPath,string errorPath) {
        AssertAbi();
        job=CreateJobObject(IntPtr.Zero,null);
        Require(job!=IntPtr.Zero);
        try  {
            var limits=new ExtendedLimit();
            limits.Basic.LimitFlags=0x2000;
            Require(SetInformationJobObject(job,9,ref limits,(uint)Marshal.SizeOf(typeof(ExtendedLimit))));
            var startup=new Startup();
            startup.cb=Marshal.SizeOf(typeof(Startup));
            ProcessInfo child;
            var attributes=new SecurityAttributes();
            attributes.length=Marshal.SizeOf(typeof(SecurityAttributes));
            attributes.inherit=true;
            IntPtr nullFile=CreateFile("NUL",0xc0000000,3,ref attributes,3,0x80,IntPtr.Zero);
            Require(nullFile!=new IntPtr(-1));
            startup.flags=0x100;
            startup.input=nullFile;
            startup.output=nullFile;
            startup.error=nullFile;
            IntPtr outputFile=IntPtr.Zero,errorFile=IntPtr.Zero;
            try  {
                // Optional fixture-only byte capture. The caller owns and pins
                // the private directory, bounds output, and waits for the entire
                // retained job before reading. Ordinary launches still use NUL.
                if(outputPath!=null || errorPath!=null) {
                    Require(outputPath!=null && errorPath!=null);
                    outputFile=CreateFile(outputPath,0x40000000,1,ref attributes,1,0x80,IntPtr.Zero);
                    Require(outputFile!=new IntPtr(-1));
                    errorFile=CreateFile(errorPath,0x40000000,1,ref attributes,1,0x80,IntPtr.Zero);
                    Require(errorFile!=new IntPtr(-1));
                    startup.output=outputFile; startup.error=errorFile;
                }
                Require(CreateProcess(executable,new System.Text.StringBuilder(commandLine),IntPtr.Zero,IntPtr.Zero,true,0x08000004,IntPtr.Zero,directory,ref startup,out child));
            }
            finally  {
                if(outputFile!=IntPtr.Zero && outputFile!=new IntPtr(-1))Require(CloseHandle(outputFile));
                if(errorFile!=IntPtr.Zero && errorFile!=new IntPtr(-1))Require(CloseHandle(errorFile));
                Require(CloseHandle(nullFile));
            }
            process=child.process;
            thread=child.thread;
            ProcessId=child.processId;
            try  {
                if(!AssignProcessToJobObject(job,process)) {
                    int error=Marshal.GetLastWin32Error();
                    Require(TerminateProcess(process,1));
                    if(WaitForSingleObject(process,30000)!=0)throw new Exception("Unassigned suspended child did not drain");
                    throw new Win32Exception(error);
                }
                // The external owner verifies the suspended identity before Resume().
            }
            finally  {
                // Retained until explicit resume or verified drainage.
            }
        }
        catch  {
            Dispose();
            throw;
        }
    }
    public void Resume() {
        if(thread==IntPtr.Zero || ResumeThread(thread)==0xffffffff)throw new Exception("Owned resume refused");
        Require(CloseHandle(thread)); thread=IntPtr.Zero;
    }
    public static string Render(string executable,string[] args) {
        var values=new System.Collections.Generic.List<string>(); values.Add(executable); values.AddRange(args);
        var result=new System.Text.StringBuilder();
        foreach(string value in values) {
            if(result.Length>0)result.Append(' '); result.Append('"'); int slashes=0;
            foreach(char ch in value) {
                if(ch=='\\'){slashes++;continue;}
                if(ch=='"'){result.Append('\\',slashes*2+1);result.Append(ch);slashes=0;continue;}
                result.Append('\\',slashes);slashes=0;result.Append(ch);
            }
            result.Append('\\',slashes*2);result.Append('"');
        }
        return result.ToString();
    }
    public bool RootExited  {
        get  {
            return WaitForSingleObject(process,0)==0;
        }
    }
    public uint Active  {
        get  {
            Accounting value;
            Require(QueryInformationJobObject(job,1,out value,(uint)Marshal.SizeOf(typeof(Accounting)),IntPtr.Zero));
            return value.ActiveProcesses;
        }
    }
    public uint Drain() {
        if(Active!=0)Require(TerminateJobObject(job,1));
        var deadline=DateTime.UtcNow.AddSeconds(30);
        while(Active!=0) {
            if(DateTime.UtcNow>=deadline)throw new Exception("Owned native job did not drain");
            Thread.Sleep(20);
        }
        if(WaitForSingleObject(process,30000)!=0)throw new Exception("Owned root did not close");
        uint code;
        Require(GetExitCodeProcess(process,out code));
        return code;
    }
    public void CloseVerified() {
        if(Active!=0 || !RootExited)throw new Exception("Native closure refused");
        if(thread!=IntPtr.Zero){Require(CloseHandle(thread));thread=IntPtr.Zero;}
        Require(CloseHandle(process));process=IntPtr.Zero;
        Require(CloseHandle(job));job=IntPtr.Zero;
    }
    public void Dispose() {
        if(thread!=IntPtr.Zero){CloseHandle(thread);thread=IntPtr.Zero;}
        if(job!=IntPtr.Zero) {
            CloseHandle(job);
            job=IntPtr.Zero;
        }
        if(process!=IntPtr.Zero) {
            CloseHandle(process);
            process=IntPtr.Zero;
        }
    }
}

// Separate read-only handle observer: a suspended process need not expose argv to CIM.
public sealed class ContainedNativeIdentity {
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr h,uint flags,System.Text.StringBuilder image,ref uint size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr h,out long created,out long exited,out long kernel,out long user);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint GetProcessId(IntPtr h);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr h,uint access,out IntPtr token);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr h);
    public uint pid; public string creationTime,executablePath,sid;
    public static ContainedNativeIdentity Observe(int id) {
        IntPtr process=OpenProcess(0x1000,false,id),token=IntPtr.Zero;
        if(process==IntPtr.Zero)throw new Exception("Native identity open refused");
        try {
            uint size=32768;var image=new System.Text.StringBuilder((int)size);long created,exited,kernel,user;
            if(!QueryFullProcessImageName(process,0,image,ref size)||!GetProcessTimes(process,out created,out exited,out kernel,out user)||!OpenProcessToken(process,8,out token))throw new Exception("Native identity read refused");
            using(var identity=new System.Security.Principal.WindowsIdentity(token)) {
                return new ContainedNativeIdentity {pid=GetProcessId(process),creationTime=DateTime.FromFileTimeUtc(created).ToString("o"),executablePath=image.ToString(),sid=identity.User.Value};
            }
        } finally {
            bool tokenClosed=token==IntPtr.Zero||CloseHandle(token);bool processClosed=CloseHandle(process);
            if(!tokenClosed||!processClosed)throw new Exception("Native observer close refused");
        }
    }
}
public sealed class ContainedParent : IDisposable {
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h,uint ms);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    IntPtr handle;
    public ContainedParent(int pid){handle=OpenProcess(0x101000,false,pid);if(handle==IntPtr.Zero)throw new Exception("Parent retention refused");}
    public bool Alive {get {uint value=WaitForSingleObject(handle,0);if(value!=0 && value!=258)throw new Exception("Parent wait refused");return value==258;}}
    public void Dispose(){if(handle!=IntPtr.Zero){if(!CloseHandle(handle))throw new Exception("Parent close refused");handle=IntPtr.Zero;}}
}
'@
if($PSCmdlet.ParameterSetName -eq 'Observe') {
 if($ObserveProcessId -le 0){throw 'Observer PID refused'}
 $observed=[ContainedNativeIdentity]::Observe($ObserveProcessId)
 [Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
 @{pid=$observed.pid;creationTime=$observed.creationTime;executablePath=$observed.executablePath;sid=$observed.sid}|ConvertTo-Json -Compress
 return
}
function Assert-Fields($value,[string[]]$names) {
 $actual=@($value.PSObject.Properties.Name | Sort-Object)
 if(($actual -join '|') -cne (($names | Sort-Object) -join '|')){throw 'Closed protocol shape refused'}
}
function Assert-Ancestry([string]$path) {
 $current=[IO.Path]::GetFullPath($path)
 while($current) {
  $item=Get-Item -LiteralPath $current -Force
  if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse ancestry refused'}
  $next=Split-Path -Parent $current
  if($next -eq $current){break}
  $current=$next
 }
}
function Open-Manifest([string]$name) {
 $path=Join-Path $ProtocolDirectory $name
 $item=Get-Item -LiteralPath $path -Force
 if($item.Attributes -band [IO.FileAttributes]::ReparsePoint -or $item.PSIsContainer){throw 'Manifest type refused'}
 $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try {
  if($stream.Length -lt 2 -or $stream.Length -gt 65536){throw 'Manifest size refused'}
  $bytes=New-Object byte[] ([int]$stream.Length)
  if($stream.Read($bytes,0,$bytes.Length) -ne $bytes.Length){throw 'Manifest read refused'}
  if($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191){throw 'Manifest encoding refused'}
  $encoding=New-Object Text.UTF8Encoding($false,$true)
  $sha=[Security.Cryptography.SHA256]::Create()
  try{$digest=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  return @{stream=$stream;value=($encoding.GetString($bytes)|ConvertFrom-Json);sha256=$digest}
 }catch{$stream.Dispose();throw}
}
function Publish([string]$name,$value) {
 $path=Join-Path $ProtocolDirectory $name
 $temporary=$path+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
 $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes(($value|ConvertTo-Json -Depth 6 -Compress))
 $file=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 [IO.File]::Move($temporary,$path)
}
function Gate([string]$name) {
 $path=Join-Path $ProtocolDirectory $name
 if(!(Test-Path -LiteralPath $path)){return $false}
 $item=Get-Item -LiteralPath $path -Force
 if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -ne 32){throw 'Gate identity refused'}
 if([IO.File]::ReadAllText($path) -cne $Token){throw 'Gate token refused'}
 return $true
}
function Sid($process) {
 $result=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
 if($result.ReturnValue -ne 0 -or !$result.Sid){throw 'Process SID refused'}
 return [string]$result.Sid
}
function Wait-Gate([string]$name) {
 $deadline=[DateTime]::UtcNow.AddSeconds(30)
 while(!(Gate $name)) {
  if((Gate 'stop') -or !$parent.Alive -or [DateTime]::UtcNow -ge $deadline){return $false}
  Start-Sleep -Milliseconds 20
 }
 return $true
}
$ownerManifest=$null;$launchManifest=$null;$parent=$null;$job=$null;$closed=$false
$rootPid=$null;$rootCode=$null;$launched=$false;$executableLock=$null
$failureStage="owner";$diagnosticOwned=$false
try {
 Assert-Ancestry $ProtocolDirectory
 foreach($directory in @($ProtocolDirectory,(Split-Path -Parent $ProtocolDirectory))) {
  $item=Get-Item -LiteralPath $directory -Force
  if(!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Protocol directory refused'}
 }
 $ownerManifest=Open-Manifest 'owner.json';$context=$ownerManifest.value
 Assert-Fields $context @('schemaVersion','kind','token','ownerPid','executable','executableSha256','driverSha256','maxLifetimeMs','cwd')
 if($ownerManifest.sha256 -cne $OwnerSha256 -or $context.schemaVersion -ne 1 -or $context.kind -cne 'certops-contained-native-test-process' -or $context.token -cne $Token -or $context.ownerPid -ne $OwnerProcessId -or $context.maxLifetimeMs -lt 5000 -or $context.maxLifetimeMs -gt 3600000){throw 'Owner context refused'}
 if((Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $context.driverSha256){throw 'Driver identity refused'}
 $self=Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
 $owner=Get-CimInstance Win32_Process -Filter "ProcessId=$OwnerProcessId"
 if(!$owner -or $self.ParentProcessId -ne $OwnerProcessId){throw 'Wrapper parent refused'}
 $sid=Sid $self
 if($sid -cne (Sid $owner)){throw 'Owner SID refused'}
 $parent=[ContainedParent]::new($OwnerProcessId)
 $retainedOwner=Get-CimInstance Win32_Process -Filter "ProcessId=$OwnerProcessId"
 if(!$parent.Alive -or !$retainedOwner -or $retainedOwner.CreationDate -ne $owner.CreationDate -or (Sid $retainedOwner) -cne $sid){throw 'Owner exited or changed'}
$diagnosticOwned=$true;$failureStage='wait-run'
 Publish 'ready.json' @{token=$Token;wrapperPid=$PID;ownerPid=$OwnerProcessId;creationTime=$self.CreationDate.ToUniversalTime().ToString('o');ownerCreationTime=$owner.CreationDate.ToUniversalTime().ToString('o');sid=$sid}
 if(Wait-Gate 'run') {
  $failureStage='launch-manifest'
  $launchManifest=Open-Manifest 'launch.json';$launch=$launchManifest.value
  Assert-Fields $launch @('token','executable','args','commandLine','cwd')
  if($launch.token -cne $Token -or $launch.executable -cne $context.executable -or $launch.cwd -cne $context.cwd -or $launch.args -isnot [Array] -or $launch.args.Count -gt 64){throw 'Launch context refused'}
  foreach($value in @($launch.executable,$launch.cwd,$launch.commandLine)+@($launch.args)){if($value -isnot [string] -or $value.Length -gt 32767 -or $value -match '[\x00-\x1f]'){throw 'Launch value refused'}}
  $failureStage='executable-lock'
  $executableLock=[IO.File]::Open($launch.executable,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  $executable=Get-Item -LiteralPath $launch.executable -Force
  $directory=Get-Item -LiteralPath $launch.cwd -Force
  if($executable.PSIsContainer -or !$directory.PSIsContainer -or ($executable.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -or (Get-FileHash -LiteralPath $launch.executable -Algorithm SHA256).Hash.ToLowerInvariant() -cne $context.executableSha256){throw 'Launch filesystem identity refused'}
  $failureStage='command-render'
  if([ContainedNativeJob]::Render($launch.executable,[string[]]$launch.args) -cne $launch.commandLine){throw 'Command rendering refused'}
  $failureStage='launch-ancestry'
  Assert-Ancestry $launch.executable
  Assert-Ancestry $launch.cwd
  if(!$parent.Alive -or (Gate 'stop')){throw 'Owner stopped before native launch'}
  $failureStage='native-create'
  $job=[ContainedNativeJob]::new($launch.executable,$launch.commandLine,$launch.cwd)
  $rootPid=$job.ProcessId;$launched=$true
  $failureStage='suspended-identity'
  $child=Get-CimInstance Win32_Process -Filter "ProcessId=$rootPid"
  $native=[ContainedNativeIdentity]::Observe([int]$rootPid)
  if(!$child -or $child.ParentProcessId -ne $PID -or $native.pid -ne $rootPid -or $native.executablePath -ine $launch.executable -or $native.sid -cne $sid -or $native.creationTime.Substring(0,26) -cne $child.CreationDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.ffffff')){throw 'Suspended native handle identity refused'}
  $failureStage='publish-started'
  Publish 'started.json' @{token=$Token;wrapperPid=$PID;ownerPid=$OwnerProcessId;pid=$rootPid;parentPid=$PID;creationTime=$native.creationTime;executablePath=$native.executablePath;commandLine=$launch.commandLine;commandLineOrigin='sealed-createprocess-input';sid=$native.sid;nativeSuspended=$true;jobAssignedBeforeResume=$true}
  $failureStage='wait-resume'
  if((Wait-Gate 'resume') -and $parent.Alive -and !(Gate 'stop')) {
  $failureStage='native-resume'
   $job.Resume()
   Publish 'running.json' @{token=$Token;pid=$rootPid;jobAssignedBeforeResume=$true}
   $deadline=[DateTime]::UtcNow.AddMilliseconds([double]$context.maxLifetimeMs)
   while(!$job.RootExited -and $parent.Alive -and !(Gate 'stop') -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 20}
  }
  $failureStage='native-drain'
  $rootCode=$job.Drain()
  $job.CloseVerified();$job=$null
 }
 if($executableLock){$executableLock.Dispose();$executableLock=$null}
 if($launchManifest){$launchManifest.stream.Dispose();$launchManifest=$null}
 $ownerManifest.stream.Dispose();$ownerManifest=$null
 $parent.Dispose();$parent=$null
 Publish 'closed.json' @{token=$Token;wrapperPid=$PID;ownerPid=$OwnerProcessId;nativeRootPid=$rootPid;rootExitCode=$rootCode;launchOccurred=$launched;activeNativeProcesses=0;retainedJobDrained=$true;nativeRootExited=$true;nativeHandlesClosed=$true}
 $closed=$true
} catch {
 # Diagnostics never assert closure and contain no exception message or arguments.
 if($diagnosticOwned){try{
  $errorValue=$_.Exception
  while($errorValue.InnerException){$errorValue=$errorValue.InnerException}
  $nativeCode=$null
  $cursor=$errorValue
  while($cursor){if($cursor -is [ComponentModel.Win32Exception]){$nativeCode=[int]$cursor.NativeErrorCode;break};$cursor=$cursor.InnerException}
  Publish 'failed.json' @{schemaVersion=1;token=$Token;wrapperPid=$PID;ownerPid=$OwnerProcessId;stage=$failureStage;exceptionType=$errorValue.GetType().FullName;hresult=[int]$errorValue.HResult;nativeErrorCode=$nativeCode}
 }catch{}}
 throw
} finally {
 # Emergency disposal invokes kill-on-close, but deliberately publishes NO drain proof.
 if($job){$job.Dispose()}
 if($executableLock){$executableLock.Dispose()}
 if($launchManifest){$launchManifest.stream.Dispose()}
 if($ownerManifest){$ownerManifest.stream.Dispose()}
 if($parent){$parent.Dispose()}
}
if(!$closed){throw 'Native containment incomplete'}
