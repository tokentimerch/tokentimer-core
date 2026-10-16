<# Test-only retained native job for a background worker controller.
The controller starts suspended, joins a kill-on-close Job Object and only
then launches the unmodified worker CLI. Exact nonce commands govern launch
and emergency drainage; graceful worker shutdown is requested separately.
A closed receipt requires zero job members. No PID-only termination. #>
param(
    [Parameter(Mandatory)][string]$NodePath,
    [Parameter(Mandatory)][string]$Entry,
    [Parameter(Mandatory)][string]$ProtocolDirectory,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$Token,
    [Parameter(Mandatory)][int]$OwnerProcessId
)
$ErrorActionPreference='Stop'
if($NodePath.Contains('"') -or $Entry.Contains('"')){throw 'Quoted paths unsupported'}
$protocol=Get-Item -LiteralPath $ProtocolDirectory
if(-not $protocol.PSIsContainer -or ($protocol.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Owned worker protocol directory required'}
$ownerMarker=Join-Path $ProtocolDirectory 'ownership.json'
$marker=Get-Item -LiteralPath $ownerMarker
if($marker.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse ownership receipt refused'}
$ownership=Get-Content -LiteralPath $ownerMarker -Raw|ConvertFrom-Json
if($ownership.nonce -cne $Token -or $ownership.controllerSha256 -cne (Get-FileHash -LiteralPath $Entry -Algorithm SHA256).Hash.ToLowerInvariant()){throw 'Worker ownership/source mismatch'}
$self=Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
$owner=Get-CimInstance Win32_Process -Filter "ProcessId=$OwnerProcessId"
if(!$owner -or $self.ParentProcessId -ne $OwnerProcessId){throw 'Wrapper parent mismatch'}
$ownerCreation=$owner.CreationDate.ToUniversalTime().ToString('o')
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
public sealed class OwnedRunnerJob : IDisposable  {
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
    IntPtr job=IntPtr.Zero,process=IntPtr.Zero;
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
    public OwnedRunnerJob(string node,string entry) {
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
            try  {
                Require(CreateProcess(node,new System.Text.StringBuilder("\""+node+"\" \""+entry+"\""),IntPtr.Zero,IntPtr.Zero,true,0x08000004,IntPtr.Zero,System.IO.Path.GetDirectoryName(entry),ref startup,out child));
            }
            finally  {
                CloseHandle(nullFile);
            }
            process=child.process;
            ProcessId=child.processId;
            try  {
                if(!AssignProcessToJobObject(job,process)) {
                    int error=Marshal.GetLastWin32Error();
                    Require(TerminateProcess(process,1));
                    if(WaitForSingleObject(process,30000)!=0)throw new Exception("Unassigned suspended child did not drain");
                    throw new Win32Exception(error);
                }
                if(ResumeThread(child.thread)==0xffffffff)throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            finally  {
                CloseHandle(child.thread);
            }
        }
        catch  {
            Dispose();
            throw;
        }
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
        Require(TerminateJobObject(job,1));
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
    public void Dispose() {
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
'@
@{token=$Token;wrapperPid=$PID;ownerPid=$OwnerProcessId;creationTime=$self.CreationDate.ToUniversalTime().ToString('o')} | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $ProtocolDirectory 'ready.json')
$deadline=[DateTime]::UtcNow.AddSeconds(30)
while(!(Test-Path -LiteralPath (Join-Path $ProtocolDirectory 'run'))){
 $live=Get-CimInstance Win32_Process -Filter "ProcessId=$OwnerProcessId"
 if(!$live -or $live.CreationDate.ToUniversalTime().ToString('o') -ne $ownerCreation){throw 'Parent exited before launch'}
 if([DateTime]::UtcNow -ge $deadline){throw 'Owned launch gate expired'}
 Start-Sleep -Milliseconds 20
}
if([IO.File]::ReadAllText((Join-Path $ProtocolDirectory 'run')) -ne $Token){throw 'Launch token mismatch'}
$job=$null
try {
 $job=[OwnedRunnerJob]::new($NodePath,$Entry)
 $deadline=[DateTime]::UtcNow.AddSeconds(600)
 while(!$job.RootExited){
  $stop=Join-Path $ProtocolDirectory 'stop'
  if(Test-Path -LiteralPath $stop){if([IO.File]::ReadAllText($stop) -ne $Token){throw 'Stop token mismatch'};break}
  $live=Get-CimInstance Win32_Process -Filter "ProcessId=$OwnerProcessId"
  if(!$live -or $live.CreationDate.ToUniversalTime().ToString('o') -ne $ownerCreation){break}
  if([DateTime]::UtcNow -ge $deadline){break}
  Start-Sleep -Milliseconds 20
 }
 $exitCode=$job.Drain()
 if($job.Active -ne 0){throw 'Owned descendants remain'}
 @{token=$Token;wrapperPid=$PID;ownerPid=$OwnerProcessId;nativeRootPid=$job.ProcessId;rootExitCode=$exitCode;activeNativeProcesses=0;retainedJobDrained=$true} | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $ProtocolDirectory 'closed.json')
} finally {if($job){$job.Dispose()}}
