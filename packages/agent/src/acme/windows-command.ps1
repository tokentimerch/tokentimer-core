# Own one ACME command tree. The child is suspended until assigned to a
# kill-on-close Job Object, so launcher exit or wrapper termination cannot orphan it.
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
try {
  $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
  Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
public static class OwnedAcmeCommand {
  [StructLayout(LayoutKind.Sequential)] struct Startup {
    public int cb; public IntPtr reserved, desktop, title;
    public int x,y,width,height,xChars,yChars,fill,flags;
    public short show,reservedSize; public IntPtr reservedData,input,output,error;
  }
  [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr process,thread; public int pid,tid; }
  [StructLayout(LayoutKind.Sequential)] struct Limits {
    public long processTime,jobTime; public uint flags; public UIntPtr min,max;
    public uint processes; public UIntPtr affinity; public uint priority,scheduling;
  }
  [StructLayout(LayoutKind.Sequential)] struct Counters { public ulong a,b,c,d,e,f; }
  [StructLayout(LayoutKind.Sequential)] struct Extended {
    public Limits basic; public Counters io; public UIntPtr processMemory,jobMemory,peakProcess,peakJob;
  }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attrs,string name);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int type,ref Extended info,int size);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateProcess(string app,StringBuilder cmd,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string cwd,ref Startup startup,out ProcessInfo info);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
  [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
  [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint timeout);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
  [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr process,uint code);
  [DllImport("kernel32.dll")] static extern bool TerminateJobObject(IntPtr job,uint code);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int kind);
  static void Check(bool ok) { if(!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
  // Windows argv quoting: backslashes are doubled only before a quote or the closing quote.
  static string Quote(string value) {
    var s=new StringBuilder("\""); int slashes=0;
    foreach(char c in value) {
      if(c=='\\') { slashes++; continue; }
      if(c=='"') { s.Append('\\',slashes*2+1); s.Append(c); }
      else { s.Append('\\',slashes); s.Append(c); }
      slashes=0;
    }
    s.Append('\\',slashes*2); return s.Append('"').ToString();
  }
  public static int Run(string executable,string[] args) {
    IntPtr job=CreateJobObject(IntPtr.Zero,null); Check(job!=IntPtr.Zero);
    var process=new ProcessInfo(); bool assigned=false;
    try {
      var limits=new Extended(); limits.basic.flags=0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
      Check(SetInformationJobObject(job,9,ref limits,Marshal.SizeOf(typeof(Extended))));
      var startup=new Startup(); startup.cb=Marshal.SizeOf(typeof(Startup)); startup.flags=0x100;
      startup.input=GetStdHandle(-10); startup.output=GetStdHandle(-11); startup.error=GetStdHandle(-12);
      var command=new StringBuilder(Quote(executable)); foreach(string arg in args) command.Append(' ').Append(Quote(arg));
      Check(CreateProcess(null,command,IntPtr.Zero,IntPtr.Zero,true,0x4|0x08000000,IntPtr.Zero,null,ref startup,out process));
      Check(AssignProcessToJobObject(job,process.process)); assigned=true;
      Check(ResumeThread(process.thread)!=0xffffffff);
      Check(WaitForSingleObject(process.process,0xffffffff)==0);
      uint code; Check(GetExitCodeProcess(process.process,out code)); return unchecked((int)code);
    } finally {
      if(assigned) TerminateJobObject(job,1);
      else if(process.process!=IntPtr.Zero) TerminateProcess(process.process,1);
      if(process.thread!=IntPtr.Zero) CloseHandle(process.thread);
      if(process.process!=IntPtr.Zero) CloseHandle(process.process);
      CloseHandle(job);
    }
  }
}
'@
  exit [OwnedAcmeCommand]::Run([string]$request.executable, [string[]]$request.arguments)
} catch {
  [Console]::Error.WriteLine('Owned ACME command wrapper failed')
  exit 1
}
