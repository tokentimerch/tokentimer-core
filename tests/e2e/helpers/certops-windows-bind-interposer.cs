// Fixture-only netsh executable. Compiled beside the reviewed retained Job
// Object launcher; never installed or shipped with the product. Every child
// receives original argv and must actually exit before its native code returns.
public static class CertOpsBindInterposer {
    static string LastNativeOutput="";
    public static bool SameNativePath(string left,string right) { return System.IO.Path.GetFullPath(left).Equals(System.IO.Path.GetFullPath(right),System.StringComparison.OrdinalIgnoreCase); }
    public static int ParseNativeError(string output) {
        var matches=System.Text.RegularExpressions.Regex.Matches(output,@"(?m)^SSL Certificate add failed, Error:[ \t]*(?<code>[0-9]{1,10})[ \t]*\r?$");
        int code;
        if(matches.Count!=1 || !int.TryParse(matches[0].Groups["code"].Value,out code))throw new System.Exception("One actual native error line required");
        return code;
    }
    static readonly System.Web.Script.Serialization.JavaScriptSerializer Json = new System.Web.Script.Serialization.JavaScriptSerializer();
    static string Read(string file) {
        var info = new System.IO.FileInfo(file);
        if (!info.Exists || info.Length > 65536 || (info.Attributes & System.IO.FileAttributes.ReparsePoint) != 0) throw new System.Exception("Owned fixture file required");
        return System.IO.File.ReadAllText(file);
    }
    static string Hash(string file) {
        using (var stream = System.IO.File.Open(file,System.IO.FileMode.Open,System.IO.FileAccess.Read,System.IO.FileShare.Read))
        using (var hash = System.Security.Cryptography.SHA256.Create()) return System.BitConverter.ToString(hash.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
    }
    static string Field(System.Collections.Generic.Dictionary<string,object> value,string name) { return (string)value[name]; }
    static int Native(string executable,string[] args,string directory,bool forward=true) {
        var output=System.IO.Path.Combine(directory,System.Guid.NewGuid().ToString("N")+".stdout");
        var error=System.IO.Path.Combine(directory,System.Guid.NewGuid().ToString("N")+".stderr");
        using (var child = new ContainedNativeJob(executable,ContainedNativeJob.Render(executable,args),directory,output,error)) {
            child.Resume(); var deadline=System.DateTime.UtcNow.AddSeconds(45);
            while (!child.RootExited || child.Active != 0) {
                if (System.DateTime.UtcNow >= deadline) { child.Drain(); throw new System.Exception("Native netsh deadline; preserve fixture"); }
                if(new System.IO.FileInfo(output).Length>1048576 || new System.IO.FileInfo(error).Length>1048576){child.Drain();throw new System.Exception("Native output overflow; preserve fixture");}
                System.Threading.Thread.Sleep(10);
            }
            var code=child.Drain(); child.CloseVerified();
            if(new System.IO.FileInfo(output).Length>1048576 || new System.IO.FileInfo(error).Length>1048576)throw new System.Exception("Native output overflow; preserve fixture");
            var stdout=System.IO.File.ReadAllBytes(output);var stderr=System.IO.File.ReadAllBytes(error);
            LastNativeOutput=System.Text.Encoding.UTF8.GetString(stdout)+System.Text.Encoding.UTF8.GetString(stderr);
            if(forward){System.Console.OpenStandardOutput().Write(stdout,0,stdout.Length);System.Console.OpenStandardError().Write(stderr,0,stderr.Length);}
            System.IO.File.Delete(output);System.IO.File.Delete(error);
            return checked((int)code);
        }
    }
    static string Argument(string[] args,string name) {
        string result=null;
        foreach(var arg in args) if(arg.StartsWith(name+"=",System.StringComparison.OrdinalIgnoreCase)) {
            if(result!=null)throw new System.Exception("Duplicate native selector"); result=arg.Substring(name.Length+1);
        }
        return result;
    }
    public static int Main(string[] args) {
        try {
            if(System.Security.Principal.WindowsIdentity.GetCurrent().User.Value!="S-1-5-18")throw new System.Exception("SYSTEM fixture required");
            var contextPath=System.Environment.GetEnvironmentVariable("CERTOPS_BIND_INTERPOSER_CONTEXT");
            var directory=System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
            if(!System.Text.RegularExpressions.Regex.IsMatch(System.IO.Path.GetFileName(directory),@"^\.bind-failure-interposer-[a-f0-9]{32}$") || !SameNativePath(contextPath,System.IO.Path.Combine(directory,"context.json")))throw new System.Exception("Exact original fixture context required");
            var ctx=Json.Deserialize<System.Collections.Generic.Dictionary<string,object>>(Read(contextPath));
            var executable=Field(ctx,"netsh");
            if(!SameNativePath(executable,System.IO.Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.System),"netsh.exe")) || Hash(executable)!=Field(ctx,"netshSha256"))throw new System.Exception("Original System32 netsh required");
            var isAdd=args.Length>=6 && args[0]=="http" && args[1]=="add" && args[2]=="sslcert";
            var selector=Argument(args,"hostnameport"); var hash=Argument(args,"certhash");
            if(!isAdd || selector!=Field(ctx,"selector") || hash==null || hash.Equals(Field(ctx,"predecessor"),System.StringComparison.OrdinalIgnoreCase) || System.IO.File.Exists(System.IO.Path.Combine(directory,"consumed.json"))) return Native(executable,args,directory);
            if(!System.Text.RegularExpressions.Regex.IsMatch(hash,"^[A-Fa-f0-9]{40}$") || Argument(args,"certstorename")!="My")throw new System.Exception("Exact owned My candidate required");
            var admission=System.IO.Path.Combine(directory,"admission.json");var deadline=System.DateTime.UtcNow.AddSeconds(20);
            while(!System.IO.File.Exists(admission)){if(System.DateTime.UtcNow>=deadline)throw new System.Exception("Public job admission missing");System.Threading.Thread.Sleep(10);}
            var job=Json.Deserialize<System.Collections.Generic.Dictionary<string,object>>(Read(admission));
            var jobId=Field(job,"jobId");
            if(!System.Text.RegularExpressions.Regex.IsMatch(jobId,"^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$"))throw new System.Exception("Owned public job required");
            bool accepted=false;
            foreach(var file in System.IO.Directory.GetFiles(Field(ctx,"issuedDirectory"),"*.json")) {
                var receipt=Json.Deserialize<System.Collections.Generic.Dictionary<string,object>>(Read(file));
                if(receipt.ContainsKey("jobId") && Field(receipt,"jobId")==jobId && receipt.ContainsKey("acceptedThumbprint") && Field(receipt,"acceptedThumbprint").Equals(hash,System.StringComparison.OrdinalIgnoreCase)) {
                    if(accepted)throw new System.Exception("Ambiguous accepted receipt");accepted=true;
                }
            }
            if(!accepted)throw new System.Exception("Accepted current-job receipt required");
            string candidateFingerprint=null,predecessorFingerprint=null;
            using(var store=new System.Security.Cryptography.X509Certificates.X509Store("My",System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine)) {
                store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);
                foreach(var thumb in new[]{hash,Field(ctx,"predecessor")}) {
                    var matches=store.Certificates.Find(System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint,thumb,false);
                    if(matches.Count!=1 || !matches[0].HasPrivateKey)throw new System.Exception("Original and accepted native custody required");
                    using(var h=System.Security.Cryptography.SHA256.Create()) {
                        var fingerprint=System.BitConverter.ToString(h.ComputeHash(matches[0].RawData)).Replace("-","").ToLowerInvariant();
                        if(thumb==hash)candidateFingerprint=fingerprint;else predecessorFingerprint=fingerprint;
                    }
                }
            }
            // Reserve this single injection before native mutation. Never edit
            // the store/key. The duplicate is the same owned predecessor binding.
            using(var reservation=new System.IO.FileStream(System.IO.Path.Combine(directory,"consumed.json"),System.IO.FileMode.CreateNew,System.IO.FileAccess.Write,System.IO.FileShare.None)) {
                var bytes=System.Text.Encoding.UTF8.GetBytes(Json.Serialize(new{jobId=jobId,candidate=hash}));reservation.Write(bytes,0,bytes.Length);reservation.Flush(true);
            }
            var seed=(string[])args.Clone();
            for(int i=0;i<seed.Length;i++) {
                if(seed[i].StartsWith("certhash=",System.StringComparison.OrdinalIgnoreCase))seed[i]="certhash="+Field(ctx,"predecessor");
                if(seed[i].StartsWith("appid=",System.StringComparison.OrdinalIgnoreCase))seed[i]="appid={"+Field(ctx,"appId")+"}";
            }
            int seedExit=Native(executable,seed,directory,false);
            if(seedExit!=0)throw new System.Exception("Owned duplicate binding not admitted");
            int actualExit=Native(executable,args,directory);
            int nativeErrorCode=ParseNativeError(LastNativeOutput);
            if(actualExit==0 || nativeErrorCode!=183)throw new System.Exception("Actual duplicate-binding native error required");
            var proof=new{jobId=jobId,selector=selector,candidateThumbprint=hash.ToUpperInvariant(),predecessorThumbprint=Field(ctx,"predecessor"),candidateFingerprintSha256=candidateFingerprint,predecessorFingerprintSha256=predecessorFingerprint,seedExitCode=seedExit,forwardedExitCode=actualExit,nativeErrorCode=nativeErrorCode,originalArgv=args,originalArgvSha256=Digest(Json.Serialize(args)),systemNetshSha256=Field(ctx,"netshSha256"),nativeChildrenDrained=true,captureOverflow=false,drainFailure=false,certificateStoreModified=false};
            using(var output=new System.IO.FileStream(System.IO.Path.Combine(directory,"native-result.json"),System.IO.FileMode.CreateNew,System.IO.FileAccess.Write,System.IO.FileShare.None)) {
                var bytes=System.Text.Encoding.UTF8.GetBytes(Json.Serialize(proof));output.Write(bytes,0,bytes.Length);output.Flush(true);
            }
            return actualExit;
        } catch { return 197; } // No successful receipt on an unknown native state.
    }
    static string Digest(string value) { using(var h=System.Security.Cryptography.SHA256.Create())return System.BitConverter.ToString(h.ComputeHash(System.Text.Encoding.UTF8.GetBytes(value))).Replace("-","").ToLowerInvariant(); }
}
