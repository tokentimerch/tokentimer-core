using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TokenTimerTests {
  public static class MaterialCustodyTests {
    const BindingFlags PrivateStatic = BindingFlags.NonPublic | BindingFlags.Static;
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct KeyProviderInfo {
      [MarshalAs(UnmanagedType.LPWStr)] public string Container;
      [MarshalAs(UnmanagedType.LPWStr)] public string Provider;
      public uint ProviderType, Flags, ParameterCount;
      public IntPtr Parameters;
      public uint KeySpec;
    }
    [DllImport("crypt32.dll", SetLastError=true)]
    static extern bool CertSetCertificateContextProperty(IntPtr cert,uint property,uint flags,ref KeyProviderInfo info);
    static void Require(bool condition,string code) { if(!condition)throw new Exception(code); }
    static byte[] Acl(CngKey key) { return key.GetProperty("Security Descr",(CngPropertyOptions)4).GetValue(); }
    static void SetAcl(CngKey key,string[] sids) {
      typeof(TokenTimer.MaterialImport).GetMethod("SetAcl",PrivateStatic).Invoke(null,new object[]{key,sids});
    }
    static void Policy(bool machine,bool ephemeral,CngExportPolicies exportPolicy,string provider,bool allowed) {
      bool rejected=false;
      try {
        typeof(TokenTimer.MaterialImport).GetMethod("CheckCustodyPolicy",PrivateStatic).Invoke(null,
          new object[]{machine,ephemeral,exportPolicy,new CngProvider(provider)});
      } catch(TargetInvocationException error) {
        if(!(error.InnerException is CryptographicException))throw;
        rejected=true;
      }
      Require(rejected!=allowed,"custody-policy-result");
    }
    public static void Run(string scenario) {
      if(scenario=="cng-provider-policy") {
        string software=CngProvider.MicrosoftSoftwareKeyStorageProvider.Provider;
        Policy(true,false,CngExportPolicies.None,software,true);
        Policy(true,false,CngExportPolicies.None,"Microsoft Platform Crypto Provider",false);
        Policy(true,false,CngExportPolicies.None,"Microsoft Smart Card Key Storage Provider",false);
        Policy(false,false,CngExportPolicies.None,software,false);
        Policy(true,true,CngExportPolicies.None,software,false);
        Policy(true,false,CngExportPolicies.AllowArchiving,software,false);
        return;
      }
      string name="TTReviewCustody"+Guid.NewGuid().ToString("N");
      var keys=new List<CngKey>();
      X509Certificate2 certificate=null;
      RSACryptoServiceProvider legacy=null;
      using(var destination=new X509Store(name,StoreLocation.LocalMachine)) {
        destination.Open(OpenFlags.ReadWrite);
        try {
          var parameters=new CngKeyCreationParameters {
            Provider=CngProvider.MicrosoftSoftwareKeyStorageProvider,
            KeyCreationOptions=scenario=="user-key"?CngKeyCreationOptions.None:CngKeyCreationOptions.MachineKey,
            ExportPolicy=scenario=="exportable"?CngExportPolicies.AllowExport|CngExportPolicies.AllowPlaintextExport:CngExportPolicies.None
          };
          parameters.Parameters.Add(new CngProperty("Length",BitConverter.GetBytes(2048),CngPropertyOptions.None));
          var key=CngKey.Create(CngAlgorithm.Rsa,name,parameters);keys.Add(key);
          SetAcl(key,new string[0]);
          using(var rsa=new RSACng(key)) {
            var request=new CertificateRequest("CN=isolated-review.invalid",rsa,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
            certificate=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(1));
          }
          if(scenario=="private-key-mismatch") {
            var other=CngKey.Create(CngAlgorithm.Rsa,name+"Other",parameters);keys.Add(other);SetAcl(other,new string[0]);
            var publicOnly=new X509Certificate2(certificate.RawData);certificate.Dispose();certificate=publicOnly;
            var info=new KeyProviderInfo {Container=other.KeyName,Provider=other.Provider.Provider,Flags=0x20,KeySpec=0xffffffff};
            Require(CertSetCertificateContextProperty(certificate.Handle,2,0,ref info),"mismatch-fixture-association");
          }
          if(scenario=="legacy-csp") {
            legacy=new RSACryptoServiceProvider(2048,new CspParameters(24,"Microsoft Enhanced RSA and AES Cryptographic Provider",name+"Legacy") {
              Flags=CspProviderFlags.UseMachineKeyStore,KeyNumber=(int)KeyNumber.Exchange
            });
            legacy.PersistKeyInCsp=true;
            var request=new CertificateRequest("CN=isolated-review.invalid",legacy,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
            certificate.Dispose();
            // CreateSelfSigned can attach an ephemeral CNG copy of a CSP key.
            // Persist the explicit legacy provider association instead, so the
            // fixture actually reaches the unsupported-provider acquisition.
            using(var signed=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(1)))certificate=new X509Certificate2(signed.RawData);
            var info=new KeyProviderInfo {Container=legacy.CspKeyContainerInfo.KeyContainerName,Provider=legacy.CspKeyContainerInfo.ProviderName,ProviderType=24,Flags=0x20,KeySpec=(uint)KeyNumber.Exchange};
            Require(CertSetCertificateContextProperty(certificate.Handle,2,0,ref info),"legacy-fixture-association");
            using(var acquired=certificate.GetRSAPrivateKey())Require(acquired is RSACryptoServiceProvider,"legacy-fixture-provider");
          }
          if(scenario=="incorrect-acl") {
            var descriptor=new RawSecurityDescriptor("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;WD)");
            byte[] value=new byte[descriptor.BinaryLength];descriptor.GetBinaryForm(value,0);
            key.SetProperty(new CngProperty("Security Descr",value,CngPropertyOptions.Persist|(CngPropertyOptions)4));
          }
          destination.Add(certificate);
          var aclBefore=new List<string>();foreach(var owned in keys)aclBefore.Add(Convert.ToBase64String(Acl(owned)));
          string legacyAcl=legacy==null?null:Convert.ToBase64String(legacy.CspKeyContainerInfo.CryptoKeySecurity.GetSecurityDescriptorBinaryForm());
          int count=destination.Certificates.Count;
          bool rejected=false;
          try { TokenTimer.MaterialImport.Install(new byte[0],"",name,certificate.Thumbprint,new string[0]); }
          catch(CryptographicException) { rejected=true; }
          Require(rejected==(scenario!="valid-reuse"),"existing-key-reuse-result-"+scenario);
          if(rejected) {
            string expected=scenario=="incorrect-acl"?"acl-principal":scenario=="private-key-mismatch"?"verify-signature":scenario=="legacy-csp"?"existing-key":"key-custody";
            Require(TokenTimer.MaterialImport.FailureStage==expected,"unexpected-safe-stage-"+scenario+"-"+TokenTimer.MaterialImport.FailureStage);
          } else {
            using(var sha=SHA256.Create()) {
              string fingerprint=BitConverter.ToString(sha.ComputeHash(certificate.RawData)).Replace("-","").ToLowerInvariant();
              TokenTimer.MaterialImport.Verify(name,certificate.Thumbprint,fingerprint,new string[0]);
            }
            Require(key.IsMachineKey && key.ExportPolicy==CngExportPolicies.None,"valid-custody");
          }
          Require(destination.Certificates.Count==count,"store-mutated-on-reuse");
          for(int i=0;i<keys.Count;i++)Require(Convert.ToBase64String(Acl(keys[i]))==aclBefore[i],"foreign-acl-mutated");
          Require(key.ExportPolicy==parameters.ExportPolicy,"export-policy-mutated");
          if(legacy!=null)Require(Convert.ToBase64String(legacy.CspKeyContainerInfo.CryptoKeySecurity.GetSecurityDescriptorBinaryForm())==legacyAcl,"legacy-acl-mutated");
        } finally {
          foreach(var cert in destination.Certificates) { destination.Remove(cert);cert.Dispose(); }
          if(certificate!=null)certificate.Dispose();
          if(legacy!=null) { legacy.PersistKeyInCsp=false;legacy.Dispose(); }
          // Only named keys created by this invocation are deleted. Never repair
          // an existing product key or change an ACL to make adoption succeed.
          foreach(var key in keys) { key.Delete();key.Dispose(); }
        }
      }
    }
  }
}
