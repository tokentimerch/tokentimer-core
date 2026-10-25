using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

namespace TokenTimer {
  // Shared-material import is deliberately separate from CNG enrollment.
  // No existing local-key/non-exportable enrollment code is changed.
  public static class MaterialImport {
    // Fixed diagnostic vocabulary only; never certificate/key/config values.
    public static string FailureStage = "input";
    [StructLayout(LayoutKind.Sequential)] struct Blob { public int Size; public IntPtr Data; }
    [DllImport("crypt32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr PFXImportCertStore(ref Blob blob, string password, uint flags);
    [DllImport("crypt32.dll")] static extern bool CertCloseStore(IntPtr store, uint flags);

    static X509Certificate2 Find(X509Store store, string thumbprint) {
      X509Certificate2 found = null;
      foreach (var cert in store.Certificates) {
        if (String.Equals(cert.Thumbprint,thumbprint,StringComparison.OrdinalIgnoreCase)) {
          if (found != null) throw new CryptographicException();
          found = cert;
        }
      }
      return found;
    }
    static CngKey Key(X509Certificate2 cert) {
      var rsa = cert.GetRSAPrivateKey() as RSACng;
      if (rsa != null) { using(rsa) return Duplicate(rsa.Key); }
      var ec = cert.GetECDsaPrivateKey() as ECDsaCng;
      if (ec != null) { using(ec) return Duplicate(ec.Key); }
      throw new CryptographicException();
    }
    static CngKey Duplicate(CngKey key) {
      // RSACng/ECDsaCng own and dispose their Key. Keep an independently
      // duplicated native handle before disposing the algorithm wrapper.
      using(var handle=key.Handle) return CngKey.Open(handle,key.IsEphemeral?CngKeyHandleOpenOptions.EphemeralKey:CngKeyHandleOpenOptions.None);
    }
    static string Descriptor(string[] sids) {
      string sddl="D:P(A;;GA;;;SY)(A;;GA;;;BA)";
      foreach(string sid in sids) {
        var parsed=new SecurityIdentifier(sid);
        if(parsed.IsWellKnown(WellKnownSidType.WorldSid) || parsed.IsWellKnown(WellKnownSidType.AuthenticatedUserSid) || parsed.IsWellKnown(WellKnownSidType.BuiltinUsersSid)) throw new CryptographicException();
        if(sid!="S-1-5-18" && sid!="S-1-5-32-544") sddl+="(A;;GR;;;"+parsed.Value+")";
      }
      return sddl;
    }
    static void SetAcl(CngKey key,string[] sids) {
      var descriptor=new RawSecurityDescriptor(Descriptor(sids));
      byte[] bytes=new byte[descriptor.BinaryLength];descriptor.GetBinaryForm(bytes,0);
      key.SetProperty(new CngProperty("Security Descr",bytes,CngPropertyOptions.Persist | (CngPropertyOptions)4));
    }
    static int EffectiveMask(int accessMask) {
      // The Microsoft Software KSP returns generic rights together with their
      // expanded file rights (for example GA becomes D01F01FF). Compare the
      // effective rights, retaining every unexpected specific bit. These are
      // the Windows FILE_GENERIC_* / FILE_ALL_ACCESS mappings used by this KSP.
      uint mask=unchecked((uint)accessMask);
      if((mask & 0x10000000)!=0)mask=(mask & ~0x10000000u)|0x001f01ff;
      if((mask & 0x80000000)!=0)mask=(mask & ~0x80000000u)|0x00120089;
      if((mask & 0x40000000)!=0)mask=(mask & ~0x40000000u)|0x00120116;
      if((mask & 0x20000000)!=0)mask=(mask & ~0x20000000u)|0x001200a0;
      return unchecked((int)mask);
    }
    static void CheckCustody(CngKey key) {
      // Shared import uses this file-backed KSP. Do not apply its ACL mapping
      // to a TPM/HSM or another provider with different access semantics.
      if(!key.IsMachineKey || key.IsEphemeral || key.ExportPolicy!=CngExportPolicies.None ||
        !key.Provider.Equals(CngProvider.MicrosoftSoftwareKeyStorageProvider))throw new CryptographicException();
    }
    static void CheckAcl(CngKey key,string[] sids) {
      var descriptor=new RawSecurityDescriptor(key.GetProperty("Security Descr",(CngPropertyOptions)4).GetValue(),0);
      FailureStage="acl-presence";
      if(descriptor.DiscretionaryAcl==null)throw new CryptographicException();
      FailureStage="acl-protection";
      if((descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected)==0) throw new CryptographicException();
      var expected=new RawSecurityDescriptor(Descriptor(sids));
      foreach(GenericAce ace in descriptor.DiscretionaryAcl) {
        FailureStage="acl-shape";
        var actual=ace as CommonAce;bool match=false;
        if(actual==null || actual.AceQualifier!=AceQualifier.AccessAllowed || actual.IsInherited) throw new CryptographicException();
        bool principal=false;
        foreach(CommonAce allowed in expected.DiscretionaryAcl) {
          if(actual.SecurityIdentifier==allowed.SecurityIdentifier) {principal=true;if(EffectiveMask(actual.AccessMask)==EffectiveMask(allowed.AccessMask)) match=true;}
        }
        FailureStage=principal?"acl-access-mask-"+actual.AccessMask.ToString("X8"):"acl-principal";
        if(!match) throw new CryptographicException();
      }
      FailureStage="acl-membership";
      foreach(CommonAce allowed in expected.DiscretionaryAcl) {
        bool present=false;
        foreach(CommonAce actual in descriptor.DiscretionaryAcl) if(actual.SecurityIdentifier==allowed.SecurityIdentifier && EffectiveMask(actual.AccessMask)==EffectiveMask(allowed.AccessMask))present=true;
        if(!present) throw new CryptographicException();
      }
    }
    public static void Install(byte[] pfx,string password,string storeName,string thumbprint,string[] sids) {
      // Validate every configured SID before creating a persisted key or store.
      Descriptor(sids);
      FailureStage="store-open";
      using(var destination=new X509Store(storeName,StoreLocation.LocalMachine)) {
        destination.Open(OpenFlags.ReadWrite);
        var existing=Find(destination,thumbprint);
        // An existing key is adopted only if its key association, CNG custody
        // and exact service ACL can be proven. Never rewrite a foreign ACL.
        if(existing!=null) { FailureStage="existing-key";using(var key=Key(existing))CheckAcl(key,sids);return; }
        GCHandle pinned=GCHandle.Alloc(pfx,GCHandleType.Pinned);
        IntPtr handle=IntPtr.Zero;
        try {
          var blob=new Blob { Size=pfx.Length,Data=pinned.AddrOfPinnedObject() };
          // Machine key set, prefer and require CNG; omit EXPORTABLE and
          // ALLOW_OVERWRITE_KEY. There is no user profile or UI dependency.
          FailureStage="pfx-import";
          handle=PFXImportCertStore(ref blob,password,0x20|0x100|0x200);
          if(handle==IntPtr.Zero)throw new CryptographicException(Marshal.GetLastWin32Error());
          using(var imported=new X509Store(handle)) {
            FailureStage="key-association";
            var leaf=Find(imported,thumbprint);
            if(leaf==null || !leaf.HasPrivateKey)throw new CryptographicException();
            using(var key=Key(leaf)) {
              FailureStage="key-custody";
              CheckCustody(key);
              FailureStage="key-acl";
              SetAcl(key,sids);CheckAcl(key,sids);
            }
            // Chain certificates remain in the selected personal store. No
            // trust roots are installed or changed by shared-material import.
            FailureStage="store-add";
            foreach(var cert in imported.Certificates)destination.Add(cert);
          }
        } finally { if(handle!=IntPtr.Zero)CertCloseStore(handle,0);pinned.Free(); }
      }
    }
    public static void Verify(string storeName,string thumbprint,string fingerprint,string[] sids) {
      FailureStage="verify-cert";
      using(var store=new X509Store(storeName,StoreLocation.LocalMachine)) {
        store.Open(OpenFlags.ReadOnly);var cert=Find(store,thumbprint);
        if(cert==null || !cert.HasPrivateKey)throw new CryptographicException();
        using(var sha=SHA256.Create()) {
          var actual=BitConverter.ToString(sha.ComputeHash(cert.RawData)).Replace("-","").ToLowerInvariant();
          if(actual!=fingerprint)throw new CryptographicException();
        }
        using(var key=Key(cert)) {
          FailureStage="verify-key";
          CheckCustody(key);
          FailureStage="verify-acl";
          CheckAcl(key,sids);
        }
        // HasPrivateKey alone is insufficient: prove the acquired key matches
        // the certificate and is usable by the executing service identity.
        FailureStage="verify-signature";
        byte[] nonce=new byte[32];using(var random=RandomNumberGenerator.Create())random.GetBytes(nonce);
        using(var rsa=cert.GetRSAPrivateKey()) {
          if(rsa!=null) { using(var pub=cert.GetRSAPublicKey())if(!pub.VerifyData(nonce,rsa.SignData(nonce,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1),HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1))throw new CryptographicException(); }
          else using(var ec=cert.GetECDsaPrivateKey())using(var pub=cert.GetECDsaPublicKey())if(!pub.VerifyData(nonce,ec.SignData(nonce,HashAlgorithmName.SHA256),HashAlgorithmName.SHA256))throw new CryptographicException();
        }
      }
    }
  }
}
