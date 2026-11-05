# TEST ONLY. Cryptographic proof of a timestamp; this is not a trust verifier.
# It intentionally does not validate a TSA chain, publisher identity or revocation.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class TimestampFixtureProbe {
    [StructLayout(LayoutKind.Sequential)] struct Blob { public uint length; public IntPtr data; }
    [StructLayout(LayoutKind.Sequential)] struct Algorithm { public IntPtr oid; public Blob parameters; }
    [StructLayout(LayoutKind.Sequential)] struct TimestampInfo {
        public uint version; public IntPtr policy; public Algorithm algorithm;
        public Blob message; public Blob serial;
        public System.Runtime.InteropServices.ComTypes.FILETIME time;
    }
    [StructLayout(LayoutKind.Sequential)] struct TimestampContext {
        public uint length; public IntPtr encoded; public IntPtr info;
    }
    [DllImport("crypt32.dll", SetLastError=true)]
    static extern bool CryptVerifyTimeStampSignature(byte[] token, uint tokenLength, byte[] data, uint dataLength, IntPtr additionalStore, out IntPtr context, out IntPtr signer, out IntPtr store);
    [DllImport("crypt32.dll")] static extern void CryptMemFree(IntPtr context);
    [DllImport("crypt32.dll")] static extern bool CertFreeCertificateContext(IntPtr cert);
    [DllImport("crypt32.dll")] static extern bool CertCloseStore(IntPtr store, uint flags);

    public static string Verify(byte[] token, byte[] signature) {
        IntPtr context=IntPtr.Zero, signer=IntPtr.Zero, store=IntPtr.Zero;
        try {
            if (!CryptVerifyTimeStampSignature(token, (uint)token.Length, signature, (uint)signature.Length,
                IntPtr.Zero, out context, out signer, out store)) throw new Win32Exception(Marshal.GetLastWin32Error());
            var ctx=(TimestampContext)Marshal.PtrToStructure(context, typeof(TimestampContext));
            var info=(TimestampInfo)Marshal.PtrToStructure(ctx.info, typeof(TimestampInfo));
            if (Marshal.PtrToStringAnsi(info.algorithm.oid)!="2.16.840.1.101.3.4.2.1") throw new Exception("unexpected digest");
            long time=((long)info.time.dwHighDateTime << 32) | (uint)info.time.dwLowDateTime;
            return DateTime.FromFileTimeUtc(time).ToString("o");
        } finally {
            if (context!=IntPtr.Zero) CryptMemFree(context);
            if (signer!=IntPtr.Zero) CertFreeCertificateContext(signer);
            if (store!=IntPtr.Zero) CertCloseStore(store, 0);
        }
    }
}
'@
$cms=New-Object System.Security.Cryptography.Pkcs.SignedCms
$cms.Decode([Convert]::FromBase64String($env:TT_TEST_CMS))
if ($cms.Detached -or $cms.SignerInfos.Count -ne 1 -or $cms.ContentInfo.ContentType.Value -ne '1.2.840.113549.1.7.1') { throw 'bad CMS' }
$cms.CheckSignature($true)
$signer=$cms.SignerInfos[0]
if ($signer.DigestAlgorithm.Value -ne '2.16.840.1.101.3.4.2.1' -or -not $signer.Certificate) { throw 'bad signer' }
$values=@($signer.UnsignedAttributes | Where-Object {$_.Oid.Value -eq '1.3.6.1.4.1.311.3.3.1'} | ForEach-Object { $_.Values })
if ($values.Count -ne 1) { throw 'expected one timestamp' }
$token=$values[0].RawData
$signature=$signer.GetSignature()
if ($env:TT_TEST_MUTATE_SIGNATURE -eq '1') { $signature[0]=$signature[0] -bxor 1 }
if ($env:TT_TEST_MUTATE_TIMESTAMP -eq '1') { $token[$token.Length-1]=$token[$token.Length-1] -bxor 1 }
[Console]::Out.Write([TimestampFixtureProbe]::Verify($token,$signature))
