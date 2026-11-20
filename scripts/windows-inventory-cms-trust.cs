using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

public static class WindowsInventoryCertificateChain
{
    private static readonly IntPtr LocalMachineEngine = new IntPtr(1);
    private static readonly IntPtr MemoryStoreProvider = new IntPtr(2);
    private const uint AddAlways = 4;
    private const uint CacheOnlyChainObjects = 0x00000004;
    private const uint DisableRootAutoUpdate = 0x00000100;
    private const uint DisableAia = 0x00002000;
    private const uint CheckRevocationExceptRoot = 0x40000000;
    private const uint CacheOnlyRevocation = 0x80000000;

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime
    {
        public uint Low;
        public uint High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EnhancedKeyUsage
    {
        public uint IdentifierCount;
        public IntPtr Identifiers;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UsageMatch
    {
        public uint MatchType;
        public EnhancedKeyUsage Usage;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ChainParameters
    {
        public uint Size;
        public UsageMatch RequestedUsage;
    }

    // Both CERT_CHAIN_CONTEXT and CERT_SIMPLE_CHAIN start with these fields.
    [StructLayout(LayoutKind.Sequential)]
    private struct ChainHeader
    {
        public uint Size;
        public uint ErrorStatus;
        public uint InfoStatus;
        public uint Count;
        public IntPtr Items;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ChainElementHeader
    {
        public uint Size;
        public IntPtr Certificate;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CertificateHeader
    {
        public uint Encoding;
        public IntPtr Encoded;
        public uint EncodedLength;
    }

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern IntPtr CertOpenStore(IntPtr provider, uint encoding, IntPtr cryptProvider,
        uint flags, IntPtr parameters);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CertAddCertificateContextToStore(IntPtr store, IntPtr certificate,
        uint disposition, IntPtr addedCertificate);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CertGetCertificateChain(IntPtr engine, IntPtr certificate, ref FileTime time,
        IntPtr additionalStore, ref ChainParameters parameters, uint flags, IntPtr reserved, out IntPtr context);

    [DllImport("crypt32.dll")]
    private static extern void CertFreeCertificateChain(IntPtr context);

    [DllImport("crypt32.dll")]
    private static extern bool CertCloseStore(IntPtr store, uint flags);

    public static byte[] Verify(X509Certificate2 certificate, X509Certificate2Collection supportingCertificates,
        DateTime verificationTime, string requiredUsage, bool returnIssuer)
    {
        IntPtr store = IntPtr.Zero;
        IntPtr chainContext = IntPtr.Zero;
        IntPtr usageOid = IntPtr.Zero;
        IntPtr usageList = IntPtr.Zero;
        try
        {
            store = CertOpenStore(MemoryStoreProvider, 0, IntPtr.Zero, 0, IntPtr.Zero);
            if (store == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            foreach (X509Certificate2 supporting in supportingCertificates)
            {
                if (!CertAddCertificateContextToStore(store, supporting.Handle, AddAlways, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            usageOid = Marshal.StringToHGlobalAnsi(requiredUsage);
            usageList = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(usageList, usageOid);
            var parameters = new ChainParameters
            {
                Size = (uint)Marshal.SizeOf<ChainParameters>(),
                RequestedUsage = new UsageMatch
                {
                    Usage = new EnhancedKeyUsage { IdentifierCount = 1, Identifiers = usageList }
                }
            };
            long utcFileTime = verificationTime.ToFileTimeUtc();
            var time = new FileTime { Low = unchecked((uint)utcFileTime), High = (uint)(utcFileTime >> 32) };
            uint flags = CacheOnlyChainObjects | DisableRootAutoUpdate | DisableAia |
                CheckRevocationExceptRoot | CacheOnlyRevocation;
            if (!CertGetCertificateChain(LocalMachineEngine, certificate.Handle, ref time, store,
                ref parameters, flags, IntPtr.Zero, out chainContext))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            var context = Marshal.PtrToStructure<ChainHeader>(chainContext);
            if (context.ErrorStatus != 0)
                throw new InvalidOperationException(
                    $"Inventory certificate chain or cached revocation is invalid or unavailable (0x{context.ErrorStatus:X8}).");
            if (context.Count == 0) throw new InvalidOperationException("Inventory certificate chain is missing.");
            if (!returnIssuer) return Array.Empty<byte>();

            // Windows lists the signer's simple chain first.
            var chain = Marshal.PtrToStructure<ChainHeader>(Marshal.ReadIntPtr(context.Items));
            if (chain.Count < 2) throw new InvalidOperationException("Inventory certificate issuer is missing.");
            var issuerElement = Marshal.PtrToStructure<ChainElementHeader>(
                Marshal.ReadIntPtr(chain.Items, IntPtr.Size));
            var issuer = Marshal.PtrToStructure<CertificateHeader>(issuerElement.Certificate);
            var issuerDer = new byte[checked((int)issuer.EncodedLength)];
            Marshal.Copy(issuer.Encoded, issuerDer, 0, issuerDer.Length);
            return issuerDer;
        }
        finally
        {
            if (chainContext != IntPtr.Zero) CertFreeCertificateChain(chainContext);
            if (store != IntPtr.Zero) CertCloseStore(store, 0);
            Marshal.FreeHGlobal(usageList);
            Marshal.FreeHGlobal(usageOid);
            GC.KeepAlive(certificate);
            GC.KeepAlive(supportingCertificates);
        }
    }
}
