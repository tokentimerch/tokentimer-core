using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

public static class InventoryCmsProducer
{
    public const string TimestampAttributeOid = "1.2.840.113549.1.9.16.2.14";
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";

    public static byte[] Sign(
        byte[] inventory,
        X509Certificate2 publisher,
        RSA publisherKey,
        X509Certificate2Collection publisherIntermediates,
        Func<byte[], byte[]> exchangeTimestamp)
    {
        if (inventory.Length is < 1 or > 16 * 1024 * 1024)
            throw new CryptographicException("Invalid inventory size.");

        var cms = new SignedCms(new ContentInfo(inventory), detached: false);
        var publisherSigner = new CmsSigner(
            SubjectIdentifierType.IssuerAndSerialNumber, publisher, publisherKey, RSASignaturePadding.Pkcs1)
        {
            DigestAlgorithm = new Oid(Sha256Oid),
            IncludeOption = X509IncludeOption.EndCertOnly
        };
        publisherSigner.Certificates.AddRange(publisherIntermediates);
        cms.ComputeSignature(publisherSigner, silent: true);
        cms.CheckSignature(verifySignatureOnly: true);

        SignerInfo signer = cms.SignerInfos[0];
        Rfc3161TimestampRequest request = Rfc3161TimestampRequest.CreateFromSignerInfo(
            signer, HashAlgorithmName.SHA256, nonce: RandomNumberGenerator.GetBytes(16),
            requestSignerCertificates: true);
        byte[] response = exchangeTimestamp(request.Encode());
        if (response.Length is < 1 or > 1024 * 1024)
            throw new CryptographicException("Invalid timestamp response size.");
        Rfc3161TimestampToken token = request.ProcessResponse(response, out int consumed);
        if (consumed != response.Length ||
            token.TokenInfo.HashAlgorithmId.Value != Sha256Oid ||
            token.TokenInfo.Timestamp > DateTimeOffset.UtcNow ||
            token.TokenInfo.Timestamp < publisher.NotBefore.ToUniversalTime() ||
            token.TokenInfo.Timestamp > publisher.NotAfter.ToUniversalTime() ||
            !token.VerifySignatureForSignerInfo(signer, out X509Certificate2? timestampSigner))
        {
            throw new CryptographicException("Timestamp does not match the inventory publisher signature.");
        }
        timestampSigner?.Dispose();

        signer.AddUnsignedAttribute(new AsnEncodedData(
            new Oid(TimestampAttributeOid), token.AsSignedCms().Encode()));
        return cms.Encode();
    }
}
