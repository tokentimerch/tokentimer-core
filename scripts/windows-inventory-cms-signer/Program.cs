using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Azure;
using Azure.CodeSigning;
using Azure.Developer.ArtifactSigning.CryptoProvider;
using Azure.Developer.ArtifactSigning.CryptoProvider.Models;
using Azure.Identity;

try
{
    if (args.Length != 1)
        throw new InvalidOperationException("Expected the common Authenticode publisher SHA-256.");

    string stage = RequireEnvironment("PILOT_STAGE");
    string version = RequireEnvironment("PILOT_VERSION");
    if (!Path.IsPathFullyQualified(stage) || !Regex.IsMatch(version, @"\A[0-9]+\.[0-9]+\.[0-9]+\z"))
        throw new InvalidOperationException("Expected the verified Windows package stage and version.");
    string inventoryPath = Path.Combine(stage, $"tokentimer-agent-{version}-windows-amd64.inventory.json");
    string output = inventoryPath + ".p7";
    byte[] inventoryPin = ParseHash(RequireEnvironment("PILOT_INVENTORY_SHA256"));
    byte[] publisherPin = ParseHash(args[0]);
    byte[] issuerPin = ParseHash(RequireEnvironment("PILOT_ISSUER_SHA256"));
    string profileEku = RequireEnvironment("PILOT_PROFILE_EKU");
    string endpoint = RequireEnvironment("PILOT_ENDPOINT");
    string account = RequireEnvironment("PILOT_ACCOUNT");
    string profile = RequireEnvironment("PILOT_PROFILE");
    if (!Regex.IsMatch(endpoint, @"\Ahttps://[a-z][a-z0-9-]*\.codesigning\.azure\.net\z") ||
        !Regex.IsMatch(account, @"\A[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]\z") ||
        !Regex.IsMatch(profile, @"\A[A-Za-z][A-Za-z0-9-]{3,98}[A-Za-z0-9]\z") ||
        !Regex.IsMatch(profileEku, @"\A1\.3\.6\.1\.4\.1\.311\.97\.(?:[0-9]+\.){2,}[0-9]+\z") ||
        Regex.IsMatch(profileEku, @"\A1\.3\.6\.1\.4\.1\.311\.97\.1\.(?:0|3\.1|4\.1)(?:\.|\z)"))
    {
        throw new InvalidOperationException("Expected a reviewed Artifact Signing endpoint and Public Trust profile.");
    }

    byte[] inventory;
    if ((File.GetAttributes(inventoryPath) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        throw new InvalidOperationException("Expected a regular inventory file in the verified stage.");
    using (var input = new FileStream(inventoryPath, FileMode.Open, FileAccess.Read, FileShare.Read))
    {
        if (input.Length is < 1 or > 16 * 1024 * 1024 || File.Exists(output))
            throw new InvalidOperationException("Invalid inventory length or existing CMS output.");
        inventory = new byte[checked((int)input.Length)];
        input.ReadExactly(inventory);
    }
    if (!CryptographicOperations.FixedTimeEquals(inventoryPin, SHA256.HashData(inventory)))
        throw new InvalidOperationException("Inventory does not match its independently pinned digest.");

    var credential = new AzureCliCredential(new AzureCliCredentialOptions { ProcessTimeout = TimeSpan.FromSeconds(30) });
    var clientOptions = new CertificateProfileClientOptions();
    clientOptions.Retry.MaxRetries = 0;
    clientOptions.Retry.NetworkTimeout = TimeSpan.FromSeconds(30);
    var client = new CertificateProfileClient(credential, new Uri(endpoint), clientOptions);
    var context = new AzSignContext(accountName: account, certProfile: profile, cpClient: client,
        signContextOptions: new AzSignContextOptions { TaskRetryCount = 1, TaskTimeOutInSeconds = 60 });
    using X509Certificate2 publisher = context.GetSigningCertificate();
    if (!CryptographicOperations.FixedTimeEquals(publisherPin, SHA256.HashData(publisher.RawData)))
        throw new InvalidOperationException("Current signing leaf differs from the Authenticode package leaf.");
    DateTime utcNow = DateTime.UtcNow;
    if (publisher.NotBefore.ToUniversalTime() > utcNow || publisher.NotAfter.ToUniversalTime() <= utcNow)
        throw new InvalidOperationException("Current signing leaf is outside its validity period.");
    var usages = publisher.Extensions.OfType<X509EnhancedKeyUsageExtension>()
        .SelectMany(extension => extension.EnhancedKeyUsages.Cast<Oid>())
        .Select(oid => oid.Value).ToHashSet(StringComparer.Ordinal);
    if (!usages.Contains("1.3.6.1.5.5.7.3.3") ||
        !usages.Contains("1.3.6.1.4.1.311.97.1.0") ||
        !usages.Contains(profileEku))
    {
        throw new InvalidOperationException("Signing leaf lacks the exact Public Trust profile.");
    }

    var intermediates = new X509Certificate2Collection();
    bool hasPinnedIssuer = false;
    foreach (X509Certificate2 certificate in context.GetCertChain())
    {
        if (certificate.RawData.AsSpan().SequenceEqual(publisher.RawData) ||
            certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData))
        {
            continue;
        }
        intermediates.Add(certificate);
        if (certificate.SubjectName.RawData.AsSpan().SequenceEqual(publisher.IssuerName.RawData) &&
            CryptographicOperations.FixedTimeEquals(issuerPin, SHA256.HashData(certificate.RawData)))
        {
            hasPinnedIssuer = true;
        }
    }
    if (!hasPinnedIssuer)
        throw new InvalidOperationException("Signing chain lacks the independently pinned immediate issuer.");

    using var rsa = new RSAAzSign(context);
    using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
    {
        Timeout = TimeSpan.FromSeconds(45),
        MaxResponseContentBufferSize = 1024 * 1024
    };
    byte[] signature = InventoryCmsProducer.Sign(inventory, publisher, rsa, intermediates, request =>
    {
        using var payload = new ByteArrayContent(request);
        payload.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");
        using HttpResponseMessage response = http.PostAsync("http://timestamp.acs.microsoft.com", payload).GetAwaiter().GetResult();
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentType?.MediaType != "application/timestamp-reply")
            throw new InvalidOperationException("Unexpected RFC 3161 response type.");
        return response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
    });
    using var signedOutput = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None);
    signedOutput.Write(signature);
    return 0;
}
catch (RequestFailedException error)
{
    Console.Error.WriteLine($"Artifact Signing rejected the inventory request (HTTP {error.Status}).");
}
catch (InvalidOperationException error)
{
    Console.Error.WriteLine(error.Message);
}
catch (Exception error)
{
    Console.Error.WriteLine($"Inventory CMS signing failed ({error.GetType().Name}).");
}
return 1;

static string RequireEnvironment(string name) =>
    Environment.GetEnvironmentVariable(name) ?? throw new InvalidOperationException($"Missing {name}.");

static byte[] ParseHash(string value)
{
    if (!Regex.IsMatch(value, @"\A[a-f0-9]{64}\z"))
        throw new InvalidOperationException("Expected a lowercase SHA-256 digest.");
    return Convert.FromHexString(value);
}
