using Azure.CodeSigning;
using Azure.CodeSigning.Models;
using Azure.Identity;
using System.Text.Json;

namespace OfficeVbaSigner;

/// <summary>
/// Wraps Azure Trusted Signing SDK (Azure.CodeSigning.Sdk) to sign
/// a pre-computed digest remotely and return the raw signature + certificate.
/// </summary>
internal sealed class AzureSigner
{
    private readonly CertificateProfileClient _client;
    private readonly string _accountName;
    private readonly string _profileName;

    public AzureSigner(string endpoint, string accountName, string profileName,
                       DefaultAzureCredentialOptions? credentialOptions = null)
    {
        _accountName = accountName;
        _profileName = profileName;

        var credential = new DefaultAzureCredential(credentialOptions ?? new DefaultAzureCredentialOptions());
        _client = new CertificateProfileClient(credential, new Uri(endpoint));
    }

    /// <summary>
    /// Load signing parameters from a metadata JSON file (same format as signtool /dmdf).
    /// Required keys: Endpoint, CodeSigningAccountName, CertificateProfileName.
    /// Optional keys: Exclude* (bool) to disable specific credential sources.
    /// </summary>
    public static AzureSigner FromMetadataFile(string metadataPath)
    {
        var json = File.ReadAllText(metadataPath);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        string endpoint = root.GetProperty("Endpoint").GetString()
            ?? throw new InvalidOperationException("Metadata JSON missing 'Endpoint'.");
        string account = root.GetProperty("CodeSigningAccountName").GetString()
            ?? throw new InvalidOperationException("Metadata JSON missing 'CodeSigningAccountName'.");
        string profile = root.GetProperty("CertificateProfileName").GetString()
            ?? throw new InvalidOperationException("Metadata JSON missing 'CertificateProfileName'.");

        var opts = new DefaultAzureCredentialOptions();

        if (TryGetBool(root, "ExcludeEnvironmentCredential", out bool v)) opts.ExcludeEnvironmentCredential = v;
        if (TryGetBool(root, "ExcludeManagedIdentityCredential", out v)) opts.ExcludeManagedIdentityCredential = v;
        if (TryGetBool(root, "ExcludeAzureCliCredential", out v)) opts.ExcludeAzureCliCredential = v;
        if (TryGetBool(root, "ExcludeAzurePowerShellCredential", out v)) opts.ExcludeAzurePowerShellCredential = v;
        if (TryGetBool(root, "ExcludeVisualStudioCredential", out v)) opts.ExcludeVisualStudioCredential = v;
        if (TryGetBool(root, "ExcludeVisualStudioCodeCredential", out v)) opts.ExcludeVisualStudioCodeCredential = v;
        if (TryGetBool(root, "ExcludeSharedTokenCacheCredential", out v)) opts.ExcludeSharedTokenCacheCredential = v;
        if (TryGetBool(root, "ExcludeInteractiveBrowserCredential", out v)) opts.ExcludeInteractiveBrowserCredential = v;
        if (TryGetBool(root, "ExcludeAzureDeveloperCliCredential", out v)) opts.ExcludeAzureDeveloperCliCredential = v;
        if (TryGetBool(root, "ExcludeWorkloadIdentityCredential", out v)) opts.ExcludeWorkloadIdentityCredential = v;

        return new AzureSigner(endpoint, account, profile, opts);
    }

    /// <summary>
    /// Sign a pre-computed digest using Azure Trusted Signing.
    /// Returns the raw signature bytes and the DER-encoded signing certificate.
    /// </summary>
    public async Task<(byte[] Signature, byte[] CertificateDer)> SignDigestAsync(
        byte[] digest, string digestAlgOid, CancellationToken ct = default)
    {
        var sigAlg = MapToSignatureAlgorithm(digestAlgOid);
        var request = new SignRequest(sigAlg, digest);

        var operation = await _client.StartSignAsync(
            _accountName, _profileName, request,
            xCorrelationId: null,
            clientVersion: "OfficeVbaSigner/1.0",
            certificateThumbprint: null,
            cancellationToken: ct);

        var result = await operation.WaitForCompletionAsync(ct);
        var signStatus = result.Value;

        if (signStatus.Signature is null || signStatus.SigningCertificate is null)
            throw new InvalidOperationException(
                $"Azure Trusted Signing returned status '{signStatus.Status}' but no signature/certificate.");

        return (signStatus.Signature, signStatus.SigningCertificate);
    }

    /// <summary>
    /// Fetch the full certificate chain (DER-encoded PKCS#7 or concatenated certs).
    /// </summary>
    public async Task<byte[]?> GetCertificateChainAsync(CancellationToken ct = default)
    {
        try
        {
            var response = await _client.GetSignCertificateChainAsync(
                _accountName, _profileName, ct);

            using var ms = new MemoryStream();
            await response.Value.CopyToAsync(ms, ct);
            return ms.ToArray();
        }
        catch
        {
            return null;
        }
    }

    private static bool TryGetBool(JsonElement root, string propertyName, out bool value)
    {
        value = false;
        if (root.TryGetProperty(propertyName, out var el) && el.ValueKind == JsonValueKind.True || el.ValueKind == JsonValueKind.False)
        {
            value = el.GetBoolean();
            return true;
        }
        return false;
    }

    private static SignatureAlgorithm MapToSignatureAlgorithm(string digestAlgOid) => digestAlgOid switch
    {
        NativeMethods.OID_SHA256 => SignatureAlgorithm.RS256,
        NativeMethods.OID_SHA384 => SignatureAlgorithm.RS384,
        NativeMethods.OID_SHA512 => SignatureAlgorithm.RS512,
        _ => SignatureAlgorithm.RS256
    };
}
