using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OfficeVbaSigner;

/// <summary>
/// A custom RSA implementation that delegates SignHash to Azure Trusted Signing.
/// Used with SignedCms.ComputeSignature to produce a PKCS#7 where the actual
/// signing is done remotely by Azure, while .NET handles all CMS structure building.
/// </summary>
internal sealed class AzureRsa : RSA
{
    private readonly AzureSigner _signer;
    private readonly string _digestAlgOid;
    private RSA? _publicKeyOnly;

    public AzureRsa(AzureSigner signer, string digestAlgOid)
    {
        _signer = signer;
        _digestAlgOid = digestAlgOid;
    }

    /// <summary>
    /// Initialize the public key from the signing certificate so that
    /// KeySize and ExportParameters work (required by CmsSigner).
    /// </summary>
    public void LoadPublicKeyFromCert(byte[] certDer)
    {
        using var cert = X509CertificateLoader.LoadCertificate(certDer);
        _publicKeyOnly = cert.GetRSAPublicKey()!;
        KeySizeValue = _publicKeyOnly.KeySize;
    }

    public override RSAParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
            throw new CryptographicException("Private key is remote (Azure Trusted Signing).");
        return _publicKeyOnly?.ExportParameters(false)
            ?? throw new InvalidOperationException("Call LoadPublicKeyFromCert first.");
    }

    public override void ImportParameters(RSAParameters parameters)
    {
        // Required by contract; store as public-key-only
        _publicKeyOnly = RSA.Create(parameters);
        KeySizeValue = _publicKeyOnly.KeySize;
    }

    /// <summary>
    /// Core signing method — delegates to Azure Trusted Signing.
    /// SignedCms calls this with the hash of the authenticated attributes.
    /// </summary>
    public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        if (padding != RSASignaturePadding.Pkcs1)
            throw new CryptographicException($"Unsupported padding: {padding}. Azure Trusted Signing uses PKCS#1 v1.5.");

        // Map hash algorithm to OID for the Azure call
        string algOid = hashAlgorithm.Name switch
        {
            "SHA256" => NativeMethods.OID_SHA256,
            "SHA384" => NativeMethods.OID_SHA384,
            "SHA512" => NativeMethods.OID_SHA512,
            _ => _digestAlgOid
        };

        var (signature, _) = _signer.SignDigestAsync(hash, algOid)
            .GetAwaiter().GetResult();

        return signature;
    }

    public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        return _publicKeyOnly?.VerifyHash(hash, signature, hashAlgorithm, padding)
            ?? throw new InvalidOperationException("No public key loaded.");
    }

    // Required overrides that delegate to the public key
    public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding)
        => throw new NotSupportedException("Encryption not supported.");

    public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
        => throw new NotSupportedException("Decryption not supported.");

    protected override void Dispose(bool disposing)
    {
        if (disposing) _publicKeyOnly?.Dispose();
        base.Dispose(disposing);
    }
}
