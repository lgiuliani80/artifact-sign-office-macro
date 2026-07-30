using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OfficeVbaSigner;

/// <summary>
/// Builds an Authenticode CMS/PKCS#7 SignedData structure from its components.
/// Uses System.Formats.Asn1.AsnWriter for DER encoding (no external dependencies).
/// </summary>
internal static class Pkcs7Builder
{
    // ── OID constants ───────────────────────────────────────────────────
    private const string OID_SIGNED_DATA          = "1.2.840.113549.1.7.2";
    private const string OID_SPC_INDIRECT_DATA    = "1.3.6.1.4.1.311.2.1.4";
    private const string OID_CONTENT_TYPE         = "1.2.840.113549.1.9.3";
    private const string OID_MESSAGE_DIGEST       = "1.2.840.113549.1.9.4";
    private const string OID_RSA_ENCRYPTION       = "1.2.840.113549.1.1.1";
    private const string OID_SHA256_WITH_RSA      = "1.2.840.113549.1.1.11";
    private const string OID_SHA384_WITH_RSA      = "1.2.840.113549.1.1.12";
    private const string OID_SHA512_WITH_RSA      = "1.2.840.113549.1.1.13";
    private const string OID_ECDSA_WITH_SHA256    = "1.2.840.10045.4.3.2";
    private const string OID_ECDSA_WITH_SHA384    = "1.2.840.10045.4.3.3";
    private const string OID_ECDSA_WITH_SHA512    = "1.2.840.10045.4.3.4";

    /// <summary>
    /// DER-encode the SPC_INDIRECT_DATA content from its parsed fields.
    /// </summary>
    public static byte[] EncodeSpcIndirectData(NativeMethods.IndirectDataFields fields)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        w.PushSequence(); // SpcIndirectDataContent

        // data: SpcAttributeTypeAndOptionalValue
        w.PushSequence();
        w.WriteObjectIdentifier(fields.DataOid);
        if (fields.DataValue.Length > 0)
        {
            // The value is already DER-encoded; embed as-is under [0] EXPLICIT
            var tag0 = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
            w.PushSequence(tag0);
            w.WriteEncodedValue(fields.DataValue);
            w.PopSequence(tag0);
        }
        w.PopSequence();

        // messageDigest: DigestInfo
        w.PushSequence();
        // digestAlgorithm
        w.PushSequence();
        w.WriteObjectIdentifier(fields.DigestAlgOid);
        if (fields.DigestAlgParams.Length > 0)
            w.WriteEncodedValue(fields.DigestAlgParams);
        w.PopSequence();
        // digest
        w.WriteOctetString(fields.Digest);
        w.PopSequence();

        w.PopSequence();
        return w.Encode();
    }

    /// <summary>
    /// Build the DER-encoded authenticated attributes as a SET OF (tag 0x31)
    /// for hash computation during signing.
    /// </summary>
    public static byte[] BuildAuthenticatedAttributesForSigning(
        byte[] contentDigest,
        string digestAlgOid)
    {
        // Build individual attributes
        byte[] contentTypeAttr = BuildAttribute(OID_CONTENT_TYPE, writer =>
        {
            writer.WriteObjectIdentifier(OID_SPC_INDIRECT_DATA);
        });

        byte[] messageDigestAttr = BuildAttribute(OID_MESSAGE_DIGEST, writer =>
        {
            writer.WriteOctetString(contentDigest);
        });

        // Wrap in SET OF (tag 0x31) — this is what gets hashed for signing
        var setWriter = new AsnWriter(AsnEncodingRules.DER);
        setWriter.PushSetOf();
        setWriter.WriteEncodedValue(contentTypeAttr);
        setWriter.WriteEncodedValue(messageDigestAttr);
        setWriter.PopSetOf();
        return setWriter.Encode();
    }

    /// <summary>
    /// Build a complete Authenticode PKCS#7 ContentInfo wrapping a CMS SignedData.
    /// </summary>
    public static byte[] BuildAuthenticodePkcs7(
        byte[] spcIndirectDataDer,
        byte[] signatureBytes,
        byte[] signingCertDer,
        string digestAlgOid,
        byte[] authenticatedAttrsDer)
    {
        // Parse cert to extract issuer + serial
        using var cert = X509CertificateLoader.LoadCertificate(signingCertDer);
        byte[] issuerDer = cert.IssuerName.RawData;
        byte[] serialBE = cert.GetSerialNumber(); // little-endian
        Array.Reverse(serialBE); // convert to big-endian

        // Determine signature algorithm OID based on cert key type
        string sigAlgOid = GetSignatureAlgorithmOid(cert, digestAlgOid);

        // Build ContentInfo
        var w = new AsnWriter(AsnEncodingRules.DER);
        w.PushSequence(); // ContentInfo
        w.WriteObjectIdentifier(OID_SIGNED_DATA);

        // [0] EXPLICIT SignedData
        var explicit0 = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
        w.PushSequence(explicit0);

        // ── SignedData SEQUENCE ──
        w.PushSequence();

        // version (CMS v3 because contentType != id-data)
        w.WriteInteger(3);

        // digestAlgorithms SET OF
        w.PushSetOf();
        WriteAlgorithmIdentifier(w, digestAlgOid);
        w.PopSetOf();

        // encapContentInfo
        w.PushSequence();
        w.WriteObjectIdentifier(OID_SPC_INDIRECT_DATA);
        // [0] EXPLICIT { OCTET STRING { spcIndirectData } } — standard CMS format
        w.PushSequence(explicit0);
        w.WriteOctetString(spcIndirectDataDer);
        w.PopSequence(explicit0);
        w.PopSequence();

        // certificates [0] IMPLICIT SET OF Certificate
        var implicit0 = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
        w.PushSetOf(implicit0);
        w.WriteEncodedValue(signingCertDer);
        w.PopSetOf(implicit0);

        // signerInfos SET OF SignerInfo
        w.PushSetOf();
        WriteSignerInfo(w, issuerDer, serialBE, digestAlgOid, sigAlgOid,
                        authenticatedAttrsDer, signatureBytes);
        w.PopSetOf();

        w.PopSequence(); // end SignedData
        w.PopSequence(explicit0);
        w.PopSequence(); // end ContentInfo

        return w.Encode();
    }

    /// <summary>
    /// Hash the content for the messageDigest attribute.
    /// </summary>
    public static byte[] HashContent(byte[] content, string digestAlgOid)
    {
        return digestAlgOid switch
        {
            NativeMethods.OID_SHA256 or "2.16.840.1.101.3.4.2.1" => SHA256.HashData(content),
            NativeMethods.OID_SHA384 or "2.16.840.1.101.3.4.2.2" => SHA384.HashData(content),
            NativeMethods.OID_SHA512 or "2.16.840.1.101.3.4.2.3" => SHA512.HashData(content),
            _ => SHA256.HashData(content)
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Private helpers
    // ═══════════════════════════════════════════════════════════════════

    private static byte[] BuildAttribute(string oid, Action<AsnWriter> writeValue)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        w.PushSequence();
        w.WriteObjectIdentifier(oid);
        w.PushSetOf();
        writeValue(w);
        w.PopSetOf();
        w.PopSequence();
        return w.Encode();
    }

    private static void WriteAlgorithmIdentifier(AsnWriter w, string oid)
    {
        w.PushSequence();
        w.WriteObjectIdentifier(oid);
        // Per RFC 5754, SHA-2 algorithm identifiers SHOULD omit the parameters field.
        // (Many implementations accept NULL too, but we match .NET's SignedCms output.)
        w.PopSequence();
    }

    private static void WriteSignerInfo(
        AsnWriter w,
        byte[] issuerDer,
        byte[] serialBigEndian,
        string digestAlgOid,
        string sigAlgOid,
        byte[] authenticatedAttrsDer,
        byte[] signatureBytes)
    {
        w.PushSequence(); // SignerInfo

        // version
        w.WriteInteger(1);

        // sid: IssuerAndSerialNumber
        w.PushSequence();
        w.WriteEncodedValue(issuerDer); // Name (already DER)
        w.WriteInteger(serialBigEndian); // CertificateSerialNumber
        w.PopSequence();

        // digestAlgorithm
        WriteAlgorithmIdentifier(w, digestAlgOid);

        // signedAttrs [0] IMPLICIT — re-tag from SET (0x31) to [0] (0xA0)
        byte[] implicitAttrs = ReTagSetToImplicit0(authenticatedAttrsDer);
        w.WriteEncodedValue(implicitAttrs);

        // signatureAlgorithm
        WriteAlgorithmIdentifier(w, sigAlgOid);

        // signature
        w.WriteOctetString(signatureBytes);

        w.PopSequence(); // end SignerInfo
    }

    /// <summary>
    /// Re-tag the first byte of the DER-encoded SET OF (tag 0x31)
    /// to IMPLICIT [0] CONSTRUCTED (tag 0xA0) for embedding in SignerInfo.
    /// The content and length bytes are identical.
    /// </summary>
    private static byte[] ReTagSetToImplicit0(byte[] setOfDer)
    {
        if (setOfDer.Length == 0 || setOfDer[0] != 0x31)
            throw new ArgumentException("Expected DER SET OF (tag 0x31)");

        byte[] result = (byte[])setOfDer.Clone();
        result[0] = 0xA0; // context-specific, constructed, tag 0
        return result;
    }

    private static string GetSignatureAlgorithmOid(X509Certificate2 cert, string digestAlgOid)
    {
        string keyAlg = cert.GetKeyAlgorithm();

        // RSA: 1.2.840.113549.1.1.1
        if (keyAlg == OID_RSA_ENCRYPTION || keyAlg == "1.2.840.113549.1.1.1")
        {
            return digestAlgOid switch
            {
                NativeMethods.OID_SHA384 => OID_SHA384_WITH_RSA,
                NativeMethods.OID_SHA512 => OID_SHA512_WITH_RSA,
                _ => OID_SHA256_WITH_RSA
            };
        }

        // ECC: 1.2.840.10045.2.1
        if (keyAlg == "1.2.840.10045.2.1")
        {
            return digestAlgOid switch
            {
                NativeMethods.OID_SHA384 => OID_ECDSA_WITH_SHA384,
                NativeMethods.OID_SHA512 => OID_ECDSA_WITH_SHA512,
                _ => OID_ECDSA_WITH_SHA256
            };
        }

        // Fallback: use RSA-SHA256
        return OID_SHA256_WITH_RSA;
    }
}
