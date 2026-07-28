using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static OfficeVbaSigner.NativeMethods;

namespace OfficeVbaSigner;

internal class Program
{
    private const string Usage = @"
OfficeVbaSigner — Signs VBA macros in Office files using Azure Trusted Signing.
Bypasses signtool's /dlib limitation with third-party SIPs by calling the SIP
directly and using the Azure.CodeSigning managed SDK for remote signing.

Usage:
  OfficeVbaSigner <file> --metadata <json> [options]

Required:
  <file>                  Office file containing VBA macros (.xlsm, .docm, .xls, etc.)
  --metadata <json>       Path to the metadata JSON file (same format as signtool /dmdf)
                          Keys: Endpoint, CodeSigningAccountName, CertificateProfileName

Options:
  --alg <sha256|sha384|sha512>   Hash algorithm (default: sha256)
  --passes <1|2|3>               Number of signing passes (default: 3 for triple-sign)
  --clear                        Remove existing signatures before signing
  --verbose                      Show detailed progress

Example:
  OfficeVbaSigner ""C:\Files\macros.xlsm"" ^
    --metadata ""C:\Config\metadata.json"" ^
    --alg sha256 --passes 3 --clear
";

    static int Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "--help" or "-h" or "help" or "/?")
        {
            Console.Write(Usage);
            return 0;
        }

        // Parse arguments
        string filePath = args[0];
        string? metadataPath = null;
        string algName = "sha256";
        int passes = 3;
        bool clearFirst = false, verbose = false, testLocal = false;

        for (int i = 1; i < args.Length; i++)
        {
            switch (args[i].ToLowerInvariant())
            {
                case "--metadata": metadataPath = args[++i]; break;
                case "--alg":    algName = args[++i].ToLowerInvariant(); break;
                case "--passes": passes = int.Parse(args[++i]); break;
                case "--clear":  clearFirst = true; break;
                case "--verbose": verbose = true; break;
                case "--test-local": testLocal = true; break;
            }
        }

        string digestAlgOid = algName switch
        {
            "sha384" => OID_SHA384,
            "sha512" => OID_SHA512,
            _ => OID_SHA256
        };

        if (!testLocal && metadataPath is null)
        {
            Console.Error.WriteLine("Error: --metadata is required.");
            return 1;
        }

        if (!File.Exists(filePath))    { Console.Error.WriteLine($"File not found: {filePath}"); return 1; }
        if (!testLocal && !File.Exists(metadataPath!)){ Console.Error.WriteLine($"Metadata not found: {metadataPath}"); return 1; }

        filePath = Path.GetFullPath(filePath);

        if (testLocal)
        {
            // Quick test: sign with local self-signed cert to verify SIP interop
            if (!CryptSIPRetrieveSubjectGuid(filePath, IntPtr.Zero, out Guid sipGuid))
            {
                Console.Error.WriteLine($"No SIP registered for this file type.");
                return 1;
            }
            GCHandle guidHandle = GCHandle.Alloc(sipGuid, GCHandleType.Pinned);
            IntPtr pAlgOid = Marshal.StringToHGlobalAnsi(digestAlgOid);
            try
            {
                if (clearFirst) ClearSignatures(filePath, guidHandle.AddrOfPinnedObject(), pAlgOid);
                return TestSignWithLocalCert(filePath, guidHandle.AddrOfPinnedObject(),
                    pAlgOid, digestAlgOid, verbose) ? 0 : 1;
            }
            finally
            {
                Marshal.FreeHGlobal(pAlgOid);
                guidHandle.Free();
            }
        }

        try
        {
            return RunSigning(filePath, metadataPath, digestAlgOid, passes, clearFirst, verbose);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Fatal error: {ex.Message}");
            if (verbose) Console.Error.WriteLine(ex.StackTrace);
            return 1;
        }
    }

    static int RunSigning(string filePath, string metadataPath,
                           string digestAlgOid, int passes, bool clearFirst, bool verbose)
    {
        // ── 1. Determine SIP GUID for this file ────────────────────────
        if (!CryptSIPRetrieveSubjectGuid(filePath, IntPtr.Zero, out Guid sipGuid))
        {
            int err = Marshal.GetLastWin32Error();
            Console.Error.WriteLine($"No SIP registered for this file type (error 0x{err:X8}).");
            Console.Error.WriteLine("Ensure msosip.dll / msosipx.dll is registered (regsvr32).");
            return 1;
        }
        if (verbose) Console.WriteLine($"SIP GUID: {sipGuid}");

        // ── 2. Initialize Azure Trusted Signing client ─────────────────
        if (verbose) Console.WriteLine("Initializing Azure Trusted Signing client...");
        var signer = AzureSigner.FromMetadataFile(metadataPath);
        if (verbose) Console.WriteLine("Azure client ready (using DefaultAzureCredential).");

        // ── 3. Pin native resources ────────────────────────────────────
        GCHandle guidHandle = GCHandle.Alloc(sipGuid, GCHandleType.Pinned);
        IntPtr pAlgOid = Marshal.StringToHGlobalAnsi(digestAlgOid);

        try
        {
            // ── 4. Clear existing signatures if requested ──────────────
            if (clearFirst)
            {
                if (verbose) Console.WriteLine("Clearing existing signatures...");
                ClearSignatures(filePath, guidHandle.AddrOfPinnedObject(), pAlgOid);
            }

            // ── 5. Triple-sign loop ────────────────────────────────────
            for (int pass = 1; pass <= passes; pass++)
            {
                Console.WriteLine($"── Signing pass {pass}/{passes} ──");

                bool ok = SignOnePass(filePath, guidHandle.AddrOfPinnedObject(),
                                     pAlgOid, digestAlgOid, signer, verbose);
                if (!ok) return 1;

                Console.WriteLine($"   Pass {pass} completed successfully.");
            }

            Console.WriteLine($"\nAll {passes} signing pass(es) completed for: {filePath}");
            return 0;
        }
        finally
        {
            Marshal.FreeHGlobal(pAlgOid);
            guidHandle.Free();
        }
    }

    /// <summary>
    /// Execute a single signing pass (synchronous to maintain COM thread affinity):
    ///   1. Get indirect data (digest) from the SIP
    ///   2. Encode it as DER → SPC_INDIRECT_DATA
    ///   3. Use .NET SignedCms with a custom RSA wrapper that delegates to Azure
    ///   4. Embed the PKCS#7 via the SIP
    /// </summary>
    static bool SignOnePass(string filePath, IntPtr pGuid, IntPtr pAlgOid,
                            string digestAlgOid, AzureSigner signer, bool verbose)
    {
        // ── Step 1: Get IndirectData hash via subprocess ─────────────────
        // The SIP uses process-global mutable state that gets corrupted by the Azure SDK.
        // Solution: run all SIP operations in clean subprocesses.
        var fields = RunHashSubprocess(filePath, verbose);
        if (fields == null) return false;

        if (verbose)
        {
            Console.WriteLine($"   Data OID: {fields.Value.DataOid}");
            Console.WriteLine($"   Digest Alg: {fields.Value.DigestAlgOid}");
            Console.WriteLine($"   Digest: {Convert.ToHexString(fields.Value.Digest)}");
        }

        byte[] spcDer = Pkcs7Builder.EncodeSpcIndirectData(fields.Value);
        if (verbose) Console.WriteLine($"   Encoded SPC_INDIRECT_DATA: {spcDer.Length} bytes");

        // ── Step 2: Get certificate from Azure + build SignedCms ────────
        if (verbose) Console.WriteLine("   Fetching signing certificate from Azure...");

        // First do a dummy sign to get the certificate
        byte[] dummyDigest = new byte[32]; // placeholder
        var (_, certBytes) = signer.SignDigestAsync(dummyDigest, digestAlgOid)
            .GetAwaiter().GetResult();
        byte[] certDer = ParseCertificate(certBytes);

        if (verbose)
        {
            using var certInfo = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(certDer);
            Console.WriteLine($"   Certificate: {certInfo.Subject}");
            Console.WriteLine($"   Issuer: {certInfo.Issuer}");
        }

        // Build SignedCms using a custom RSA that delegates SignHash to Azure
        var contentInfo = new System.Security.Cryptography.Pkcs.ContentInfo(
            new Oid("1.3.6.1.4.1.311.2.1.4"), spcDer);
        var signedCms = new System.Security.Cryptography.Pkcs.SignedCms(contentInfo, detached: false);

        using var signingCert = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(certDer);
        using var azureRsa = new AzureRsa(signer, digestAlgOid);
        azureRsa.LoadPublicKeyFromCert(certDer);

        var cmsSigner = new System.Security.Cryptography.Pkcs.CmsSigner(
            System.Security.Cryptography.Pkcs.SubjectIdentifierType.IssuerAndSerialNumber,
            signingCert, azureRsa, RSASignaturePadding.Pkcs1);
        cmsSigner.DigestAlgorithm = new Oid(digestAlgOid);
        cmsSigner.IncludeOption = System.Security.Cryptography.X509Certificates.X509IncludeOption.EndCertOnly;

        if (verbose) Console.WriteLine("   Computing CMS signature via Azure...");
        signedCms.ComputeSignature(cmsSigner);

        byte[] pkcs7 = signedCms.Encode();
        if (verbose) Console.WriteLine($"   PKCS#7 size: {pkcs7.Length} bytes");

        // ── Step 3: Embed signature via subprocess ─────────────────────
        string pkcs7TempPath = Path.Combine(Path.GetTempPath(), $"vbasign_{Guid.NewGuid():N}.p7");
        File.WriteAllBytes(pkcs7TempPath, pkcs7);
        try
        {
            if (verbose) Console.WriteLine($"   Invoking PutSignedDataMsg via subprocess...");
            bool putOk = RunPutSubprocess(filePath, pkcs7TempPath, verbose);
            if (!putOk) return false;
            if (verbose) Console.WriteLine($"   Signature embedded successfully.");
        }
        finally
        {
            File.Delete(pkcs7TempPath);
        }

        return true;
    }

    static void ClearSignatures(string filePath, IntPtr pGuid, IntPtr pAlgOid)
    {
        var si = new SIP_SUBJECTINFO();
        si.cbSize = 0x50;
        si.pgSubjectType = pGuid;
        si.hFile = INVALID_HANDLE_VALUE;
        si.pwsFileName = Marshal.StringToHGlobalUni(filePath);
        si.dwEncodingType = ENCODING;
        si.digestAlgObjId = pAlgOid;
        si.dwIntVersion = 1;

        try
        {
            for (int i = 0; i < 5; i++)
            {
                if (!CryptSIPRemoveSignedDataMsg(ref si, 0))
                    break;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(si.pwsFileName);
        }
    }

    /// <summary>
    /// Runs CryptSIPCreateIndirectData in a subprocess to get the file hash.
    /// Returns the IndirectData fields needed to build the PKCS#7.
    /// </summary>
    static IndirectDataFields? RunHashSubprocess(string filePath, bool verbose)
    {
        string putTestExe = FindPutTestExe();
        if (putTestExe == null!) return null;

        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = putTestExe,
            Arguments = $"\"{filePath}\" --hash",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        using var proc = System.Diagnostics.Process.Start(psi)!;
        string stdout = proc.StandardOutput.ReadToEnd();
        string stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit();

        if (proc.ExitCode != 0)
        {
            Console.Error.WriteLine($"   Hash subprocess failed (exit={proc.ExitCode}):");
            if (!string.IsNullOrWhiteSpace(stderr))
                Console.Error.Write($"   {stderr}");
            return null;
        }

        // Parse structured output
        var lines = stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        string? dataOid = null, digestAlg = null;
        byte[]? dataValue = null, digest = null;
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("DATA_OID=")) dataOid = trimmed["DATA_OID=".Length..];
            else if (trimmed.StartsWith("DATA_VALUE=")) dataValue = Convert.FromHexString(trimmed["DATA_VALUE=".Length..]);
            else if (trimmed.StartsWith("DIGEST_ALG=")) digestAlg = trimmed["DIGEST_ALG=".Length..];
            else if (trimmed.StartsWith("DIGEST=")) digest = Convert.FromHexString(trimmed["DIGEST=".Length..]);
        }

        if (dataOid == null || digestAlg == null || digest == null || dataValue == null)
        {
            Console.Error.WriteLine("   Hash subprocess returned incomplete data.");
            return null;
        }

        return new IndirectDataFields
        {
            DataOid = dataOid,
            DataValue = dataValue,
            DigestAlgOid = digestAlg,
            Digest = digest,
            DigestAlgParams = [],
        };
    }

    /// <summary>
    /// Runs CryptSIPCreateIndirectData + CryptSIPPutSignedDataMsg in a subprocess.
    /// This avoids the SIP state corruption caused by the Azure SDK's crypto operations.
    /// Uses PutTest.exe which is a minimal helper that calls these functions in a clean process.
    /// </summary>
    static bool RunPutSubprocess(string filePath, string pkcs7Path, bool verbose)
    {
        string putTestExe = FindPutTestExe();
        if (putTestExe == null!) { Console.Error.WriteLine("   PutTest helper not found."); return false; }

        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = putTestExe,
            Arguments = $"\"{filePath}\" \"{pkcs7Path}\"",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        using var proc = System.Diagnostics.Process.Start(psi)!;
        string stdout = proc.StandardOutput.ReadToEnd();
        string stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit();

        if (verbose && !string.IsNullOrWhiteSpace(stdout))
        {
            foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                Console.WriteLine($"   [Put] {line.TrimEnd()}");
        }

        if (proc.ExitCode != 0)
        {
            Console.Error.WriteLine($"   PutSignedDataMsg subprocess failed (exit={proc.ExitCode}):");
            if (!string.IsNullOrWhiteSpace(stderr))
                Console.Error.Write($"   {stderr}");
            return false;
        }
        return true;
    }

    static string FindPutTestExe()
    {
        // Search for PutTest.exe in known locations
        string[] candidates = [
            Path.Combine(AppContext.BaseDirectory, "PutTest.exe"),
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "PutTest",
                "bin", "Release", "net10.0-windows", "win-x86", "PutTest.exe")),
            Path.GetFullPath(Path.Combine(".", "..", "PutTest",
                "bin", "Release", "net10.0-windows", "win-x86", "PutTest.exe")),
        ];
        foreach (var c in candidates)
            if (File.Exists(c)) return c;
        Console.Error.WriteLine("   PutTest helper not found. Build PutTest project first.");
        return null!;
    }

    static void PrintPutError(int err)
    {
        switch (unchecked((uint)err))
        {
            case 0x80004003:
                Console.Error.WriteLine("   → E_POINTER: Invalid parameter (null pointer).");
                break;
            case 0x80004002:
                Console.Error.WriteLine("   → E_NOINTERFACE: SIP interface error.");
                break;
            case 0x8007000D:
                Console.Error.WriteLine("   → ERROR_INVALID_DATA: The PKCS#7 structure is invalid.");
                break;
            case 0x800B0106:
                Console.Error.WriteLine("   → CERT_E_WRONG_USAGE: Certificate lacks Code Signing EKU.");
                break;
            case 0x80070005:
                Console.Error.WriteLine("   → E_ACCESSDENIED: File or signing access denied.");
                break;
            case 0x8007000E:
                Console.Error.WriteLine("   → E_OUTOFMEMORY.");
                break;
        }
    }

    /// <summary>
    /// TEST: Sign using a local self-signed certificate and .NET's SignedCms,
    /// to verify that our SIP_SUBJECTINFO struct + P/Invoke are correct.
    /// If this works, the issue is in our manual PKCS#7 builder.
    /// </summary>
    static bool TestSignWithLocalCert(string filePath, IntPtr pGuid, IntPtr pAlgOid,
                                      string digestAlgOid, bool verbose)
    {
        // Test: use the Azure cert embedded in the PKCS#7 but sign with a LOCAL key.
        // This isolates whether the crash is due to the cert content or the signature.
        byte[] azureCertDer;
        string metaFile = Path.Combine(Path.GetDirectoryName(filePath)!, "metadata.json");
        if (File.Exists(metaFile))
        {
            Console.WriteLine("[TEST] Fetching Azure cert to test with local key...");
            var tempSigner = AzureSigner.FromMetadataFile(metaFile);
            var (_, cb) = tempSigner.SignDigestAsync(new byte[32], digestAlgOid)
                .GetAwaiter().GetResult();
            azureCertDer = ParseCertificate(cb);
            Console.WriteLine($"[TEST] Azure cert: {azureCertDer.Length} bytes");
        }
        else
        {
            // Fallback: use a large self-signed cert
            using var tmpRsa = System.Security.Cryptography.RSA.Create(3072);
            var tmpReq = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                "CN=Test", tmpRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            tmpReq.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension(
                new System.Security.Cryptography.OidCollection { new Oid("1.3.6.1.5.5.7.3.3") }, false));
            using var tmpCert = tmpReq.CreateSelfSigned(DateTimeOffset.Now.AddMinutes(-5), DateTimeOffset.Now.AddHours(1));
            azureCertDer = tmpCert.RawData;
        }

        // Create a local RSA key matching the Azure cert's key size
        using var azureCertParsed = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(azureCertDer);
        using var pubKey = System.Security.Cryptography.X509Certificates.RSACertificateExtensions.GetRSAPublicKey(azureCertParsed)!;
        int keySize = pubKey.KeySize;
        Console.WriteLine($"[TEST] Azure cert key size: {keySize} bits, Subject: {azureCertParsed.Subject}");

        // Create a self-signed cert with SAME key size (signature won't verify but tests structure)
        using var localRsa = System.Security.Cryptography.RSA.Create(keySize);
        var req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            azureCertParsed.Subject, localRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension(
            new System.Security.Cryptography.OidCollection { new Oid("1.3.6.1.5.5.7.3.3") }, false));
        using var localCert = req.CreateSelfSigned(DateTimeOffset.Now.AddMinutes(-5), DateTimeOffset.Now.AddHours(1));
        Console.WriteLine($"[TEST] Created local cert: {localCert.RawData.Length} bytes");

        // Now use CmsSigner with the AZURE CERT but LOCAL RSA key
        // SignedCms will embed azureCert but sign with localRsa
        // The signature won't verify, but we test if the SIP crashes due to the cert content

        // ── Step 1: CryptSIPCreateIndirectData ─────────────────────────
        var si = new SIP_SUBJECTINFO();
        si.cbSize = 0x50;
        si.pgSubjectType = pGuid;
        si.hFile = INVALID_HANDLE_VALUE;
        si.pwsFileName = Marshal.StringToHGlobalUni(filePath);
        si.dwEncodingType = ENCODING;
        si.digestAlgObjId = pAlgOid;
        si.dwIntVersion = 1;

        IntPtr pIndirectData = IntPtr.Zero;
        try
        {
            uint cbIndirectData = 0;
            if (!CryptSIPCreateIndirectData(ref si, ref cbIndirectData, IntPtr.Zero))
            {
                Console.Error.WriteLine($"[TEST] CreateIndirectData size query failed: 0x{Marshal.GetLastWin32Error():X8}");
                return false;
            }

            pIndirectData = Marshal.AllocHGlobal((int)cbIndirectData);
            if (!CryptSIPCreateIndirectData(ref si, ref cbIndirectData, pIndirectData))
            {
                Console.Error.WriteLine($"[TEST] CreateIndirectData fill failed: 0x{Marshal.GetLastWin32Error():X8}");
                return false;
            }

            var fields = ReadIndirectData(pIndirectData);
            Console.WriteLine($"[TEST] IndirectData: OID={fields.DataOid}, Digest={Convert.ToHexString(fields.Digest)}");

            // ── Step 2: Encode SPC_INDIRECT_DATA ──────────────────────────
            byte[] spcDer = Pkcs7Builder.EncodeSpcIndirectData(fields);

            // ── Step 3: Use .NET SignedCms, sign with localRsa, embed azureCert ─
            var contentInfo = new System.Security.Cryptography.Pkcs.ContentInfo(
                new Oid("1.3.6.1.4.1.311.2.1.4"), spcDer);
            var signedCms = new System.Security.Cryptography.Pkcs.SignedCms(contentInfo, detached: false);

            // CmsSigner with the Azure cert + local RSA (mismatched, but tests cert embedding)
            var cmsSigner = new System.Security.Cryptography.Pkcs.CmsSigner(
                System.Security.Cryptography.Pkcs.SubjectIdentifierType.IssuerAndSerialNumber,
                azureCertParsed, localRsa, RSASignaturePadding.Pkcs1);
            cmsSigner.DigestAlgorithm = new Oid(digestAlgOid);
            cmsSigner.IncludeOption = System.Security.Cryptography.X509Certificates.X509IncludeOption.EndCertOnly;
            signedCms.ComputeSignature(cmsSigner);

            byte[] pkcs7 = signedCms.Encode();
            Console.WriteLine($"[TEST] SignedCms PKCS#7 (azure cert + local key): {pkcs7.Length} bytes");

            string dumpPath = Path.ChangeExtension(filePath, ".test_pkcs7.der");
            File.WriteAllBytes(dumpPath, pkcs7);
            Console.WriteLine($"[TEST] Dumped to: {dumpPath}");

            // ── Step 4: CryptSIPPutSignedDataMsg ───────────────────────────
            uint dwIndex = 0;
            GCHandle pkcs7Pin = GCHandle.Alloc(pkcs7, GCHandleType.Pinned);
            try
            {
                Console.WriteLine("[TEST] Calling CryptSIPPutSignedDataMsg...");
                if (!CryptSIPPutSignedDataMsg(ref si, ENCODING, ref dwIndex,
                                              (uint)pkcs7.Length, pkcs7Pin.AddrOfPinnedObject()))
                {
                    int err = Marshal.GetLastWin32Error();
                    Console.Error.WriteLine($"[TEST] PutSignedDataMsg FAILED (no crash!): 0x{err:X8}");
                    PrintPutError(err);
                    return false;
                }
                Console.WriteLine($"[TEST] PutSignedDataMsg SUCCESS! Index={dwIndex}");
                return true;
            }
            finally
            {
                pkcs7Pin.Free();
            }
        }
        finally
        {
            if (pIndirectData != IntPtr.Zero) Marshal.FreeHGlobal(pIndirectData);
            Marshal.FreeHGlobal(si.pwsFileName);
        }
    }

    /// <summary>
    /// Parse the certificate bytes returned by the Azure SDK.
    /// Handles DER, PEM, and PKCS#7/certificate-chain formats.
    /// Returns the end-entity certificate as raw DER.
    /// </summary>
    static byte[] ParseCertificate(byte[] certBytes)
    {
        // Try raw DER first (most common)
        if (certBytes.Length > 0 && certBytes[0] == 0x30)
        {
            try
            {
                using var cert = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(certBytes);
                return certBytes; // It's valid DER
            }
            catch
            {
                // Might be a PKCS#7 chain starting with 0x30
            }
        }

        // Try PEM
        if (certBytes.Length > 10 && System.Text.Encoding.ASCII.GetString(certBytes, 0, 10).StartsWith("-----"))
        {
            var pem = System.Text.Encoding.ASCII.GetString(certBytes);
            using var cert = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(
                Convert.FromBase64String(
                    pem.Replace("-----BEGIN CERTIFICATE-----", "")
                       .Replace("-----END CERTIFICATE-----", "")
                       .Trim()));
            return cert.RawData;
        }

        // Try as PKCS#7 collection (extract first/leaf cert)
        try
        {
            var collection = new System.Security.Cryptography.X509Certificates.X509Certificate2Collection();
            collection.Import(certBytes);
            if (collection.Count > 0)
            {
                // Return the end-entity cert (typically first, or the one without CA basic constraint)
                foreach (var c in collection)
                {
                    var bc = c.Extensions["2.5.29.19"]; // Basic Constraints
                    if (bc == null || !((System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension)bc).CertificateAuthority)
                        return c.RawData;
                }
                return collection[0].RawData;
            }
        }
        catch { }

        // Last resort: return as-is and let caller handle the error
        return certBytes;
    }
}
