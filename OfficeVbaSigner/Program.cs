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
    --passes <1>                   Number of signing passes (legacy VBA format)
  --timestamp <url>              RFC 3161 timestamp server URL (e.g. http://timestamp.digicert.com)
  --clear                        Remove existing signatures before signing
  --verbose                      Show detailed progress

Example:
  OfficeVbaSigner ""C:\Files\macros.xlsm"" ^
    --metadata ""C:\Config\metadata.json"" ^
    --alg sha256 --passes 1 --clear
";

    static int Main(string[] args)
    {
        // ── Internal subprocess commands (self-invocation for SIP isolation) ──
        if (args.Length >= 3 && args[0] == "--sip-hash")
            return SipHash(args[1], args[2]);

        if (args.Length >= 3 && args[0] == "--sip-clear")
            return SipClear(args[1], args[2]);
        if (args.Length >= 4 && args[0] == "--sip-put")
            return SipPut(args[1], args[2], args[3]);

        // ── Normal CLI entry point ──
        if (args.Length == 0 || args[0] is "--help" or "-h" or "help" or "/?")
        {
            Console.Write(Usage);
            return 0;
        }

        // Parse arguments
        string filePath = args[0];
        string? metadataPath = null;
        string algName = "sha256";
        string? timestampUrl = null;
        int passes = 1;
        bool clearFirst = false, verbose = false;

        for (int i = 1; i < args.Length; i++)
        {
            switch (args[i].ToLowerInvariant())
            {
                case "--metadata":  metadataPath = args[++i]; break;
                case "--alg":       algName = args[++i].ToLowerInvariant(); break;
                case "--timestamp": timestampUrl = args[++i]; break;
                case "--passes":    passes = int.Parse(args[++i]); break;
                case "--clear":     clearFirst = true; break;
                case "--verbose":   verbose = true; break;
            }
        }

        string digestAlgOid = algName switch
        {
            "sha384" => OID_SHA384,
            "sha512" => OID_SHA512,
            _ => OID_SHA256
        };

        if (metadataPath is null)
        {
            Console.Error.WriteLine("Error: --metadata is required.");
            return 1;
        }

        if (!File.Exists(filePath))    { Console.Error.WriteLine($"File not found: {filePath}"); return 1; }
        if (!File.Exists(metadataPath)){ Console.Error.WriteLine($"Metadata not found: {metadataPath}"); return 1; }

        filePath = Path.GetFullPath(filePath);

        try
        {
            return RunSigning(filePath, metadataPath, digestAlgOid, passes, clearFirst, verbose, timestampUrl);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Fatal error: {ex.Message}");
            if (verbose) Console.Error.WriteLine(ex.StackTrace);
            return 1;
        }
    }

    static int RunSigning(string filePath, string metadataPath,
                           string digestAlgOid, int passes, bool clearFirst, bool verbose,
                           string? timestampUrl)
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
                                     pAlgOid, digestAlgOid, signer, verbose, timestampUrl);
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
    /// Execute a single signing pass:
    ///   1. Get indirect data (digest) from the SIP via self-subprocess
    ///   2. Encode it as DER → SPC_INDIRECT_DATA
    ///   3. Use .NET SignedCms with a custom RSA wrapper that delegates to Azure
    ///   4. Embed the PKCS#7 via self-subprocess
    ///
    /// SIP operations run in clean child processes (self-invocation with --sip-hash / --sip-put)
    /// because msosipx.dll uses process-global mutable state that gets corrupted by the Azure SDK.
    /// </summary>
    static bool SignOnePass(string filePath, IntPtr pGuid, IntPtr pAlgOid,
                            string digestAlgOid, AzureSigner signer, bool verbose,
                            string? timestampUrl)
    {
        // ── Step 1: Get IndirectData hash via self-subprocess ────────────
        var fields = RunSipHashSubprocess(filePath, digestAlgOid, verbose);
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

        // Dummy sign to obtain the certificate (the SDK requires a sign op to return it)
        byte[] dummyDigest = new byte[32];
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

        // ── Step 2b: Add RFC 3161 timestamp if requested ───────────────
        if (timestampUrl is not null)
        {
            if (verbose) Console.WriteLine($"   Requesting RFC 3161 timestamp from {timestampUrl}...");
            AddRfc3161Timestamp(signedCms, timestampUrl, digestAlgOid, verbose);
            if (verbose) Console.WriteLine("   Timestamp added successfully.");
        }

        byte[] pkcs7 = signedCms.Encode();
        if (verbose) Console.WriteLine($"   PKCS#7 size: {pkcs7.Length} bytes");

        // Fail before touching the Office file if the CMS is not
        // cryptographically self-consistent.
        var verificationCms = new System.Security.Cryptography.Pkcs.SignedCms();
        verificationCms.Decode(pkcs7);
        verificationCms.CheckSignature(verifySignatureOnly: true);
        if (verbose) Console.WriteLine("   CMS signature verified locally.");

        // ── Step 3: Embed signature via self-subprocess ─────────────────
        string pkcs7TempPath = Path.Combine(Path.GetTempPath(), $"test_vbasign_{Guid.NewGuid():N}.p7");
        File.WriteAllBytes(pkcs7TempPath, pkcs7);
        try
        {
            if (verbose) Console.WriteLine($"   Invoking PutSignedDataMsg via subprocess...");
            bool putOk = RunSipPutSubprocess(filePath, pkcs7TempPath, digestAlgOid, verbose);
            if (!putOk) return false;
            if (verbose) Console.WriteLine($"   Signature embedded successfully.");
        }
        finally
        {
            File.Delete(pkcs7TempPath);
        }

        return true;
    }

    static int ClearSignatures(string filePath, IntPtr pGuid, IntPtr pAlgOid)
    {
        var si = new SIP_SUBJECTINFO();
        si.cbSize = 0x50;
        si.pgSubjectType = pGuid;
        si.hFile = INVALID_HANDLE_VALUE;
        si.pwsFileName = Marshal.StringToHGlobalUni(filePath);
        si.dwEncodingType = ENCODING;
        si.digestAlgObjId = pAlgOid;
        si.dwIntVersion = 1;

        int removed = 0;
        try
        {
            for (int i = 0; i < 5; i++)
            {
                if (!CryptSIPRemoveSignedDataMsg(ref si, 0))
                    break;
                removed++;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(si.pwsFileName);
        }

        return removed;
    }

    /// <summary>
    /// Request an RFC 3161 timestamp from a TSA and embed it as an unsigned attribute
    /// (OID 1.3.6.1.4.1.311.3.3.1) in the first signer info.
    /// </summary>
    static void AddRfc3161Timestamp(
        System.Security.Cryptography.Pkcs.SignedCms signedCms,
        string tsaUrl,
        string digestAlgOid,
        bool verbose)
    {
        var signerInfo = signedCms.SignerInfos[0];

        // Map digest OID to HashAlgorithmName
        var hashAlg = digestAlgOid switch
        {
            OID_SHA384 => HashAlgorithmName.SHA384,
            OID_SHA512 => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256
        };

        // Build the timestamp request from the signer's encrypted digest
        var tsReq = System.Security.Cryptography.Pkcs.Rfc3161TimestampRequest.CreateFromSignerInfo(
            signerInfo,
            hashAlg,
            requestSignerCertificates: true,
            nonce: null);

        byte[] reqBytes = tsReq.Encode();
        if (verbose) Console.WriteLine($"   Timestamp request: {reqBytes.Length} bytes");

        // Send to TSA via HTTP POST
        using var http = new HttpClient();
        http.Timeout = TimeSpan.FromSeconds(30);
        var content = new ByteArrayContent(reqBytes);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/timestamp-query");

        var response = http.Send(new HttpRequestMessage(HttpMethod.Post, tsaUrl) { Content = content });
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException(
                $"Timestamp server returned HTTP {(int)response.StatusCode}: {response.ReasonPhrase}");

        byte[] tsaRespBytes = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
        if (verbose) Console.WriteLine($"   Timestamp response: {tsaRespBytes.Length} bytes");

        // Process the RFC 3161 response and extract the timestamp token
        var token = tsReq.ProcessResponse(tsaRespBytes, out int pkiStatus);
        if (verbose) Console.WriteLine($"   TSA status: {pkiStatus} (0=granted)");

        // Embed as unsigned attribute (szOID_RFC3161_counterSign)
        byte[] tokenBytes = token.AsSignedCms().Encode();
        signerInfo.AddUnsignedAttribute(new AsnEncodedData("1.3.6.1.4.1.311.3.3.1", tokenBytes));
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Self-subprocess methods: invoke this same executable with internal args
    //  to isolate SIP operations from the Azure SDK's crypto interference.
    // ═══════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Invokes self with --sip-hash to get IndirectData from a clean process.
    /// </summary>
    static IndirectDataFields? RunSipHashSubprocess(string filePath, string digestAlgOid, bool verbose)
    {
        string self = Environment.ProcessPath
            ?? throw new InvalidOperationException("Cannot determine own executable path.");

        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = self,
            Arguments = $"--sip-hash \"{filePath}\" \"{digestAlgOid}\"",
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
            Console.Error.WriteLine($"   SIP hash subprocess failed (exit={proc.ExitCode}):");
            if (!string.IsNullOrWhiteSpace(stderr))
                Console.Error.Write($"   {stderr}");
            return null;
        }

        // Parse structured output
        var lines = stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        string? dataOid = null, digestAlg = null;
        byte[]? dataValue = null, digestAlgParams = null, digest = null;
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("DATA_OID=")) dataOid = trimmed["DATA_OID=".Length..];
            else if (trimmed.StartsWith("DATA_VALUE=")) dataValue = Convert.FromHexString(trimmed["DATA_VALUE=".Length..]);
            else if (trimmed.StartsWith("DIGEST_ALG=")) digestAlg = trimmed["DIGEST_ALG=".Length..];
            else if (trimmed.StartsWith("DIGEST_ALG_PARAMS=")) digestAlgParams = Convert.FromHexString(trimmed["DIGEST_ALG_PARAMS=".Length..]);
            else if (trimmed.StartsWith("DIGEST=")) digest = Convert.FromHexString(trimmed["DIGEST=".Length..]);
        }

        if (dataOid == null || digestAlg == null || digestAlgParams == null || digest == null || dataValue == null)
        {
            Console.Error.WriteLine("   SIP hash subprocess returned incomplete data.");
            return null;
        }

        return new IndirectDataFields
        {
            DataOid = dataOid,
            DataValue = dataValue,
            DigestAlgOid = digestAlg,
            Digest = digest,
            DigestAlgParams = digestAlgParams,
        };
    }

    /// <summary>
    /// Invokes self with --sip-put to embed the PKCS#7 in a clean process.
    /// </summary>
    static bool RunSipPutSubprocess(string filePath, string pkcs7Path, string digestAlgOid, bool verbose)
    {
        string self = Environment.ProcessPath
            ?? throw new InvalidOperationException("Cannot determine own executable path.");

        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = self,
            Arguments = $"--sip-put \"{filePath}\" \"{pkcs7Path}\" \"{digestAlgOid}\"",
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
                Console.WriteLine($"   [SIP] {line.TrimEnd()}");
        }

        if (proc.ExitCode != 0)
        {
            Console.Error.WriteLine($"   SIP put subprocess failed (exit={proc.ExitCode}):");
            if (!string.IsNullOrWhiteSpace(stderr))
                Console.Error.Write($"   {stderr}");
            return false;
        }
        return true;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Internal SIP subprocess entry points (invoked via --sip-hash / --sip-put)
    //  These run in a CLEAN process without any Azure SDK loaded, avoiding
    //  corruption of msosipx.dll's process-global mutable state.
    // ═══════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Subprocess mode: compute IndirectData and print fields to stdout.
    /// </summary>
    static int SipHash(string filePath, string digestAlgOid)
    {
        filePath = Path.GetFullPath(filePath);
        if (!File.Exists(filePath)) { Console.Error.WriteLine($"Not found: {filePath}"); return 1; }

        if (!CryptSIPRetrieveSubjectGuid(filePath, IntPtr.Zero, out Guid sipGuid))
        { Console.Error.WriteLine($"No SIP. Error: 0x{Marshal.GetLastWin32Error():X8}"); return 1; }

        var si = BuildSubjectInfo(filePath, sipGuid, digestAlgOid, out var handles);
        try
        {
            uint cb = 0;
            CryptSIPCreateIndirectData(ref si, ref cb, IntPtr.Zero);
            IntPtr pBuf = Marshal.AllocHGlobal((int)cb);
            if (!CryptSIPCreateIndirectData(ref si, ref cb, pBuf))
            {
                Console.Error.WriteLine($"CreateIndirectData failed: 0x{Marshal.GetLastWin32Error():X8}");
                Marshal.FreeHGlobal(pBuf);
                return 1;
            }

            // Read SPC_INDIRECT_DATA native struct (x86 layout)
            string dataOid = Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(pBuf, 0x00))!;
            uint dataValCb = (uint)Marshal.ReadInt32(pBuf, 0x04);
            IntPtr dataValPb = Marshal.ReadIntPtr(pBuf, 0x08);
            string sipDigestAlgOid = Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(pBuf, 0x0C))!;
            uint digestAlgParamCb = (uint)Marshal.ReadInt32(pBuf, 0x10);
            IntPtr digestAlgParamPb = Marshal.ReadIntPtr(pBuf, 0x14);
            uint digestCb = (uint)Marshal.ReadInt32(pBuf, 0x18);
            IntPtr digestPb = Marshal.ReadIntPtr(pBuf, 0x1C);

            byte[] dataVal = new byte[dataValCb];
            if (dataValCb > 0) Marshal.Copy(dataValPb, dataVal, 0, (int)dataValCb);
            byte[] digestAlgParams = new byte[digestAlgParamCb];
            if (digestAlgParamCb > 0) Marshal.Copy(digestAlgParamPb, digestAlgParams, 0, (int)digestAlgParamCb);
            byte[] digest = new byte[digestCb];
            if (digestCb > 0) Marshal.Copy(digestPb, digest, 0, (int)digestCb);

            Marshal.FreeHGlobal(pBuf);

            Console.WriteLine($"DATA_OID={dataOid}");
            Console.WriteLine($"DATA_VALUE={Convert.ToHexString(dataVal)}");
            Console.WriteLine($"DIGEST_ALG={sipDigestAlgOid}");
            Console.WriteLine($"DIGEST_ALG_PARAMS={Convert.ToHexString(digestAlgParams)}");
            Console.WriteLine($"DIGEST={Convert.ToHexString(digest)}");
            Console.WriteLine($"SIZE={cb}");
            return 0;
        }
        finally { FreeHandles(handles); }
    }

    static int SipClear(string filePath, string digestAlgOid)
    {
        filePath = Path.GetFullPath(filePath);
        if (!File.Exists(filePath)) { Console.Error.WriteLine($"Not found: {filePath}"); return 1; }

        if (!CryptSIPRetrieveSubjectGuid(filePath, IntPtr.Zero, out Guid sipGuid))
        { Console.Error.WriteLine($"No SIP. Error: 0x{Marshal.GetLastWin32Error():X8}"); return 1; }

        GCHandle guidHandle = GCHandle.Alloc(sipGuid, GCHandleType.Pinned);
        IntPtr algPtr = Marshal.StringToHGlobalAnsi(digestAlgOid);
        try
        {
            int removed = ClearSignatures(filePath, guidHandle.AddrOfPinnedObject(), algPtr);
            Console.WriteLine($"Removed={removed}");
            return 0;
        }
        finally
        {
            Marshal.FreeHGlobal(algPtr);
            guidHandle.Free();
        }
    }

    /// <summary>
    /// Subprocess mode: CreateIndirectData (to open file) then PutSignedDataMsg.
    /// </summary>
    static int SipPut(string filePath, string pkcs7Path, string digestAlgOid)
    {
        filePath = Path.GetFullPath(filePath);
        pkcs7Path = Path.GetFullPath(pkcs7Path);
        if (!File.Exists(filePath)) { Console.Error.WriteLine($"Not found: {filePath}"); return 1; }
        if (!File.Exists(pkcs7Path)) { Console.Error.WriteLine($"Not found: {pkcs7Path}"); return 1; }

        byte[] pkcs7 = File.ReadAllBytes(pkcs7Path);

        if (!CryptSIPRetrieveSubjectGuid(filePath, IntPtr.Zero, out Guid sipGuid))
        { Console.Error.WriteLine($"No SIP. Error: 0x{Marshal.GetLastWin32Error():X8}"); return 1; }

        var si = BuildSubjectInfo(filePath, sipGuid, digestAlgOid, out var handles);
        try
        {
            // CreateIndirectData to open the file and set SIP globals
            uint cb = 0;
            CryptSIPCreateIndirectData(ref si, ref cb, IntPtr.Zero);
            IntPtr pBuf = Marshal.AllocHGlobal((int)cb);
            if (!CryptSIPCreateIndirectData(ref si, ref cb, pBuf))
            {
                Console.Error.WriteLine($"CreateIndirectData failed: 0x{Marshal.GetLastWin32Error():X8}");
                Marshal.FreeHGlobal(pBuf);
                return 1;
            }
            Marshal.FreeHGlobal(pBuf);

            // PutSignedDataMsg
            GCHandle pkcs7Pin = GCHandle.Alloc(pkcs7, GCHandleType.Pinned);
            uint dwIndex = 0;
            bool result = CryptSIPPutSignedDataMsg(ref si, ENCODING, ref dwIndex,
                (uint)pkcs7.Length, pkcs7Pin.AddrOfPinnedObject());
            pkcs7Pin.Free();

            if (result)
                Console.WriteLine($"OK Index={dwIndex}");
            else
                Console.Error.WriteLine($"PutSignedDataMsg failed: 0x{Marshal.GetLastWin32Error():X8}");
            return result ? 0 : 1;
        }
        finally { FreeHandles(handles); }
    }

    static SIP_SUBJECTINFO BuildSubjectInfo(string filePath, Guid sipGuid, string digestAlgOid,
                                            out (GCHandle, IntPtr, IntPtr) handles)
    {
        var si = new SIP_SUBJECTINFO();
        si.cbSize = 0x50;
        GCHandle guidPin = GCHandle.Alloc(sipGuid, GCHandleType.Pinned);
        si.pgSubjectType = guidPin.AddrOfPinnedObject();
        si.hFile = INVALID_HANDLE_VALUE;
        IntPtr pwsFile = Marshal.StringToHGlobalUni(filePath);
        si.pwsFileName = pwsFile;
        si.dwIntVersion = 1;
        IntPtr pAlg = Marshal.StringToHGlobalAnsi(digestAlgOid);
        si.digestAlgObjId = pAlg;
        si.dwEncodingType = ENCODING;
        handles = (guidPin, pwsFile, pAlg);
        return si;
    }

    static void FreeHandles((GCHandle, IntPtr, IntPtr) h)
    {
        h.Item1.Free();
        Marshal.FreeHGlobal(h.Item2);
        Marshal.FreeHGlobal(h.Item3);
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
