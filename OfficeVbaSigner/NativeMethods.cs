using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;

namespace OfficeVbaSigner;

/// <summary>
/// P/Invoke declarations for Windows Crypto SIP APIs.
/// Uses LibraryImport source generation (.NET 7+) for compile-time marshalling.
/// All structures are laid out for x86 (32-bit) interop.
/// </summary>
internal static partial class NativeMethods
{
    // ── Encoding types ──────────────────────────────────────────────────
    public const uint X509_ASN_ENCODING = 0x00000001;
    public const uint PKCS_7_ASN_ENCODING = 0x00010000;
    public const uint ENCODING = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    // ── HANDLE constants ────────────────────────────────────────────────
    public static readonly IntPtr INVALID_HANDLE_VALUE = (IntPtr)(-1);

    // ── OID strings ─────────────────────────────────────────────────────
    public const string OID_SHA256 = "2.16.840.1.101.3.4.2.1";
    public const string OID_SHA384 = "2.16.840.1.101.3.4.2.2";
    public const string OID_SHA512 = "2.16.840.1.101.3.4.2.3";

    // ═══════════════════════════════════════════════════════════════════
    //  Native structures (x86 layout)
    // ═══════════════════════════════════════════════════════════════════

    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_DATA_BLOB
    {
        public uint cbData;
        public IntPtr pbData;
    }

    /// <summary>
    /// SIP_SUBJECTINFO — flattened for x86 (total 0x50 = 80 bytes).
    /// The CRYPT_ALGORITHM_IDENTIFIER for DigestAlgorithm is inlined as 3 fields.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SIP_SUBJECTINFO
    {
        public uint cbSize;            // 0x00
        public IntPtr pgSubjectType;   // 0x04  GUID*
        public IntPtr hFile;           // 0x08  HANDLE
        public IntPtr pwsFileName;     // 0x0C  LPCWSTR
        public IntPtr pwsDisplayName;  // 0x10  LPCWSTR
        public uint dwReserved1;       // 0x14
        public uint dwIntVersion;      // 0x18
        public IntPtr hProv;           // 0x1C  HCRYPTPROV

        // DigestAlgorithm (CRYPT_ALGORITHM_IDENTIFIER) inlined:
        public IntPtr digestAlgObjId;  // 0x20  LPSTR  pszObjId
        public uint   digestAlgParamCb;// 0x24  Parameters.cbData
        public IntPtr digestAlgParamPb;// 0x28  Parameters.pbData

        public uint dwFlags;           // 0x2C
        public uint dwEncodingType;    // 0x30
        public uint dwReserved2;       // 0x34
        public uint fdwCAPISettings;   // 0x38
        public uint fdwSecuritySettings;// 0x3C
        public uint dwIndex;           // 0x40
        public uint dwUnionChoice;     // 0x44
        public IntPtr psUnion;         // 0x48  union ptr
        public IntPtr pClientData;     // 0x4C
    }

    // ═══════════════════════════════════════════════════════════════════
    //  SIP_INDIRECT_DATA field offsets (x86)
    // ═══════════════════════════════════════════════════════════════════

    // SIP_INDIRECT_DATA layout:
    // 0x00  Data.pszObjId           (IntPtr)
    // 0x04  Data.Value.cbData       (uint)
    // 0x08  Data.Value.pbData       (IntPtr)
    // 0x0C  DigestAlgorithm.pszObjId(IntPtr)
    // 0x10  DigestAlgorithm.Params.cb (uint)
    // 0x14  DigestAlgorithm.Params.pb (IntPtr)
    // 0x18  Digest.cbData           (uint)
    // 0x1C  Digest.pbData           (IntPtr)
    // Total: 0x20 = 32 bytes header

    public static IndirectDataFields ReadIndirectData(IntPtr ptr)
    {
        var f = new IndirectDataFields();
        f.DataOid = Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(ptr, 0x00))!;

        uint cbVal = (uint)Marshal.ReadInt32(ptr, 0x04);
        IntPtr pbVal = Marshal.ReadIntPtr(ptr, 0x08);
        f.DataValue = new byte[cbVal];
        if (cbVal > 0) Marshal.Copy(pbVal, f.DataValue, 0, (int)cbVal);

        f.DigestAlgOid = Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(ptr, 0x0C))!;

        uint cbParams = (uint)Marshal.ReadInt32(ptr, 0x10);
        IntPtr pbParams = Marshal.ReadIntPtr(ptr, 0x14);
        f.DigestAlgParams = new byte[cbParams];
        if (cbParams > 0) Marshal.Copy(pbParams, f.DigestAlgParams, 0, (int)cbParams);

        uint cbDigest = (uint)Marshal.ReadInt32(ptr, 0x18);
        IntPtr pbDigest = Marshal.ReadIntPtr(ptr, 0x1C);
        f.Digest = new byte[cbDigest];
        if (cbDigest > 0) Marshal.Copy(pbDigest, f.Digest, 0, (int)cbDigest);

        return f;
    }

    public struct IndirectDataFields
    {
        public string DataOid;
        public byte[] DataValue;
        public string DigestAlgOid;
        public byte[] DigestAlgParams;
        public byte[] Digest;
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Crypt32 P/Invoke (LibraryImport source generation)
    // ═══════════════════════════════════════════════════════════════════

    [LibraryImport("crypt32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CryptSIPRetrieveSubjectGuid(
        string FileName,
        IntPtr hFileIn,
        out Guid pgSubject);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CryptSIPCreateIndirectData(
        ref SIP_SUBJECTINFO pSubjectInfo,
        ref uint pcbIndirectData,
        IntPtr pIndirectData);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CryptSIPPutSignedDataMsg(
        ref SIP_SUBJECTINFO pSubjectInfo,
        uint dwEncodingType,
        ref uint pdwIndex,
        uint cbSignedDataMsg,
        IntPtr pbSignedDataMsg);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CryptSIPRemoveSignedDataMsg(
        ref SIP_SUBJECTINFO pSubjectInfo,
        uint dwIndex);

    // ═══════════════════════════════════════════════════════════════════
    //  CryptoMsg API for diagnostics
    // ═══════════════════════════════════════════════════════════════════

    [LibraryImport("crypt32.dll", SetLastError = true)]
    public static partial IntPtr CryptMsgOpenToDecode(
        uint dwMsgEncodingType, uint dwFlags, uint dwMsgType,
        IntPtr hCryptProv, IntPtr pRecipientInfo, IntPtr pStreamInfo);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CryptMsgUpdate(
        IntPtr hCryptMsg, IntPtr pbData, uint cbData,
        [MarshalAs(UnmanagedType.Bool)] bool fFinal);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CryptMsgGetParam(
        IntPtr hCryptMsg, uint dwParamType, uint dwIndex,
        IntPtr pvData, ref uint pcbData);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CryptMsgClose(IntPtr hCryptMsg);
}
