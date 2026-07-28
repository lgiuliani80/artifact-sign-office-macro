using System.Runtime.InteropServices;
using System.Diagnostics;

// SIP helper subprocess: operates in a clean process without Azure SDK loaded.
// Modes:
//   PutTest <file> --hash              → prints IndirectData fields to stdout (for signing)
//   PutTest <file> <pkcs7-file>        → CreateIndirectData + PutSignedDataMsg

var app = new PutTestApp();
return app.Run(args);

class PutTestApp
{
    public int Run(string[] args)
    {
        if (args.Length < 2) { Console.Error.WriteLine("Usage: PutTest <file> --hash | PutTest <file> <pkcs7>"); return 1; }
        string filePath = Path.GetFullPath(args[0]);
        if (!File.Exists(filePath)) { Console.Error.WriteLine($"Not found: {filePath}"); return 1; }

        if (args[1] == "--hash")
            return DoHash(filePath);
        else
            return DoPut(filePath, Path.GetFullPath(args[1]));
    }

    int DoHash(string filePath)
    {
        if (!Native.CryptSIPRetrieveSubjectGuid(filePath, IntPtr.Zero, out Guid sipGuid))
        { Console.Error.WriteLine($"No SIP. Error: 0x{Marshal.GetLastWin32Error():X8}"); return 1; }

        var si = BuildSubjectInfo(filePath, sipGuid, out var handles);
        try
        {
            uint cb = 0;
            Native.CryptSIPCreateIndirectData(ref si, ref cb, IntPtr.Zero);
            IntPtr pBuf = Marshal.AllocHGlobal((int)cb);
            if (!Native.CryptSIPCreateIndirectData(ref si, ref cb, pBuf))
            {
                Console.Error.WriteLine($"CreateIndirectData failed: 0x{Marshal.GetLastWin32Error():X8}");
                Marshal.FreeHGlobal(pBuf);
                return 1;
            }

            // Read SPC_INDIRECT_DATA native struct (x86 layout):
            // +0x00: Data.pszObjId (LPSTR ptr)
            // +0x04: Data.Value.cbData (uint)
            // +0x08: Data.Value.pbData (IntPtr)
            // +0x0C: DigestAlgorithm.pszObjId (LPSTR ptr)
            // +0x10: DigestAlgorithm.Parameters.cbData (uint)
            // +0x14: DigestAlgorithm.Parameters.pbData (IntPtr)
            // +0x18: Digest.cbData (uint)
            // +0x1C: Digest.pbData (IntPtr)
            string dataOid = Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(pBuf, 0x00))!;
            uint dataValCb = (uint)Marshal.ReadInt32(pBuf, 0x04);
            IntPtr dataValPb = Marshal.ReadIntPtr(pBuf, 0x08);
            string digestAlgOid = Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(pBuf, 0x0C))!;
            uint digestCb = (uint)Marshal.ReadInt32(pBuf, 0x18);
            IntPtr digestPb = Marshal.ReadIntPtr(pBuf, 0x1C);

            byte[] dataVal = new byte[dataValCb];
            if (dataValCb > 0) Marshal.Copy(dataValPb, dataVal, 0, (int)dataValCb);
            byte[] digest = new byte[digestCb];
            if (digestCb > 0) Marshal.Copy(digestPb, digest, 0, (int)digestCb);

            Marshal.FreeHGlobal(pBuf);

            // Output structured data (one field per line)
            Console.WriteLine($"DATA_OID={dataOid}");
            Console.WriteLine($"DATA_VALUE={Convert.ToHexString(dataVal)}");
            Console.WriteLine($"DIGEST_ALG={digestAlgOid}");
            Console.WriteLine($"DIGEST={Convert.ToHexString(digest)}");
            Console.WriteLine($"SIZE={cb}");
            return 0;
        }
        finally { FreeHandles(handles); }
    }

    int DoPut(string filePath, string pkcs7Path)
    {
        if (!File.Exists(pkcs7Path)) { Console.Error.WriteLine($"Not found: {pkcs7Path}"); return 1; }
        byte[] pkcs7 = File.ReadAllBytes(pkcs7Path);
        Console.WriteLine($"PKCS#7: {pkcs7.Length} bytes");

        if (!Native.CryptSIPRetrieveSubjectGuid(filePath, IntPtr.Zero, out Guid sipGuid))
        { Console.Error.WriteLine($"No SIP. Error: 0x{Marshal.GetLastWin32Error():X8}"); return 1; }
        Console.WriteLine($"SIP GUID: {sipGuid}");

        // Print msosipx base
        foreach (ProcessModule m in Process.GetCurrentProcess().Modules)
            if (m.ModuleName != null && m.ModuleName.Contains("msosip", StringComparison.OrdinalIgnoreCase))
                Console.WriteLine($"  {m.ModuleName}: base=0x{m.BaseAddress:X8} size=0x{m.ModuleMemorySize:X}");

        var si = BuildSubjectInfo(filePath, sipGuid, out var handles);
        try
        {
            // CreateIndirectData to open the file
            Console.WriteLine("Calling CryptSIPCreateIndirectData (to open the file)...");
            uint cb = 0;
            Native.CryptSIPCreateIndirectData(ref si, ref cb, IntPtr.Zero);
            IntPtr pBuf = Marshal.AllocHGlobal((int)cb);
            if (!Native.CryptSIPCreateIndirectData(ref si, ref cb, pBuf))
            {
                Console.Error.WriteLine($"CreateIndirectData failed: 0x{Marshal.GetLastWin32Error():X8}");
                Marshal.FreeHGlobal(pBuf);
                return 1;
            }
            Marshal.FreeHGlobal(pBuf);
            Console.WriteLine($"  IndirectData: {cb} bytes - file is now open");

            // PutSignedDataMsg
            GCHandle pkcs7Pin = GCHandle.Alloc(pkcs7, GCHandleType.Pinned);
            uint dwIndex = 0;
            Console.WriteLine("Calling CryptSIPPutSignedDataMsg...");
            bool result = Native.CryptSIPPutSignedDataMsg(ref si, 0x10001, ref dwIndex,
                (uint)pkcs7.Length, pkcs7Pin.AddrOfPinnedObject());
            pkcs7Pin.Free();

            if (result) Console.WriteLine($"SUCCESS! Index={dwIndex}");
            else Console.Error.WriteLine($"FAILED: 0x{Marshal.GetLastWin32Error():X8}");
            return result ? 0 : 1;
        }
        finally { FreeHandles(handles); }
    }

    static Native.SIP_SUBJECTINFO BuildSubjectInfo(string filePath, Guid sipGuid, out (GCHandle, IntPtr, IntPtr) handles)
    {
        var si = new Native.SIP_SUBJECTINFO();
        si.cbSize = 0x50;
        GCHandle guidPin = GCHandle.Alloc(sipGuid, GCHandleType.Pinned);
        si.pgSubjectType = guidPin.AddrOfPinnedObject();
        si.hFile = (IntPtr)(-1);
        IntPtr pwsFile = Marshal.StringToHGlobalUni(filePath);
        si.pwsFileName = pwsFile;
        si.dwIntVersion = 1;
        IntPtr pAlg = Marshal.StringToHGlobalAnsi("2.16.840.1.101.3.4.2.1");
        si.digestAlgObjId = pAlg;
        si.dwEncodingType = 0x10001;
        handles = (guidPin, pwsFile, pAlg);
        return si;
    }

    static void FreeHandles((GCHandle, IntPtr, IntPtr) h)
    {
        h.Item1.Free();
        Marshal.FreeHGlobal(h.Item2);
        Marshal.FreeHGlobal(h.Item3);
    }
}

static class Native
{
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CryptSIPRetrieveSubjectGuid(string FileName, IntPtr hFileIn, out Guid pgSubject);
    [DllImport("crypt32.dll", SetLastError = true)]
    public static extern bool CryptSIPCreateIndirectData(ref SIP_SUBJECTINFO pSubjectInfo, ref uint pcbIndirectData, IntPtr pIndirectData);
    [DllImport("crypt32.dll", SetLastError = true)]
    public static extern bool CryptSIPPutSignedDataMsg(ref SIP_SUBJECTINFO pSubjectInfo, uint dwEncodingType, ref uint pdwIndex, uint cbSignedDataMsg, IntPtr pbSignedDataMsg);

    [StructLayout(LayoutKind.Sequential)]
    public struct SIP_SUBJECTINFO
    {
        public uint cbSize;
        public IntPtr pgSubjectType;
        public IntPtr hFile;
        public IntPtr pwsFileName;
        public IntPtr pwsDisplayName;
        public uint dwReserved1;
        public uint dwIntVersion;
        public IntPtr hProv;
        public IntPtr digestAlgObjId;
        public uint digestAlgParamCb;
        public IntPtr digestAlgParamPb;
        public uint dwFlags;
        public uint dwEncodingType;
        public uint dwReserved2;
        public uint fdwCAPISettings;
        public uint fdwSecuritySettings;
        public uint dwIndex;
        public uint dwUnionChoice;
        public IntPtr psUnion;
        public IntPtr pClientData;
    }
}
