<#
.SYNOPSIS
    Extracts and displays VBA macro signature information from Office files.

.DESCRIPTION
    Supports both OOXML formats (.xlsm, .xlsb, .docm) and legacy binary formats (.xls, .doc, .ppt).
    - OOXML: extracts PKCS#7 from vbaProjectSignature.bin inside the ZIP
    - Legacy: uses CryptSIPGetSignedDataMsg via P/Invoke to extract the signature through the registered SIP
    
    Displays signer information, digest algorithm, timestamp details, and certificate chain.

.PARAMETER Path
    Path to the Office file to inspect.

.EXAMPLE
    .\Get-VbaSignature.ps1 -Path "C:\Files\macros.xlsm"

.EXAMPLE
    .\Get-VbaSignature.ps1 -Path "C:\Files\legacy.xls"

.EXAMPLE
    Get-ChildItem *.xlsm,*.xls | .\Get-VbaSignature.ps1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 0)]
    [Alias("FullName")]
    [string]$Path
)

begin {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    Add-Type -AssemblyName System.Security

    # P/Invoke for CryptSIP APIs + direct OLE stream reading (legacy format support)
    $sipNativeCode = @"
using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;

// Direct OLE/CFB stream reader - no COM automation required
public static class OleStreamReader
{
    const uint MAXREGSECT = 0xFFFFFFFAu;

    public static byte[] ReadStream(string filePath, string[] storagePath, string streamName)
    {
        using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            var hdr = new byte[512];
            if (fs.Read(hdr, 0, 512) < 512) return null;
            if (BitConverter.ToUInt64(hdr, 0) != 0xE11AB1A1E011CFD0UL) return null; // magic

            int sectorShift = BitConverter.ToUInt16(hdr, 30);
            int sectorSize  = 1 << sectorShift;
            int dirSect     = BitConverter.ToInt32(hdr, 48);
            int miniCutoff  = BitConverter.ToInt32(hdr, 56);
            int miniFatSect = BitConverter.ToInt32(hdr, 60);
            int miniShift   = BitConverter.ToUInt16(hdr, 32);
            int miniSize    = 1 << miniShift;
            int entriesPerSector = sectorSize / 4;

            // Collect FAT sector locations from DIFAT (first 109 in header)
            var difat = new List<int>();
            for (int i = 0; i < 109; i++)
            {
                int s = BitConverter.ToInt32(hdr, 76 + i * 4);
                if (s < 0 || (uint)s > MAXREGSECT) break;
                difat.Add(s);
            }
            // (Extended DIFAT chain omitted — covers files up to 109*128*512=7MB for 512B sectors)

            // Build FAT: difat[k] holds the disk sector whose content describes FAT entries k*N..(k+1)*N-1
            var fat = new int[difat.Count * entriesPerSector];
            for (int k = 0; k < difat.Count; k++)
            {
                fs.Seek((long)(difat[k] + 1) * sectorSize, SeekOrigin.Begin);
                var buf = new byte[sectorSize];
                fs.Read(buf, 0, sectorSize);
                int baseIdx = k * entriesPerSector;
                for (int j = 0; j < entriesPerSector; j++)
                    fat[baseIdx + j] = BitConverter.ToInt32(buf, j * 4);
            }

            // Helper: follow FAT chain from startSect, read up to knownSize bytes
            Func<int, long, byte[]> readChain = (startSect, knownSize) =>
            {
                var chunks = new List<byte[]>();
                long total = 0;
                int cur = startSect;
                var seen = new HashSet<int>();
                while (cur >= 0 && (uint)cur <= MAXREGSECT && !seen.Contains(cur))
                {
                    seen.Add(cur);
                    fs.Seek((long)(cur + 1) * sectorSize, SeekOrigin.Begin);
                    var chunk = new byte[sectorSize];
                    fs.Read(chunk, 0, sectorSize);
                    chunks.Add(chunk);
                    total += sectorSize;
                    cur = (cur < fat.Length) ? fat[cur] : -1;
                }
                long take = knownSize >= 0 ? Math.Min(knownSize, total) : total;
                var result2 = new byte[take];
                long pos2 = 0;
                foreach (var ch in chunks)
                {
                    long copy = Math.Min(ch.Length, take - pos2);
                    if (copy <= 0) break;
                    Array.Copy(ch, 0, result2, pos2, copy);
                    pos2 += copy;
                }
                return result2;
            };

            // Read directory sectors
            var dirBytes = readChain(dirSect, -1);
            int entryCount = dirBytes.Length / 128;

            Func<int, string> entryName  = sid => {
                if (sid < 0 || sid >= entryCount) return null;
                int nl = BitConverter.ToUInt16(dirBytes, sid * 128 + 64);
                return nl < 2 ? "" : System.Text.Encoding.Unicode.GetString(dirBytes, sid * 128, nl - 2);
            };
            Func<int, int> childSid    = sid => sid >= 0 && sid < entryCount ? BitConverter.ToInt32(dirBytes, sid * 128 + 76) : -1;
            Func<int, int> leftSid     = sid => sid >= 0 && sid < entryCount ? BitConverter.ToInt32(dirBytes, sid * 128 + 68) : -1;
            Func<int, int> rightSid    = sid => sid >= 0 && sid < entryCount ? BitConverter.ToInt32(dirBytes, sid * 128 + 72) : -1;
            Func<int, int> startSector = sid => sid >= 0 && sid < entryCount ? BitConverter.ToInt32(dirBytes, sid * 128 + 116) : -1;
            Func<int, long> entrySize  = sid => sid >= 0 && sid < entryCount ? (long)BitConverter.ToUInt32(dirBytes, sid * 128 + 120) : -1;

            // BFS over sibling red-black tree to find a named entry under a parent
            Func<int, string, int> findChild = (parentSid, name) =>
            {
                var queue = new Queue<int>();
                int c = childSid(parentSid);
                if (c >= 0 && (uint)c < (uint)entryCount) queue.Enqueue(c);
                var vis = new HashSet<int>();
                while (queue.Count > 0)
                {
                    int n = queue.Dequeue();
                    if (n < 0 || (uint)n >= (uint)entryCount || !vis.Add(n)) continue;
                    string en = entryName(n);
                    if (en != null && string.Equals(en, name, StringComparison.OrdinalIgnoreCase)) return n;
                    int l = leftSid(n), r = rightSid(n);
                    if (l >= 0 && (uint)l < (uint)entryCount) queue.Enqueue(l);
                    if (r >= 0 && (uint)r < (uint)entryCount) queue.Enqueue(r);
                }
                return -1;
            };

            // Navigate storage path
            int curSid = 0;
            foreach (string seg in storagePath)
            {
                curSid = findChild(curSid, seg);
                if (curSid < 0) return null;
            }
            int sid2 = findChild(curSid, streamName);
            if (sid2 < 0) return null;

            int  sect = startSector(sid2);
            long size = entrySize(sid2);

            if (size < miniCutoff && size > 0)
            {
                // Stream lives in the mini-stream (root data chain)
                byte[] miniContainer = readChain(startSector(0), entrySize(0));

                // Build mini-FAT by following its chain through regular FAT
                var miniFat = new List<int>();
                int mfCur = miniFatSect;
                var mfSeen = new HashSet<int>();
                while (mfCur >= 0 && (uint)mfCur <= MAXREGSECT && mfSeen.Add(mfCur))
                {
                    fs.Seek((long)(mfCur + 1) * sectorSize, SeekOrigin.Begin);
                    var mfbuf = new byte[sectorSize];
                    fs.Read(mfbuf, 0, sectorSize);
                    for (int j = 0; j < entriesPerSector; j++)
                        miniFat.Add(BitConverter.ToInt32(mfbuf, j * 4));
                    mfCur = (mfCur < fat.Length) ? fat[mfCur] : -1;
                }

                var result3 = new byte[size];
                long written = 0;
                int msCur = sect;
                var msSeen = new HashSet<int>();
                while (msCur >= 0 && (uint)msCur <= MAXREGSECT && written < size && msSeen.Add(msCur))
                {
                    long msOff = (long)msCur * miniSize;
                    long copy  = Math.Min(miniSize, size - written);
                    if (msOff + copy <= miniContainer.Length)
                        Array.Copy(miniContainer, msOff, result3, written, copy);
                    written += copy;
                    msCur = (msCur < miniFat.Count) ? miniFat[msCur] : -1;
                }
                return result3;
            }
            else
            {
                return readChain(sect, size);
            }
        }
    }

    // Search a stream for all PKCS#7 ContentInfo blobs (signedData OID)
    // Used for Word binary files where signatures are embedded in 1Table/0Table
    public static byte[][] FindPkcs7Blobs(string filePath, string[] storagePath, string streamName)
    {
        byte[] data = ReadStream(filePath, storagePath, streamName);
        if (data == null) return new byte[0][];

        // signedData OID: 06 09 2A 86 48 86 F7 0D 01 07 02
        var oid = new byte[] { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02 };
        var result = new System.Collections.Generic.List<byte[]>();

        for (int i = 0; i < data.Length - oid.Length - 4; i++)
        {
            // Look for SEQUENCE (0x30) with 2-byte length (0x82) followed by signedData OID
            if (data[i] != 0x30 || data[i+1] != 0x82) continue;
            if (i + 4 + oid.Length > data.Length) break;

            bool match = true;
            for (int j = 0; j < oid.Length; j++)
                if (data[i + 4 + j] != oid[j]) { match = false; break; }
            if (!match) continue;

            int len = (data[i+2] << 8) | data[i+3];
            int end = i + 4 + len;
            if (end > data.Length || len < oid.Length) continue;

            var blob = new byte[4 + len];
            Array.Copy(data, i, blob, 0, blob.Length);
            result.Add(blob);
            i = end - 1; // skip past this blob
        }
        return result.ToArray();
    }
}

public static class SipInterop
{
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

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CryptSIPRetrieveSubjectGuid(
        string FileName, IntPtr hFileIn, out Guid pgSubject);

    [DllImport("crypt32.dll", SetLastError = true)]
    public static extern bool CryptSIPGetSignedDataMsg(
        ref SIP_SUBJECTINFO pSubjectInfo,
        ref uint pdwEncodingType,
        uint dwIndex,
        ref uint pcbSignedDataMsg,
        IntPtr pbSignedDataMsg);

    public static byte[] GetSignature(string filePath, int index)
    {
        Guid sipGuid;
        if (!CryptSIPRetrieveSubjectGuid(filePath, IntPtr.Zero, out sipGuid))
            return null;

        var guidBytes = sipGuid.ToByteArray();
        var guidPin = GCHandle.Alloc(guidBytes, GCHandleType.Pinned);
        var algPtr = Marshal.StringToHGlobalAnsi("2.16.840.1.101.3.4.2.1");
        var filePtr = Marshal.StringToHGlobalUni(filePath);

        try
        {
            var si = new SIP_SUBJECTINFO();
            si.cbSize = (uint)Marshal.SizeOf(si);  // 0x50 on 32-bit, 0x80 on 64-bit
            si.pgSubjectType = guidPin.AddrOfPinnedObject();
            si.hFile = (IntPtr)(-1);
            si.pwsFileName = filePtr;
            si.dwIntVersion = 1;
            si.digestAlgObjId = algPtr;
            si.dwEncodingType = 0x10001;
            si.dwIndex = (uint)index;

            uint encoding = 0x10001;
            uint cbData = 0;

            if (!CryptSIPGetSignedDataMsg(ref si, ref encoding, (uint)index, ref cbData, IntPtr.Zero))
                return null;

            IntPtr pData = Marshal.AllocHGlobal((int)cbData);
            try
            {
                if (!CryptSIPGetSignedDataMsg(ref si, ref encoding, (uint)index, ref cbData, pData))
                    return null;

                byte[] result = new byte[cbData];
                Marshal.Copy(pData, result, 0, (int)cbData);
                return result;
            }
            finally { Marshal.FreeHGlobal(pData); }
        }
        finally
        {
            guidPin.Free();
            Marshal.FreeHGlobal(algPtr);
            Marshal.FreeHGlobal(filePtr);
        }
    }

    public static Guid GetSipGuid(string filePath)
    {
        Guid g;
        CryptSIPRetrieveSubjectGuid(filePath, IntPtr.Zero, out g);
        return g;
    }
}
"@

    if (-not ([System.Management.Automation.PSTypeName]'SipInterop').Type) {
        Add-Type -TypeDefinition $sipNativeCode -Language CSharp
    }
    function Show-Pkcs7Info {
        param([byte[]]$Pkcs7Bytes, [string]$Label)

        try {
            $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
            $cms.Decode($Pkcs7Bytes)
        }
        catch {
            Write-Warning "  Failed to decode PKCS#7: $_"
            return
        }

        Write-Host "  Content Type: $($cms.ContentInfo.ContentType.Value)" -ForegroundColor Gray
        Write-Host "  PKCS#7 size:  $($Pkcs7Bytes.Length) bytes" -ForegroundColor Gray

        foreach ($si in $cms.SignerInfos) {
            Write-Host "`n  `u{250C}`u{2500} Signer `u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}" -ForegroundColor Green
            Write-Host "  `u{2502} Subject:    $($si.Certificate.Subject)"
            Write-Host "  `u{2502} Issuer:     $($si.Certificate.Issuer)"
            Write-Host "  `u{2502} Serial:     $($si.Certificate.SerialNumber)"
            Write-Host "  `u{2502} Thumbprint: $($si.Certificate.Thumbprint)"
            Write-Host "  `u{2502} Not Before: $($si.Certificate.NotBefore)"
            Write-Host "  `u{2502} Not After:  $($si.Certificate.NotAfter)"
            Write-Host "  `u{2502} Digest Alg: $($si.DigestAlgorithm.FriendlyName) ($($si.DigestAlgorithm.Value))"

            # Signed attributes
            if ($si.SignedAttributes.Count -gt 0) {
                Write-Host "  `u{2502}"
                Write-Host "  `u{2502} Signed Attributes:" -ForegroundColor DarkGray
                foreach ($sa in $si.SignedAttributes) {
                    Write-Host "  `u{2502}   $($sa.Oid.Value) ($($sa.Oid.FriendlyName))" -ForegroundColor DarkGray
                }
            }

            # Timestamp
            $hasTimestamp = $false
            foreach ($ua in $si.UnsignedAttributes) {
                if ($ua.Oid.Value -eq "1.3.6.1.4.1.311.3.3.1") {
                    $hasTimestamp = $true
                    Write-Host "  `u{2502}"
                    Write-Host "  `u{2502} `u{23F1} RFC 3161 Timestamp:" -ForegroundColor Magenta
                    try {
                        $tsCms = New-Object System.Security.Cryptography.Pkcs.SignedCms
                        $tsCms.Decode($ua.Values[0].RawData)
                        foreach ($tsSi in $tsCms.SignerInfos) {
                            Write-Host "  `u{2502}   TSA:        $($tsSi.Certificate.Subject)"
                            Write-Host "  `u{2502}   TSA Issuer: $($tsSi.Certificate.Issuer)"
                            Write-Host "  `u{2502}   Digest:     $($tsSi.DigestAlgorithm.FriendlyName)"
                        }
                        $tsContent = $tsCms.ContentInfo.Content
                        for ($j = 0; $j -lt $tsContent.Length - 15; $j++) {
                            if ($tsContent[$j] -eq 0x18 -and $tsContent[$j+1] -eq 0x0F) {
                                $timeStr = [System.Text.Encoding]::ASCII.GetString($tsContent, $j + 2, 15)
                                Write-Host "  `u{2502}   Time:       $timeStr"
                                break
                            }
                        }
                    }
                    catch {
                        Write-Host "  `u{2502}   (could not parse timestamp token)" -ForegroundColor DarkYellow
                    }
                }
                elseif ($ua.Oid.Value -eq "1.2.840.113549.1.9.6") {
                    $hasTimestamp = $true
                    Write-Host "  `u{2502}"
                    Write-Host "  `u{2502} `u{23F1} Legacy Countersignature Timestamp" -ForegroundColor Magenta
                }
            }

            if (-not $hasTimestamp) {
                Write-Host "  `u{2502}"
                Write-Host "  `u{2502} `u{26A0} NO TIMESTAMP" -ForegroundColor Red
            }

            Write-Host "  `u{2514}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}" -ForegroundColor Green
        }
    }
}

process {
    $Path = (Resolve-Path $Path -ErrorAction Stop).Path

    Write-Host "`n`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}" -ForegroundColor Cyan
    Write-Host " File: $Path" -ForegroundColor Cyan
    Write-Host "`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}`u{2550}" -ForegroundColor Cyan

    # Determine file type: OOXML (ZIP) or legacy (OLE compound doc)
    $header = [byte[]]::new(4)
    $fs = [System.IO.File]::OpenRead($Path)
    [void]$fs.Read($header, 0, 4)
    $fs.Close()

    $isZip = ($header[0] -eq 0x50 -and $header[1] -eq 0x4B)  # PK..
    $isOle = ($header[0] -eq 0xD0 -and $header[1] -eq 0xCF -and $header[2] -eq 0x11 -and $header[3] -eq 0xE0)

    # Get SIP GUID for reference
    $sipGuid = [SipInterop]::GetSipGuid($Path)
    if ($sipGuid -ne [Guid]::Empty) {
        Write-Host " SIP GUID: $sipGuid" -ForegroundColor DarkGray
        $knownSips = @{
            '6e64d5bd-ceb0-4b66-b4a0-15ac71775c48' = 'msosipx.dll (OOXML VBA)'
            '01f45160-3e3e-11d3-b49a-00104b2cf645' = 'msosip.dll (Legacy binary VBA)'
            'c689aab8-8e78-11d0-8c47-00c04fc295ee' = 'Default PE/COFF SIP'
        }
        $sipName = $knownSips[$sipGuid.ToString()]
        if ($sipName) { Write-Host " SIP:      $sipName" -ForegroundColor DarkGray }
    }

    if ($isZip) {
        # ═══ OOXML format (ZIP-based) ═══
        Write-Host " Format:   OOXML (ZIP)" -ForegroundColor DarkGray

        try {
            $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
        }
        catch {
            Write-Error "Cannot open file as ZIP: $_"
            return
        }

        $sigEntries = $zip.Entries | Where-Object {
            $_.FullName -match 'vbaProjectSignature\.bin|vbaProjectSignatureAgile\.bin|vbaProjectSignatureV3\.bin'
        }

        if (-not $sigEntries) {
            Write-Warning "No VBA signature found in this file."
            $zip.Dispose()
            return
        }

        foreach ($entry in $sigEntries) {
            Write-Host "`n`u{2500}`u{2500} $($entry.FullName) ($($entry.Length) bytes) `u{2500}`u{2500}" -ForegroundColor Yellow

            $stream = $entry.Open()
            $ms = New-Object System.IO.MemoryStream
            $stream.CopyTo($ms)
            $sigBlob = $ms.ToArray()
            $stream.Close()
            $ms.Close()

            # Office signature blob has a header before the PKCS#7
            $pkcs7Start = -1
            for ($i = 0; $i -lt [Math]::Min(128, $sigBlob.Length); $i++) {
                if ($sigBlob[$i] -eq 0x30 -and ($i + 1) -lt $sigBlob.Length -and $sigBlob[$i + 1] -eq 0x82) {
                    $len = ($sigBlob[$i + 2] -shl 8) -bor $sigBlob[$i + 3]
                    if (($i + 4 + $len) -le ($sigBlob.Length + 16)) {
                        $pkcs7Start = $i
                        break
                    }
                }
            }

            if ($pkcs7Start -lt 0) {
                Write-Warning "  Could not locate PKCS#7 in signature blob."
                continue
            }

            $pkcs7Bytes = New-Object byte[] ($sigBlob.Length - $pkcs7Start)
            [Array]::Copy($sigBlob, $pkcs7Start, $pkcs7Bytes, 0, $pkcs7Bytes.Length)

            Show-Pkcs7Info -Pkcs7Bytes $pkcs7Bytes -Label $entry.FullName
        }

        $zip.Dispose()
    }
    elseif ($isOle) {
        # ═══ Legacy binary format (OLE compound document) ═══
        Write-Host " Format:   Legacy OLE compound document" -ForegroundColor DarkGray

        $foundAny = $false

        # Strategy 1: CryptSIPGetSignedDataMsg (works when msosip.dll recognises the file)
        if ($sipGuid -ne [Guid]::Empty) {
            $idx = 0
            while ($idx -lt 5) {
                $pkcs7 = [SipInterop]::GetSignature($Path, $idx)
                if ($null -eq $pkcs7 -or $pkcs7.Length -eq 0) { break }

                $foundAny = $true
                Write-Host "`n`u{2500}`u{2500} Signature index $idx ($($pkcs7.Length) bytes) via SIP `u{2500}`u{2500}" -ForegroundColor Yellow
                Show-Pkcs7Info -Pkcs7Bytes $pkcs7 -Label "Index $idx"
                $idx++
            }
        }

        # Strategy 2: Direct OLE stream read — covers Word (.doc/.dot) and Excel (.xls/.xlt)
        # Word:  Macros\VBA Digital Signature
        # Excel: _VBA_PROJECT_CUR\VBA Digital Signature
        if (-not $foundAny) {
            $oleCandidates = @(
                @{ Storage = @('Macros');             Label = 'Word (Macros)' }
                @{ Storage = @('_VBA_PROJECT_CUR');   Label = 'Excel (_VBA_PROJECT_CUR)' }
            )
            foreach ($c in $oleCandidates) {
                $sigBytes = [OleStreamReader]::ReadStream($Path, $c.Storage, 'VBA Digital Signature')
                if ($null -ne $sigBytes -and $sigBytes.Length -gt 0) {
                    $foundAny = $true
                    Write-Host "`n`u{2500}`u{2500} VBA Digital Signature via OLE ($($c.Label), $($sigBytes.Length) bytes) `u{2500}`u{2500}" -ForegroundColor Yellow

                    # The stream IS the raw PKCS#7 for legacy VBA signatures
                    Show-Pkcs7Info -Pkcs7Bytes $sigBytes -Label $c.Label
                    break
                }
            }
        }

        # Strategy 3: Scan Word table streams (1Table/0Table) for embedded PKCS#7
        # Word binary format stores VBA signatures inside the table stream with a "SigVx" header
        if (-not $foundAny) {
            foreach ($tblName in @('1Table', '0Table')) {
                $blobs = [OleStreamReader]::FindPkcs7Blobs($Path, [string[]]@(), $tblName)
                if ($blobs -and $blobs.Count -gt 0) {
                    $foundAny = $true
                    Write-Host " Source:   $tblName stream (Word binary embedded signatures)" -ForegroundColor DarkGray
                    $idx = 0
                    foreach ($pkcs7 in $blobs) {
                        $idx++
                        Write-Host "`n`u{2500}`u{2500} Signature $idx of $($blobs.Count) in $tblName ($($pkcs7.Length) bytes) `u{2500}`u{2500}" -ForegroundColor Yellow
                        Show-Pkcs7Info -Pkcs7Bytes $pkcs7 -Label "$tblName sig $idx"
                    }
                    break
                }
            }
        }

        if (-not $foundAny) {
            # Report clearly whether the storage exists but has no signature
            $hasMacros  = $null -ne [OleStreamReader]::ReadStream($Path, [string[]]@(), 'PROJECT') -or
                          $null -ne [OleStreamReader]::ReadStream($Path, [string[]]@('Macros'), 'PROJECT') -or
                          $null -ne [OleStreamReader]::ReadStream($Path, [string[]]@('_VBA_PROJECT_CUR'), 'dir')
            if ($hasMacros) {
                Write-Warning "File has a VBA project but NO VBA signature (not signed)."
            } else {
                Write-Warning "No VBA signature found (SIP: $sipGuid)."
            }
        }
    }
    else {
        # ═══ Unknown or try SIP anyway ═══
        Write-Host " Format:   Unknown (trying SIP extraction)" -ForegroundColor DarkGray

        $pkcs7 = [SipInterop]::GetSignature($Path, 0)
        if ($null -ne $pkcs7 -and $pkcs7.Length -gt 0) {
            Write-Host "`n`u{2500}`u{2500} Signature ($($pkcs7.Length) bytes) `u{2500}`u{2500}" -ForegroundColor Yellow
            Show-Pkcs7Info -Pkcs7Bytes $pkcs7 -Label "SIP"
        }
        else {
            Write-Warning "No signature found."
        }
    }
}
