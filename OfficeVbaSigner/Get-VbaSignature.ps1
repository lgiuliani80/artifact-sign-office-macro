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

    # P/Invoke for CryptSIP APIs (legacy format support)
    $sipNativeCode = @"
using System;
using System.Runtime.InteropServices;

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
            si.cbSize = 0x50;
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

        # Use CryptSIPGetSignedDataMsg to extract signatures via the registered SIP
        $idx = 0
        $foundAny = $false
        while ($idx -lt 5) {
            $pkcs7 = [SipInterop]::GetSignature($Path, $idx)
            if ($null -eq $pkcs7 -or $pkcs7.Length -eq 0) { break }

            $foundAny = $true
            Write-Host "`n`u{2500}`u{2500} Signature index $idx ($($pkcs7.Length) bytes) `u{2500}`u{2500}" -ForegroundColor Yellow
            Show-Pkcs7Info -Pkcs7Bytes $pkcs7 -Label "Index $idx"
            $idx++
        }

        if (-not $foundAny) {
            Write-Warning "No VBA signature found (CryptSIPGetSignedDataMsg returned no data)."
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
