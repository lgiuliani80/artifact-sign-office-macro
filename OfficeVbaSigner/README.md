# OfficeVbaSigner

Signs VBA macros in Office files using **Azure Trusted Signing** (formerly Azure Artifact Signing).

## Problem

Microsoft's Office SIPs (`msosip.dll` / `msosipx.dll`) cannot be used with `signtool /dlib`
because signtool's "digest-only" signing flow is incompatible with third-party SIPs. Microsoft
has confirmed they will not update the Office SIPs to support this flow.

## Solution

This tool bypasses both signtool and the mixed-mode dlib DLL entirely. It uses:

1. **SIP P/Invoke** — calls `CryptSIPCreateIndirectData` directly to compute the VBA project digest
2. **Azure.CodeSigning.Sdk** (pure managed .NET) — signs the digest remotely via Azure Trusted Signing
3. **In-process PKCS#7 builder** — assembles a valid Authenticode CMS SignedData using `System.Formats.Asn1`
4. **SIP P/Invoke** — calls `CryptSIPPutSignedDataMsg` to embed the signature in the file
5. Repeats for triple-signing (legacy + agile + V3)

### Why not use the dlib?

`Azure.CodeSigning.Dlib.dll` is a mixed-mode C++/CLI assembly that hosts .NET 8 internally.
Loading it via `LoadLibrary` from a .NET 8 process creates a dual-CLR-hosting scenario
that risks initialization conflicts and assembly loading issues. This tool avoids the
problem entirely by using the pure managed SDK (`Azure.CodeSigning.Sdk` NuGet package).

## Prerequisites

1. **Office SIPs registered** — run `regsvr32 msosip.dll` and/or `regsvr32 msosipx.dll`
   (use the x86 regsvr32 from `C:\Windows\SysWOW64\`)
2. **vbe7.dll** accessible (same directory as SIP DLLs or registered in HKLM)
3. **Azure Trusted Signing** account and certificate profile configured
4. **Azure authentication** configured (`az login`, environment variables, managed identity, etc.)
5. **.NET 10.0 x86 runtime** installed

## Usage

```
OfficeVbaSigner <file> --metadata <json> [options]

Options:
  --alg <sha256|sha384|sha512>   Hash algorithm (default: sha256)
  --passes <1|2|3>               Number of signing passes (default: 3)
  --clear                        Remove existing signatures first
  --verbose                      Show detailed progress
```

Authentication leverages `DefaultAzureCredential`, meaning it will probe different authentication mechanisms until a working one is found.  
`az cli` credentials are the most common source of authentication.

### Example

```bat
OfficeVbaSigner "C:\Macros\report.xlsm" ^
  --metadata "C:\Config\metadata.json" ^
  --alg sha256 --passes 3 --clear --verbose
```

### Metadata JSON format

```json
{
    "Endpoint": "https://eus.codesigning.azure.net/",
    "CodeSigningAccountName": "my-signing-account",
    "CertificateProfileName": "my-certificate-profile"
}
```

Same format as signtool's `/dmdf` parameter. The endpoint must match the region
where your Trusted Signing account was created.

## Architecture

```
┌─────────────────────┐
│  OfficeVbaSigner    │
│  (.NET 10, x86)     │
│                     │
│  1. SIP CreateData  │──→ msosip.dll / msosipx.dll (native, via P/Invoke)
│     (get VBA hash)  │        reads VBA project from Office file
│                     │
│  2. Build auth      │
│     attributes      │
│     + hash them     │
│                     │
│  3. SDK sign        │──→ Azure.CodeSigning.Sdk (managed .NET)
│     (remote sign)   │        calls Azure Trusted Signing REST API
│                     │        → returns signature + certificate
│                     │
│  4. Build PKCS#7    │
│     (ASN.1/DER)     │
│                     │
│  5. SIP PutData     │──→ msosip.dll / msosipx.dll (native, via P/Invoke)
│     (embed sig)     │        writes signature into Office file
│                     │
│  Repeat 3x for      │
│  triple-signing     │
└─────────────────────┘
```

## Supported file formats

Same as the Office SIPs:

| SIP | Formats |
|-----|---------|
| msosip.dll | .xla .xls .xlt .pot .ppa .pps .ppt .mpp .mpt .pub .vdw .vsd .vss .vst .doc .dot .wiz |
| msosipx.dll | .xlam .xlsb .xlsm .xltm .potm .ppam .ppsm .pptm .vsdm .vssm .vstm .docm .dotm |

## Building

```
dotnet build --configuration Release
```

The output is in `bin\Release\net10.0-windows\`. Must run as x86 (32-bit) process.

## Dependencies

- **Azure.CodeSigning.Sdk** (0.1.164, unlisted NuGet) — pure managed signing SDK
- **Azure.Identity** — Azure AD/Entra authentication (DefaultAzureCredential)

No mixed-mode DLLs, no native Azure dlib required.

## Limitations

- Must run as a 32-bit (x86) process (Office SIPs are x86-only)
- Requires Azure authentication configured (DefaultAzureCredential)
- Azure.CodeSigning.Sdk is an unlisted NuGet package (API may change)
- Timestamp support not yet implemented (RFC 3161)

