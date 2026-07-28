# Office VBA Signer

A robust .NET tool for signing VBA macros in Microsoft Office files using **Azure Trusted Signing** (formerly Azure Artifact Signing).

## Project Purpose

This project provides a solution for signing VBA macros embedded in Office documents (.xlsm, .docm, .xls, etc.) using Azure Trusted Signing. It bypasses the limitations of Microsoft's standard `signtool` when working with Office SIPs (Cryptographic Service Providers), enabling automated and scalable macro signing workflows in CI/CD pipelines and enterprise automation scenarios.

### Why This Tool?

Microsoft's Office SIPs (`msosip.dll` / `msosipx.dll`) cannot be used with `signtool /dlib` because signtool's "digest-only" signing flow is incompatible with third-party SIPs. This tool provides a pure .NET alternative that:

- **Directly invokes Office SIPs** via P/Invoke to compute and embed VBA signatures
- **Uses the Azure.CodeSigning managed SDK** for remote signing without the complexity of mixed-mode DLLs
- **Constructs valid PKCS#7 signatures** in-process using `System.Formats.Asn1`
- **Supports triple-signing** (legacy + agile + V3 signatures)

---

## Prerequisites

### 1. **Office SIPs Registration** (Required)

The Office SIP DLLs must be registered on the system. These are located in the `x86/` and `x64/` folders:

*The code has been tested with 32 version ONLY, but it should work with both*.

**For 32-bit Office:**
```cmd
cd x86\
regsvr32 msosip.dll
```

**For 64-bit Office:**
```cmd
cd x64\
regsvr32 msosip.dll
```

Or use the included registration script:
```cmd
Register-SIP.cmd
```

> **Note:** Ensure you use the correct `regsvr32.exe` bitness:
> - Use `C:\Windows\System32\regsvr32.exe` for 64-bit DLLs
> - Use `C:\Windows\SysWOW64\regsvr32.exe` for 32-bit DLLs

### 2. **Additional Requirements**

- **vbe7.dll** — Must be accessible (same directory as SIP DLLs or registered in HKLM registry)
- **Azure Trusted Signing Account** — Set up an account at https://portal.azure.com
- **Azure Authentication** — Configure via:
  - `az login` (Azure CLI) -OR-
  - Environment variables (`AZURE_SUBSCRIPTION_ID`, etc.) -OR-
  - Managed Identity (if running in Azure)
- **.NET 10.0 x86 Runtime** — Install from https://dotnet.microsoft.com/download

---

## Usage

### Command Syntax

```
OfficeVbaSigner <file> --metadata <json> [options]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<file>` | Path to the Office file containing VBA macros (.xlsm, .docm, .xls, etc.) |
| `--metadata <json>` | **Required.** Path to metadata JSON file (same format as signtool `/dmdf`) |

### Options

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| `--alg` | sha256, sha384, sha512 | sha256 | Hash algorithm for signing |
| `--passes` | 1, 2, 3 | 3 | Number of signing passes (triple-sign) |
| `--timestamp` | URL | — | RFC 3161 timestamp server URL |
| `--clear` | — | — | Remove existing signatures before signing |
| `--verbose` | — | — | Show detailed progress information |
| `--help`, `-h` | — | — | Display usage information |

### Metadata JSON Format

Create a `metadata.json` file with your Azure Trusted Signing configuration:

```json
{
  "Endpoint": "https://eus.codesigning.azure.net/",
  "CodeSigningAccountName": "my-signing-account",
  "CertificateProfileName": "my-certificate-profile"
}
```

**Configuration Details:**
- **Endpoint** — Must match the region where your Trusted Signing account was created (e.g., `eus`, `wus`, `westeu`)
- **CodeSigningAccountName** — The name of your Azure Trusted Signing account
- **CertificateProfileName** — The certificate profile name configured in your account

### Examples

**Basic signing with default settings:**  
cmd:
```cmd
OfficeVbaSigner "C:\Macros\report.xlsm" --metadata "C:\Config\metadata.json" --timestamp http://timestamp.acs.microsoft.com
```

**Clear existing signatures and re-sign with verbose output:**  
cmd:
```cmd
OfficeVbaSigner "C:\Macros\report.xlsm" ^
  --metadata "C:\Config\metadata.json" ^
  --timestamp http://timestamp.acs.microsoft.com ^
  --clear ^
  --verbose
```
---

## Project Structure

```
OfficeSIP/
├── OfficeVbaSigner/          # Main CLI tool
│   ├── Program.cs            # Entry point and command-line parsing
│   ├── AzureSigner.cs        # Azure Trusted Signing integration
│   ├── Pkcs7Builder.cs       # PKCS#7 signature construction
│   ├── NativeMethods.cs      # P/Invoke declarations for Office SIPs
│   ├── OfficeVbaSigner.csproj
│   ├── README.md             # Detailed tool documentation
│   ├── metadata.json.sample  # Example configuration file
│   └── test_*.xlsm           # Test Office files with macros
├── x86/                      # 32-bit Office SIP DLLs
│   ├── msosip.dll
│   └── Catalog/
├── x64/                      # 64-bit Office SIP DLLs [not used in this project]
│   ├── msosip.dll
│   └── Catalog/
└── Register-SIP.cmd          # Registration script
```

---

## How It Works

1. **SIP Hash Computation** — Calls `CryptSIPCreateIndirectData` to compute the VBA project digest
2. **Azure Signing** — Signs the digest remotely via Azure.CodeSigning SDK
3. **PKCS#7 Assembly** — Constructs a valid Authenticode CMS SignedData using `System.Formats.Asn1`
4. **Signature Embedding** — Calls `CryptSIPPutSignedDataMsg` to embed the signature in the Office file
5. **Triple-Signing** — Repeats for legacy, agile, and V3 signatures (default: 3 passes)

---

## Building the Project

```cmd
cd OfficeVbaSigner
dotnet build -c Release
```

The compiled executable will be located at:
```
bin/Release/net10.0-windows/OfficeVbaSigner.exe
```

---

## Troubleshooting

### "msosip.dll not found"
- Ensure the Office SIPs are registered using `regsvr32`
- Verify the correct bitness (32-bit vs 64-bit)

### "Azure authentication failed"
- Run `az login` to authenticate with Azure
- Check that your Trusted Signing account and certificate profile exist
- Verify the endpoint matches your account region

### "vbe7.dll not found"
- Install Office or ensure vbe7.dll is in the system PATH
- Register vbe7.dll in HKLM if necessary

---

## Documentation

For detailed implementation information, see [OfficeVbaSigner/README.md](./OfficeVbaSigner/README.md).

