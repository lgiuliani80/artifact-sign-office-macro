Microsoft Office Subject Interface Packages (SIPs)

WHAT THIS PACKAGE CONTAINS

	msosip.dll - Subject Interface Package library to facilitate the signing and verification of
		signatures for VBA projects contained in legacy Office file formats.
	msosipx.dll - Subject Interface Package library to facilitate the signing and verification of
		signatures for VBA projects contained in OOXML Office file formats.
	offclearsig.exe - Tool for removing existing signatures for VBA projects from Office file
		types supported by the included SIPs.
	offsign.bat - Batch file for signing and verification of signatures for VBA projects contained 
		in Office file types supported by the included SIPs.
	vbe7.dll - VBE7 runtime library, which is used in the process of generating and validating the
		signatures for the VBA projects during signing or signature verification.
	eula.txt - Licensing terms. If you do not agree to the terms specified in this file, do not use
		the binaries in this package.
	readme.txt - Information on the purpose and use of the files in this package.

WHAT THESE COMPONENTS ARE FOR

	Subject Interface Packages (SIPs) are libraries that integrate with the Windows cryptographic
	stack to allow for the signing and verification of file types not natively understood by the
	default Windows cryptography components. Once the SIP is registered with the system, the file
	types supported by the SIP can be signed and verified using tools (such as signtool.exe) that
	would normally be used to perform these operations on standard executable modules (such as EXEs
	or DLLs).

HOW TO USE THESE COMPONENTS

	1) If not already present on the machine where the tools will be run, download and install the
		Microsoft Visual C++ Runtime Libraries. The installer for the redistributable can be found at 
		https://download.microsoft.com/download/C/6/D/C6D0FD4E-9E53-4897-9B91-836EBA2AACD3/vcredist_x86.exe

	2) Extract the files in the package to a directory. The files can be located at any local path on
		the machine where the signing and verification operations will be performed. Due to the
		sensitive nature of the operations the binaries perform, the chosen location should be
		well secured.

	3) The vbe7.dll library can be either located in the same directory as the SIP libraries, or it
		can be located in an alternate location, and its location registered for discovery in
		the Windows registry at:
			[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VBA]
			REG_SZ Value "Vbe71DllPath" set to the full path to vbe7.dll library

	4) Run regsvr32.exe on the SIP libraries (i.e. msosip.dll / msosipx.dll) you wish to use.
		Regsvr32.exe must be run with Administrator privileges because the libraries are
		registered into the HKEY_LOCAL_MACHINE registry hive.

		ALTERNATIVELY: an alternative SIP registration mechanism is to create an INI file called
		wintrust.dll.ini that lists the available SIP libraries you wish the cryptographic stack
		to consider. This INI file must be located side-by-side the wintrust.dll binary in SYSTEM32.
		Note that this INI file, if it is present, will control the SIP discovery for all calls
		into the Windows Cryptographic APIs and not just those of the tools in this package.
		The format in this INI file for the msosip.dll and msiosipx.dll modules is as follows:

		For x86 Office SIPs:
		[index]
		DLL=<path to msosip.dll>
		GUID={01F45160-3E3E-11D3-B49A-00104B2CF645}
		CryptSIPDllCreateIndirectData=_VBASipCreateIndirectData@12
		CryptSIPDllGetSignedDataMsg=_VBASipGetSignedDataMsg@20
		CryptSIPDllIsMyFileType2=_VBASipIsMyTypeOfFileName@8
		CryptSIPDllPutSignedDataMsg=_VBASipPutSignedDataMsg@20
		CryptSIPDllRemoveSignedDataMsg=_VBASipRemoveSignedDataMsg@8
		CryptSIPDllVerifyIndirectData=_VBASipVerifyIndirectData@8

		[index]
		DLL=<path to msosipx.dll>
		GUID={6E64D5BD-CEB0-4B66-B4A0-15AC71775C48}
		CryptSIPDllCreateIndirectData=_VBASipCreateIndirectData@12
		CryptSIPDllGetSignedDataMsg=_VBASipGetSignedDataMsg@20
		CryptSIPDllIsMyFileType2=_VBASipIsMyTypeOfFileName@8
		CryptSIPDllPutSignedDataMsg=_VBASipPutSignedDataMsg@20
		CryptSIPDllRemoveSignedDataMsg=_VBASipRemoveSignedDataMsg@8
		CryptSIPDllVerifyIndirectData=_VBASipVerifyIndirectData@8

		For x64 Office SIPs:
		[index]
		DLL=<path to msosip.dll>
		GUID={01F45160-3E3E-11D3-B49A-00104B2CF645}
		CryptSIPDllCreateIndirectData=VBASipCreateIndirectData
		CryptSIPDllGetSignedDataMsg=VBASipGetSignedDataMsg
		CryptSIPDllIsMyFileType2=VBASipIsMyTypeOfFileName
		CryptSIPDllPutSignedDataMsg=VBASipPutSignedDataMsg
		CryptSIPDllRemoveSignedDataMsg=VBASipRemoveSignedDataMsg
		CryptSIPDllVerifyIndirectData=VBASipVerifyIndirectData

		[index]
		DLL=<path to msosipx.dll>
		GUID={6E64D5BD-CEB0-4B66-B4A0-15AC71775C48}
		CryptSIPDllCreateIndirectData=VBASipCreateIndirectData
		CryptSIPDllGetSignedDataMsg=VBASipGetSignedDataMsg
		CryptSIPDllIsMyFileType2=VBASipIsMyTypeOfFileName
		CryptSIPDllPutSignedDataMsg=VBASipPutSignedDataMsg
		CryptSIPDllRemoveSignedDataMsg=VBASipRemoveSignedDataMsg
		CryptSIPDllVerifyIndirectData=VBASipVerifyIndirectData

		Note: "index" is an integer that starts at 1 for the first SIP in the INI file and increments for each
		successive SIP listed. The "DLL" properties must be fully qualified paths to the SIP
		modules.

	5) Once registered, you can run your signing or verification procedure on supported Office files
		containing VBA macros.
			Example Command Line (signing):
				signtool.exe sign /f C:\Certificates\cert1.pfx /fd SHA256 C:\Files\FileWithMacros.xlsm
			Example Command Line (verification):
				signtool.exe verify C:\Files\FileWithMacros.xlsm

	6) Beginning with Office 2016, Office supports two different signatures on VBA projects. The
		first is the same signature format that has been supported in Office in past versions. The
		second is an improved signature format that allows for more agility in specifying new hashing
		algorithms as the cryptographic landscape changes over time.

	7) Beginning with 2020.7, Office 365 supports three different signatatues on VBA projects. The
		first two are the same signature formats that have been supported in Office in past versions.
		The third adds additional information into the signature to make it even more secure.

	8) The best practice when signing VBA projects in Office files involves creating all three signatures.
		However, the Windows cryptographic stack only supports creating one of these signatures at a
		time. To accomplish signing with three signatures, begin with a document with an unsigned VBA
		project and run signtool.exe (or other tool of your choice) the first time to sign the project.
		This will generate the legacy format signature. Running the tool again on the same file will
		add the second agile signature. Running the tool for the third time on the same file will add the 
		newer, more secure, signature. Note that if a file already has both legacy and agile signatures,
		any new attempts to sign the file will produce (or overwrite) the third signature. In order to
		sign a file from scratch again, including the legacy and agile signatures, the existing signatures
		must first be removed (see below).

		Note that this triple-signature format used for VBA projects is different in format than the
		built-in dual signing mechanism supported in more recent Windows versions, and so does not work
		with signtool.exe options such as "verify /all" or "verify /ds 1" which iterate over native
		Windows multiple signature stores.

		Due to limitations in the way SIPs integrate into the Windows cryptography stack, only one
		signature can be validated on a given file. If the legacy signature is present but the agile
		signature and third signature are not, the legacy signature will be validated. If the agile 
		signature is present but the third signature is not, the agile signature will be validated. 
		If the third signature is present, it will be validated. 

	9) If your signing process requires the removal of existing signatures from files in order to 
		properly support treble-signing the Office files as described above, you can use the included
		offclearsig.exe tool to accomplish this. This tool will remove any existing VBA signatures
		contained in the specified file. The tool depends on the SIPs being registered as described
		above.

	10) Offsign.bat provides a one command line option for fully signing and validating all signatures
		for VBA projects contained in Office files. The tool depends on SignTool.exe (from the Windows
		SDK) being installed and SIPs being registered as described above. In addition, the tool will call
		offclearsig.exe to remove any existing signatures in the currently processed file before signing.
		Ensure offsign.bat and offcleansig.exe are in the same directory. For usage, please run
		"offsign.bat help". This tool performs the following operations:
			i) Remove all existing signatures from the file.
			ii) Sign the file with the legacy signature.
			iii) Validate the file to ensure the legacy signature is valid.
			iv) Sign the file again, this time producing the agile signature.
			v) Validate the file once again to ensure the agile signature is valid.
			vi) Sign the file again, this time producing the third signature.
			vii) Validate the file once again to ensure the third signature is valid.


SUPPORTED FILE FORMATS

	MSOSIP:
		Excel: .xla, .xls, .xlt
		PowerPoint: .pot, .ppa, .pps, .ppt
		Project: .mpp, .mpt
		Publisher: .pub
		Visio: .vdw, .vsd, .vss, .vst
		Word: .doc, .dot, .wiz

	MSOSIPX:
		Excel: .xlam, .xlsb, .xlsm, .xltm
		PowerPoint: .potm, .ppam, .ppsm, .pptm
		Visio: .vsdm, .vssm, .vstm
		Word: .docm, .dotm

MICROSOFT OFFICE SUBJECT INTERFACE PACKAGES SUPPORT

	The Office SIPs are provided as-is with the following options available for support:
		1) Premier customers may either:
			i) Go to the Office Premier portal.
			ii) Log a support request or call tech support at the Premier support contacts page (https://aka.ms/premier_support_contacts).
		2) Broad Commercial customers may purchase professional support for a single incident or a pack of 5 (developer support not included), which includes phone support.
			i) To purchase: https://aka.ms/business_support_options
			ii) Phone support: https://aka.ms/business_phone_support
