; System Informer Pro -- Inno Setup script for the RE-lab target.
;
; Packages the UNPROTECTED host (SystemInformer.exe) + the two PROTECTED binaries that carry the licensing
; gate: sip_progate.dll (VMProtect) and plugins\ExtendedTools.dll (Themida), plus the runtime deps the /MD
; licensing core needs. The per-machine license (SystemInformer.sipm) and the KPH kernel driver are
; deliberately NOT shipped (see the comments in [Files] and ACTIVATION.txt).
;
; Build (ISCC installed per-user by winget at the path below):
;   "C:\Users\nilot\AppData\Local\Programs\Inno Setup 6\ISCC.exe" system_informer_pro.iss
; Source roots can be overridden:  ISCC /DBinDir="..." /DCrtDir="..." system_informer_pro.iss

#ifndef BinDir
  #define BinDir "C:\Tools\GameSecLab\demo\systeminformer\bin\Release64"
#endif
#ifndef CrtDir
  ; VC14x /MD redistributable CRT (sip_progate.dll is /MD). Bump the version folder if VS updates.
  #define CrtDir "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Redist\MSVC\14.51.36231\x64\Microsoft.VC145.CRT"
#endif
#define AppName "System Informer Pro"
#define AppVer  "3.2.0.0"
#define AppPub  "Winsider Seminars & Solutions (RE-lab fork)"

[Setup]
AppId={{B1E9C0A2-5F7D-4E2A-9C31-5100A1F0C0DE}
AppName={#AppName}
AppVersion={#AppVer}
AppPublisher={#AppPub}
DefaultDirName={autopf}\System Informer Pro
DefaultGroupName=System Informer Pro
UninstallDisplayIcon={app}\SystemInformer.exe
OutputDir={#SourcePath}Output
OutputBaseFilename=SystemInformerProSetup
Compression=lzma2/ultra64
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
WizardStyle=modern

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
; --- host application (unprotected by design) ---
Source: "{#BinDir}\SystemInformer.exe";        DestDir: "{app}";         Flags: ignoreversion
; --- VMProtect-protected licensing core + its runtime deps ---
Source: "{#BinDir}\sip_progate.dll";           DestDir: "{app}";         Flags: ignoreversion
Source: "{#BinDir}\libcrypto-1_1-x64.dll";     DestDir: "{app}";         Flags: ignoreversion
; --- Themida-protected plugin (cross-DLL handshake challenger) ---
Source: "{#BinDir}\plugins\ExtendedTools.dll"; DestDir: "{app}\plugins"; Flags: ignoreversion
; --- VC/MD runtime (required only because sip_progate.dll is /MD) ---
Source: "{#CrtDir}\msvcp140.dll";              DestDir: "{app}";         Flags: ignoreversion
Source: "{#CrtDir}\vcruntime140.dll";          DestDir: "{app}";         Flags: ignoreversion
Source: "{#CrtDir}\vcruntime140_1.dll";        DestDir: "{app}";         Flags: ignoreversion
; --- activation notes (offered at end of install) ---
Source: "{#SourcePath}ACTIVATION.txt";         DestDir: "{app}";         Flags: ignoreversion isreadme
;
; INTENTIONALLY NOT SHIPPED:
;   * SystemInformer.sys / ksi.dll / ksidyn.bin  -- the KPH kernel driver. With KPH loaded, KphOpenProcess
;     bypasses the user-mode ACCESS_MASK gate this lab is built to demonstrate, so the demo runs KPH-off.
;   * SystemInformer.sipm                         -- the license is per-HWID and issued separately (ACTIVATION.txt).
;   * VMProtectSDK64.dll                          -- the VMProtect pass embeds its runtime into sip_progate.dll.
;   * *.pdb / *.lib / *.exp / *.obj / test exes   -- build artifacts.

[Icons]
Name: "{group}\System Informer Pro";            Filename: "{app}\SystemInformer.exe"
Name: "{group}\Activation notes";               Filename: "{app}\ACTIVATION.txt"
Name: "{group}\Uninstall System Informer Pro";  Filename: "{uninstallexe}"
Name: "{autodesktop}\System Informer Pro";      Filename: "{app}\SystemInformer.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\SystemInformer.exe"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent
