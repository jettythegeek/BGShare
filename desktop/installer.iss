; Inno Setup 6 script for BGShare. build.ps1 calls:  ISCC /DMyAppVersion=2.1.0 /DSourceDir=dist\BGShare installer.iss
#ifndef MyAppVersion
  #define MyAppVersion "2.1.0"
#endif
#ifndef SourceDir
  #define SourceDir "dist\BGShare"
#endif
#ifndef OneFile
  #define OneFile "0"
#endif
#define MyAppName "BGShare"
#define MyAppExe "BGShare.exe"

[Setup]
AppId={{6B7C2E4A-5D1F-4C3B-9A8E-2F0B1D6C7E91}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=Blue Giraffe Development Ltd
AppPublisherURL=https://bluegiraffedev.com
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=Output
OutputBaseFilename=BGShare-Setup
SetupIconFile=bgshare.ico
UninstallDisplayIcon={app}\{#MyAppExe}
UninstallDisplayName={#MyAppName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
WizardImageFile=wizard-large-100.bmp,wizard-large-150.bmp,wizard-large-200.bmp
WizardSmallImageFile=wizard-small-100.bmp,wizard-small-150.bmp,wizard-small-200.bmp
WizardImageStretch=no
WizardImageBackColor=$FFFCFA
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; admin is needed to add the Windows Firewall rules for TCP 8890 / UDP 8890
PrivilegesRequired=admin
CloseApplications=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"
Name: "autostart"; Description: "Start BGShare when I sign in to Windows"; GroupDescription: "Startup:"
Name: "firewall"; Description: "Allow BGShare through Windows Firewall on private networks (TCP 8890 for transfers, UDP 8890 for finding other BGShare PCs)"; GroupDescription: "Network:"

[Files]
#if OneFile == "1"
Source: "{#SourceDir}\{#MyAppExe}"; DestDir: "{app}"; Flags: ignoreversion
#else
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
#endif
Source: "bgshare.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; IconFilename: "{app}\bgshare.ico"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; IconFilename: "{app}\bgshare.ico"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#MyAppName}"; ValueData: """{app}\{#MyAppExe}"" --minimized"; Flags: uninsdeletevalue; Tasks: autostart

[Run]
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""BGShare"""; Flags: runhidden; Tasks: firewall
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""BGShare TCP 8890"""; Flags: runhidden; Tasks: firewall
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""BGShare UDP 8890"""; Flags: runhidden; Tasks: firewall
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""BGShare TCP 8890"" dir=in action=allow protocol=TCP localport=8890 profile=private enable=yes"; Flags: runhidden; Tasks: firewall
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""BGShare UDP 8890"" dir=in action=allow protocol=UDP localport=8890 profile=private enable=yes"; Flags: runhidden; Tasks: firewall
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""BGShare"" dir=in action=allow program=""{app}\{#MyAppExe}"" profile=private enable=yes"; Flags: runhidden; Tasks: firewall
Filename: "{app}\{#MyAppExe}"; Description: "Launch BGShare"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""BGShare"""; Flags: runhidden; RunOnceId: "DelFwProgram"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""BGShare TCP 8890"""; Flags: runhidden; RunOnceId: "DelFwTcp"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""BGShare UDP 8890"""; Flags: runhidden; RunOnceId: "DelFwUdp"

[UninstallDelete]
; settings, history and bgshare.log in %APPDATA%\BGShare and received files in Downloads\BGShare are kept
Type: filesandordirs; Name: "{app}"

[Code]
procedure StopRunningBGShare();
var R: Integer;
begin
  { BGShare keeps running in the tray after its window closes; stop every copy so files can be replaced. }
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM BGShare.exe', '', SW_HIDE, ewWaitUntilTerminated, R);
  Sleep(800);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopRunningBGShare();
  Result := '';
end;

function InitializeUninstall(): Boolean;
begin
  StopRunningBGShare();
  Result := True;
end;
