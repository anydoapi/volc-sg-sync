#define AppName "volc-sg-sync"
#define AppVersion "1.0.0"
#define AppPublisher "anydoapi"
#define AppExeName "volc-sg-sync.exe"

[Setup]
AppId={{D3C2D8D2-6F8F-4CE1-A8E7-8B74F1B3901E}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\VolcSgSync
OutputDir=..\..\dist
OutputBaseFilename=volc-sg-sync-setup
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
DisableProgramGroupPage=yes
ChangesEnvironment=yes

[Files]
Source: "..\..\dist\volc-sg-sync.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\dist\config.example.yaml"; DestDir: "{app}"; Flags: onlyifdoesntexist
Source: "..\..\dist\webui\*"; DestDir: "{app}\webui"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "install.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "install.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "manage.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "manage.bat"; DestDir: "{app}"; Flags: ignoreversion

[Run]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File \"{app}\install.ps1\" -InstallDir \"{app}\" -SourceDir \"{app}\""; Flags: runhidden waituntilterminated

[UninstallRun]
Filename: "schtasks.exe"; Parameters: "/Delete /TN \"VolcSgSync\" /F"; Flags: runhidden

[Code]
var
  CredentialPage: TInputQueryWizardPage;

procedure InitializeWizard;
begin
  CredentialPage := CreateInputQueryPage(wpSelectDir,
    '火山引擎凭据', '请输入 Access Key',
    '凭据将保存为本机环境变量，供开机自启任务使用。');
  CredentialPage.Add('Access Key ID:', False);
  CredentialPage.Add('Secret Access Key:', True);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = CredentialPage.ID then begin
    if Trim(CredentialPage.Values[0]) = '' then begin
      MsgBox('Access Key ID 不能为空。', mbError, MB_OK);
      Result := False;
    end else if Trim(CredentialPage.Values[1]) = '' then begin
      MsgBox('Secret Access Key 不能为空。', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then begin
    RegWriteStringValue(HKLM,
      'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
      'VOLCENGINE_ACCESS_KEY_ID', CredentialPage.Values[0]);
    RegWriteStringValue(HKLM,
      'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
      'VOLCENGINE_SECRET_ACCESS_KEY', CredentialPage.Values[1]);
  end;
end;
