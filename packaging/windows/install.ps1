param(
    [string]$InstallDir = "$PSScriptRoot",
    [string]$SourceDir = "$PSScriptRoot",
    [string]$ConfigSource = ""
)

$ErrorActionPreference = "Stop"
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal] $currentIdentity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[1/5] Requesting administrator permission..."
    $elevatedArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-InstallDir', $InstallDir, '-SourceDir', $SourceDir)
    if ($ConfigSource) { $elevatedArgs += @('-ConfigSource', $ConfigSource) }
    try {
        $child = Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $elevatedArgs -WorkingDirectory $InstallDir -Wait -PassThru
        if ($child.ExitCode -eq 0) {
            Write-Host "[SUCCESS] Administrator installation completed."
            exit 0
        }
        Write-Host "[WARN] Administrator process returned code $($child.ExitCode)."
    } catch {
        Write-Host "[WARN] Administrator request failed: $($_.Exception.Message)"
    }
    Write-Host "[WARN] Continuing with current-user installation."
}
Write-Host "[1/5] Administrator permission granted."
Write-Host "[2/5] Preparing installation directory: $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Write-Host "[3/5] Copying application files..."
$sourceExe = [IO.Path]::GetFullPath((Join-Path $SourceDir "volc-sg-sync.exe"))
$targetExe = [IO.Path]::GetFullPath((Join-Path $InstallDir "volc-sg-sync.exe"))
if ($sourceExe -ne $targetExe) { Copy-Item $sourceExe $targetExe -Force }
$sourceWeb = Join-Path $SourceDir "webui"
$targetWeb = Join-Path $InstallDir "webui"
if (Test-Path -LiteralPath $sourceWeb) {
    New-Item -ItemType Directory -Force -Path $targetWeb | Out-Null
    Copy-Item (Join-Path $sourceWeb "*") $targetWeb -Recurse -Force
}
if ($ConfigSource -and (Test-Path -LiteralPath $ConfigSource)) {
    Copy-Item $ConfigSource (Join-Path $InstallDir "config.yaml") -Force
} elseif (-not (Test-Path (Join-Path $InstallDir "config.yaml"))) {
    Copy-Item (Join-Path $SourceDir "config.example.yaml") (Join-Path $InstallDir "config.yaml")
}

$ak = [Environment]::GetEnvironmentVariable("VOLCENGINE_ACCESS_KEY_ID", "Machine")
$sk = [Environment]::GetEnvironmentVariable("VOLCENGINE_SECRET_ACCESS_KEY", "Machine")
if (-not $ak) { $ak = [Environment]::GetEnvironmentVariable("VOLCENGINE_ACCESS_KEY_ID", "User") }
if (-not $sk) { $sk = [Environment]::GetEnvironmentVariable("VOLCENGINE_SECRET_ACCESS_KEY", "User") }
if (-not $ak) { $ak = Read-Host "Access Key ID" }
if (-not $sk) { $sk = Read-Host "Secret Access Key" -AsSecureString; $sk = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sk)) }
if (-not $ak -or -not $sk) { throw "Access Key ID and Secret Access Key are required" }
$envScope = if ($isAdmin) { "Machine" } else { "User" }
Write-Host "[4/5] Saving credentials to $envScope environment variables..."
[Environment]::SetEnvironmentVariable("VOLCENGINE_ACCESS_KEY_ID", $ak, $envScope)
[Environment]::SetEnvironmentVariable("VOLCENGINE_SECRET_ACCESS_KEY", $sk, $envScope)

$task = "VolcSgSync"
$action = New-ScheduledTaskAction -Execute (Join-Path $InstallDir "volc-sg-sync.exe") -Argument "-config `"$(Join-Path $InstallDir 'config.yaml')`" -web-listen 127.0.0.1:12345 -web-static-dir `"$(Join-Path $InstallDir 'webui')`""
$trigger = if ($isAdmin) { New-ScheduledTaskTrigger -AtStartup } else { New-ScheduledTaskTrigger -AtLogOn }
$principal = if ($isAdmin) {
    New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
} else {
    New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
}
Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
Write-Host "[6/6] Starting task now..."
Start-ScheduledTask -TaskName $task
$mode = if ($isAdmin) { "system startup" } else { "user logon" }
Write-Host "[5/5] Registered $mode task $task"
Write-Host "[SUCCESS] Installed to $InstallDir"
Write-Host "[SUCCESS] Web console: http://127.0.0.1:12345"
if (-not $env:VOLC_SG_SYNC_SKIP_BROWSER) {
    Start-Process "http://127.0.0.1:12345"
}
