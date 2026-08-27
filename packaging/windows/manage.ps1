param(
    [ValidateSet("start", "stop", "status", "uninstall")]
    [string]$Action = "status",
    [string]$InstallDir = "$PSScriptRoot"
)

$ErrorActionPreference = "Stop"
$task = "VolcSgSync"

function Ensure-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $admin = ([Security.Principal.WindowsPrincipal] $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($admin) { return }
    $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-Action', $Action, '-InstallDir', $InstallDir)
    $p = Start-Process powershell.exe -Verb RunAs -ArgumentList $args -Wait -PassThru
    exit $p.ExitCode
}

if ($Action -in @("start", "stop", "uninstall")) { Ensure-Admin }

switch ($Action) {
    "start" {
        Start-ScheduledTask -TaskName $task
        Write-Host "[SUCCESS] Task started. Web console: http://127.0.0.1:12345"
    }
    "stop" {
        Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
        Write-Host "[SUCCESS] Task stopped."
    }
    "status" {
        $info = Get-ScheduledTaskInfo -TaskName $task -ErrorAction Stop
        Write-Host "Task: $task"
        Write-Host "State: $((Get-ScheduledTask -TaskName $task).State)"
        Write-Host "Last run: $($info.LastRunTime)"
        Write-Host "Last result: $($info.LastTaskResult)"
        Write-Host "Web console: http://127.0.0.1:12345"
    }
    "uninstall" {
        $installPath = [IO.Path]::GetFullPath($InstallDir)
        Write-Host "[1/4] Stopping scheduled task..."
        Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "[2/4] Stopping running processes..."
        Get-CimInstance Win32_Process -Filter "Name='volc-sg-sync.exe'" -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.ExecutablePath -and ([IO.Path]::GetFullPath($_.ExecutablePath)).StartsWith($installPath, [StringComparison]::OrdinalIgnoreCase)) {
                Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Host "[3/4] Removing credentials..."
        [Environment]::SetEnvironmentVariable("VOLCENGINE_ACCESS_KEY_ID", [string]::Empty, "Machine")
        [Environment]::SetEnvironmentVariable("VOLCENGINE_SECRET_ACCESS_KEY", [string]::Empty, "Machine")
        [Environment]::SetEnvironmentVariable("VOLCENGINE_ACCESS_KEY_ID", [string]::Empty, "User")
        [Environment]::SetEnvironmentVariable("VOLCENGINE_SECRET_ACCESS_KEY", [string]::Empty, "User")
        Write-Host "[4/4] Scheduling installation directory removal: $installPath"
        $escaped = $installPath.Replace('"', '""')
        Start-Process -FilePath "cmd.exe" -ArgumentList '/c', "ping 127.0.0.1 -n 3 >nul & rmdir /s /q `"$escaped`"" -WindowStyle Hidden
        Write-Host "[SUCCESS] Scheduled task, process, credentials and installation files will be removed."
    }
}
