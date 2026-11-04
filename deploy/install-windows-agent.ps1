<#
.SYNOPSIS
  Install the SwarmSentinel agent on this Windows PC. It watches the PC and reports to a SwarmSentinel hub.

.DESCRIPTION
  Needs: an elevated PowerShell (Run as administrator), the hub's address, and a one-time enrollment code
  (hub dashboard -> Settings -> Machines -> New enrollment code).
  What it does: downloads ssai-agent.exe from the latest SSAI-Deployment release and checks its checksum, copies it to
  Program Files, enrolls this PC with the hub, and registers a Windows scheduled task that starts the agent at every boot
  as SYSTEM. Nothing needs Python. Remove it any time with -Uninstall.

.EXAMPLE
  .\install-windows-agent.ps1 -HubUrl http://192.168.1.20:5000 -EnrollCode ABCD-EFGH-JKLM-NPQR

.EXAMPLE
  .\install-windows-agent.ps1 -HubUrl http://192.168.1.20:5000 -EnrollCode ABCD-EFGH-JKLM-NPQR -AutoStart Off
  (installs and starts it now, but it will not come back after a reboot until you start it or re-run with -AutoStart On)

.EXAMPLE
  .\install-windows-agent.ps1 -Uninstall
#>
param(
    [string]$HubUrl,
    [string]$EnrollCode,
    [string]$NodeId,
    [ValidateSet("On", "Off")][string]$AutoStart = "On",   # On: start at every boot. Off: only when you start it by hand
    [string]$ExePath,                                   # use this exe instead of downloading (offline or testing)
    [string]$Repo = "gatsbysdream25-max/SSAI-Deployment",
    [switch]$Uninstall,
    [switch]$PurgeData                                  # with -Uninstall: also delete the credential and logs
)

$ErrorActionPreference = "Stop"
$TaskName   = "SwarmSentinel Agent"
$InstallDir = Join-Path $env:ProgramFiles "SwarmSentinel"
$DataDir    = Join-Path $env:ProgramData "SwarmSentinel"
$Exe        = Join-Path $InstallDir "ssai-agent.exe"

function Say($text) { Write-Host "==> $text" }

function Require-Administrator {
    $me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this in an administrator PowerShell (right-click PowerShell, Run as administrator): the agent reads the Security log and installs a system service."
    }
}

function Stop-Agent {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    }
    Get-Process -Name "ssai-agent" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

function Lift-Blocks {
    # Blocks and isolation the agent put in place are lifted only by the agent. Undo them first so removing it, or turning
    # off start-at-boot, can never leave this PC cut off from the network.
    if (Test-Path $Exe) {
        Say "Lifting any blocks or isolation the agent applied"
        & $Exe response --lift-all
        if ($LASTEXITCODE -ne 0) { Write-Host "WARNING: some changes could not be undone. Check Windows Firewall rules named SSAI-* and C:\Windows\System32\drivers\etc\hosts." }
    }
}

function Remove-Agent {
    Say "Stopping and removing the agent"
    Lift-Blocks
    Stop-Agent
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
    if ($PurgeData -and (Test-Path $DataDir)) { Remove-Item -Recurse -Force $DataDir; Say "Deleted $DataDir" }
    elseif (Test-Path $DataDir) { Say "Kept $DataDir (this PC's credential and logs). Add -PurgeData to delete it too." }
    Say "Removed. Also delete this machine on the hub's Settings page."
}

function Get-Download($file) {
    # PowerShell 5.1 does not use TLS 1.2 by default, which GitHub requires.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $url = "https://github.com/$Repo/releases/latest/download/$file"
    $target = Join-Path $env:TEMP $file
    Invoke-WebRequest -Uri $url -OutFile $target -UseBasicParsing
    return $target
}

function Get-VerifiedExe {
    if ($ExePath) {
        if (-not (Test-Path $ExePath)) { throw "No file at $ExePath" }
        return $ExePath
    }
    Say "Downloading ssai-agent.exe from the latest release of $Repo"
    $exe = Get-Download "ssai-agent.exe"
    $sumFile = Get-Download "ssai-agent.exe.sha256"
    $expected = ((Get-Content $sumFile -TotalCount 1) -split "\s+")[0].ToLower()
    $actual = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expected) { throw "Checksum mismatch: the download is damaged or has been tampered with. Nothing was installed." }
    Say "Checksum verified"
    return $exe
}

function Install-Files($source) {
    if ($AutoStart -eq "Off") { Lift-Blocks }          # without a start at boot nothing would lift them after a restart
    Stop-Agent
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item -Force $source $Exe
}

function Enroll-This-Pc {
    if (-not $HubUrl -or -not $EnrollCode) {
        if (Test-Path (Join-Path $DataDir "agent.json")) { Say "Already enrolled; keeping the existing credential"; return }
        throw "Give -HubUrl and -EnrollCode (a one-time code from the hub's Settings page)."
    }
    Say "Enrolling with $HubUrl"
    $arguments = @("enroll", "--hub", $HubUrl, "--code", $EnrollCode)
    if ($NodeId) { $arguments += @("--node-id", $NodeId) }
    & $Exe @arguments
    if ($LASTEXITCODE -ne 0) { throw "Enrollment failed (see the message above). The code may be wrong, used or expired." }
}

function Register-StartupTask {
    $action    = New-ScheduledTaskAction -Execute $Exe -Argument "run"
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
                   -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) `
                   -MultipleInstances IgnoreNew
    if ($AutoStart -eq "On") {
        Say "Registering the task: runs as SYSTEM and starts at every boot"
        $trigger = New-ScheduledTaskTrigger -AtStartup
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    } else {
        Say "Registering the task WITHOUT starting at boot (start it yourself when you want it)"
        Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    }
    Start-ScheduledTask -TaskName $TaskName
}

function Show-Result {
    Start-Sleep -Seconds 12
    Say "Checking the connection"
    & $Exe status
    Write-Host ""
    Write-Host "Done. Look for this PC on the hub's dashboard (Settings -> Machines)."
    Write-Host "Log file: $(Join-Path $DataDir 'agent.log')"
    if ($AutoStart -eq "On") {
        Write-Host "It starts by itself at every boot. To turn that off, run this installer again with -AutoStart Off."
    } else {
        Write-Host "It is running now but will NOT start after a reboot."
        Write-Host "  Start it:  Start-ScheduledTask -TaskName '$TaskName'"
        Write-Host "  Stop it:   Stop-ScheduledTask  -TaskName '$TaskName'"
        Write-Host "  Boot start on later: run this installer again with -AutoStart On"
    }
}

Require-Administrator
if ($Uninstall) { Remove-Agent; return }
$verified = Get-VerifiedExe
Install-Files $verified
Enroll-This-Pc
Register-StartupTask
Show-Result
