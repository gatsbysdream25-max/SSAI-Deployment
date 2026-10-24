<#
.SYNOPSIS
  Install SwarmSentinel on a Windows 10/11 PC by giving it a small Ubuntu (WSL2) to run in, then using the normal installer.

.DESCRIPTION
  SwarmSentinel's agents are Linux programs, so on Windows they run inside WSL2 (Windows' built-in Linux).
  What this means for protection: the dashboard, the AI panel and the threat feeds work fully; the host sensors
  watch the Ubuntu inside WSL2, NOT Windows itself (there is no native Windows agent yet).

  What it does, in order. Nothing is changed until you drop -CheckOnly:
    1. Checks the PC (Windows version, memory, disk, virtualization, administrator rights).
    2. Installs WSL2 and Ubuntu 24.04 if they are missing (this can need one restart: run the script again after it).
    3. Turns on systemd inside Ubuntu, so the services start like on a normal Ubuntu machine.
    4. Unpacks your SwarmSentinel package inside Ubuntu and runs deploy/install.sh there.
    5. Adds a Windows scheduled task that keeps WSL2 running, because Windows stops an idle WSL2 and the services with it.

.PARAMETER Package
  The .tar.gz made by deploy/make-release.sh on a machine that has the repository (the repository itself is private).

.PARAMETER Role
  hub (default): dashboard, API and every agent.   node: host sensors only, reports to a hub (needs -HubUrl and -EnrollCode).

.PARAMETER SkipModels
  A hub normally also downloads local AI models sized to the PC's memory (about 17 GB with 16 GB of memory or more), so the AI
  panel works with no cloud keys. -SkipModels leaves that out; deploy/get-models.sh does it later.

.PARAMETER CheckOnly
  Only look and report what would happen. Changes nothing. Run this first.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File deploy\install-windows.ps1 -CheckOnly
  powershell -ExecutionPolicy Bypass -File deploy\install-windows.ps1 -Package C:\Users\me\Downloads\swarmsentinel-v1.tar.gz

.NOTES
  Not yet tested on a real PC: the first run on one is the test. It stops at the first thing it cannot do and says why.
#>
param(
    [string]$Package = "",
    [ValidateSet("hub", "node")][string]$Role = "hub",
    [string]$HubUrl = "",
    [string]$EnrollCode = "",
    [string]$Distro = "Ubuntu-24.04",
    [switch]$CheckOnly,
    [switch]$SkipModels
)

$ErrorActionPreference = "Stop"
$script:Problems = @()

function Say($text)  { Write-Host $text }
function Fail($text) { Write-Host "STOP: $text" -ForegroundColor Red; exit 1 }
function Note-Problem($text) { $script:Problems += $text; Write-Host "  [!] $text" -ForegroundColor Yellow }
function Note-Ok($text) { Write-Host "  [ok] $text" -ForegroundColor Green }

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-ThisPc {
    Say "1. Checking this PC"
    $build = [Environment]::OSVersion.Version.Build
    if ($build -ge 19041) { Note-Ok "Windows build $build supports WSL2" } else { Note-Problem "Windows build $build is too old for WSL2 (needs 19041 or newer)" }

    $ramGb = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
    if ($ramGb -ge 16) { Note-Ok "$ramGb GB of memory: enough to run local AI models" }
    elseif ($ramGb -ge 8) { Note-Ok "$ramGb GB of memory: the dashboard and cloud AI work; local models will be small" }
    else { Note-Problem "$ramGb GB of memory is too little for WSL2 plus SwarmSentinel" }

    $freeGb = [math]::Round((Get-PSDrive -Name ($env:SystemDrive.TrimEnd(':'))).Free / 1GB)
    if ($freeGb -ge 30) { Note-Ok "$freeGb GB free on $env:SystemDrive" } else { Note-Problem "only $freeGb GB free on $env:SystemDrive (30 GB or more recommended; local AI models are several GB each)" }

    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    # The firmware flag reads False once Windows' own hypervisor is running, so a running hypervisor also counts as "on".
    $hypervisorRunning = (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
    if ($cpu.VirtualizationFirmwareEnabled -or $hypervisorRunning) { Note-Ok "virtualization is available" }
    else { Note-Problem "virtualization looks switched off in the BIOS/UEFI (WSL2 needs it; look for 'Intel VT-x' or 'SVM')" }

    if (Test-Administrator) { Note-Ok "running as administrator" }
    elseif ($CheckOnly) { Say "  (not administrator: fine for a check, needed for the install)" }
    else { Fail "installing needs an administrator PowerShell (right-click PowerShell, Run as administrator)" }

    $gpu = (Get-CimInstance Win32_VideoController | Where-Object { $_.Name -match "NVIDIA" } | Select-Object -First 1).Name
    if ($gpu) { Say "  graphics card: $gpu (Ollama on Windows can use it, so AI answers are much faster)" }
    else { Say "  no NVIDIA graphics card found: local AI models will run on the processor and be slower" }
}

function Get-WslDistros {
    # `wsl --list` writes UTF-16, which PowerShell shows with gaps between letters; strip the NUL characters first.
    $raw = (& wsl.exe --list --quiet 2>$null) -join "`n"
    return ($raw -replace "`0", "") -split "`r?`n" | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
}

function Test-WslReady {
    Say "2. Checking WSL2 and Ubuntu"
    if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return $false }
    $names = @(Get-WslDistros)
    if ($names -contains $Distro) { Note-Ok "$Distro is installed"; return $true }
    Note-Problem "$Distro is not installed yet"
    return $false
}

function Install-Wsl {
    Say "   installing WSL2 and $Distro (a download of about 1 GB)"
    & wsl.exe --install -d $Distro --no-launch
    if (-not (@(Get-WslDistros) -contains $Distro)) {
        Say ""
        Say "WSL2 is set up but Windows needs a restart before Ubuntu appears."
        Say "Restart the PC, then run this same command again: it carries on from here."
        exit 0
    }
}

function Invoke-InUbuntu([string]$command) {
    # Runs one shell command as root inside Ubuntu and stops the whole script if it fails.
    & wsl.exe -d $Distro -u root -- bash -c $command
    if ($LASTEXITCODE -ne 0) { Fail "this step failed inside Ubuntu: $command" }
}

function Enable-Systemd {
    Say "3. Turning on systemd inside Ubuntu (so the services start like on a normal server)"
    Invoke-InUbuntu "grep -qs 'systemd *= *true' /etc/wsl.conf || printf '[boot]\nsystemd=true\n' >> /etc/wsl.conf"
    & wsl.exe --terminate $Distro      # the setting is read when Ubuntu starts
    Start-Sleep -Seconds 3
    Invoke-InUbuntu "systemctl is-system-running --wait >/dev/null 2>&1; systemctl --version | head -1"
}

function ConvertTo-WslPath([string]$windowsPath) {
    # C:\Users\me\file.tar.gz becomes /mnt/c/Users/me/file.tar.gz, the way WSL mounts Windows drives. Done here rather than
    # with Ubuntu's `wslpath`, because backslashes get eaten on the way into Ubuntu and the answer came back empty.
    if ($windowsPath -notmatch '^([A-Za-z]):\\(.*)$') { Fail "cannot turn this path into a WSL path (use a package on a normal drive): $windowsPath" }
    return "/mnt/" + $Matches[1].ToLower() + "/" + ($Matches[2] -replace '\\', '/')
}

function Install-SwarmSentinel {
    Say "4. Unpacking the package and running the normal installer inside Ubuntu"
    if (-not (Test-Path $Package)) { Fail "package not found: $Package (make one with deploy/make-release.sh)" }
    $linuxPath = ConvertTo-WslPath (Resolve-Path $Package).Path
    Invoke-InUbuntu "id ssai >/dev/null 2>&1 || useradd -m -s /bin/bash ssai"
    Invoke-InUbuntu "rm -rf /opt/ssai-src && mkdir -p /opt/ssai-src && tar xzf '$linuxPath' -C /opt/ssai-src"
    # The package was unpacked by root, but the installer builds as the service account (ssai), which must own the folder.
    Invoke-InUbuntu "chown -R ssai:ssai /opt/ssai-src"
    $options = "--user ssai --role $Role"
    if ($Role -eq "node") {
        if (-not $HubUrl -or -not $EnrollCode) { Fail "a node needs -HubUrl and -EnrollCode (make a code in the hub's Settings page)" }
        $options += " --hub-url '$HubUrl' --enroll-code '$EnrollCode'"
    }
    Invoke-InUbuntu "cd /opt/ssai-src/SwarmSentinel && ./deploy/install.sh $options"
    if ($Role -eq "hub" -and -not $SkipModels) {
        Say "   downloading local AI models (several GB; this is the longest step)"
        Invoke-InUbuntu "cd /opt/ssai-src/SwarmSentinel && ./deploy/get-models.sh --user ssai"
    }
}

function Add-KeepAliveTask {
    Say "5. Keeping WSL2 running (Windows stops an idle WSL2, and the services with it)"
    $action  = New-ScheduledTaskAction -Execute "wsl.exe" -Argument "-d $Distro -u root --exec /bin/sleep infinity"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
    Register-ScheduledTask -TaskName "SwarmSentinel keep WSL running" -Action $action -Trigger $trigger -Settings $settings `
        -User "SYSTEM" -RunLevel Highest -Force | Out-Null
    Start-ScheduledTask -TaskName "SwarmSentinel keep WSL running"
    Note-Ok "scheduled task added (starts at boot)"
}

# ---------------------------------------------------------------------------------------------------------------------
Test-ThisPc
$ready = Test-WslReady

if ($CheckOnly) {
    Say ""
    $blockers = @($script:Problems | Where-Object { $_ -notmatch "not installed yet" })
    if ($blockers.Count -gt 0) { Say "$($blockers.Count) thing(s) to sort out first (marked [!]). Nothing was changed." }
    elseif (-not $ready) { Say "This PC is fine. The install will add WSL2 and Ubuntu first. Nothing was changed." }
    else { Say "Everything needed is in place. Run again without -CheckOnly and with -Package to install." }
    exit 0
}
if ($script:Problems | Where-Object { $_ -notmatch "not installed yet" }) { Fail "fix the items marked [!] above, then run again" }
if (-not $Package) { Fail "give the package with -Package <path to swarmsentinel-*.tar.gz>" }

if (-not $ready) { Install-Wsl }
Enable-Systemd
Install-SwarmSentinel
Add-KeepAliveTask

Say ""
Say "Done. The dashboard is at http://localhost:5000 in your Windows browser."
Say "The report above says what protection level this PC reached. Remember: host sensors watch the Ubuntu inside WSL2, not Windows."
