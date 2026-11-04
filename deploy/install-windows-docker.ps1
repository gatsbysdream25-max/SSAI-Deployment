<#
.SYNOPSIS
  Install SwarmSentinel on a Windows 10/11 PC: the hub runs in Docker inside WSL2, and the native Windows agent watches Windows itself.

.DESCRIPTION
  Two parts, set up together so nobody has to know about either:
    * The HUB (dashboard, AI panel, threat feeds) runs in Docker Engine inside a small Ubuntu (WSL2). Docker Engine is installed
      inside Ubuntu, not Docker Desktop, so there is nothing to license and nothing to click through.
    * The AGENT is ssai-agent.exe, a normal Windows program that watches THIS PC (Security log, Defender, crashes, ports,
      processes) and reports to the hub on localhost. It needs no Python and no WSL on its own.

  What it does, in order. Nothing is changed until you drop -CheckOnly:
    1. Checks the PC (Windows version, memory, disk, virtualization, administrator rights).
    2. Installs WSL2 and Ubuntu 24.04 if they are missing (this can need one restart: run the script again after it).
    3. Turns on systemd inside Ubuntu, then installs Docker Engine and the compose plugin there.
    4. Copies SwarmSentinel into Ubuntu's own disk (/opt/ssai) and starts it with `docker compose up -d --build`.
    5. Adds a Windows scheduled task that keeps WSL2 running, because Windows stops an idle WSL2 and the hub with it.
    6. Makes a one-time enrollment code on the hub and installs the Windows agent with it (see install-windows-agent.ps1).

.PARAMETER Source
  The SwarmSentinel folder to install from. Default: the folder this script lives in, one level up (the repository / unpacked package).

.PARAMETER AgentExe
  Use this ssai-agent.exe for the Windows agent instead of downloading the latest release.

.PARAMETER SkipAgent
  Set up the hub only.

.PARAMETER CheckOnly
  Only look and report what would happen. Changes nothing. Run this first.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File deploy\install-windows-docker.ps1 -CheckOnly
  powershell -ExecutionPolicy Bypass -File deploy\install-windows-docker.ps1 -AgentExe C:\ssai-dist\ssai-agent.exe

.NOTES
  Not yet tested end to end on a real PC: the first run on one is the test. It stops at the first thing it cannot do and says why.
  Re-running is safe: it refreshes the files and restarts the hub; the hub's data lives in a Docker volume and is kept.
#>
param(
    [string]$Source = "",
    [string]$AgentExe = "",
    [string]$Distro = "Ubuntu-24.04",
    [switch]$SkipAgent,
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"
$script:Problems = @()
$AppDir = "/opt/ssai"

function Say($text)  { Write-Host $text }
function Fail($text) { Write-Host "STOP: $text" -ForegroundColor Red; exit 1 }
function Note-Problem($text) { $script:Problems += $text; Write-Host "  [!] $text" -ForegroundColor Yellow }
function Note-Ok($text) { Write-Host "  [ok] $text" -ForegroundColor Green }

if (-not $Source) { $Source = Split-Path -Parent $PSScriptRoot }

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-ThisPc {
    Say "1. Checking this PC"
    $build = [Environment]::OSVersion.Version.Build
    if ($build -ge 19041) { Note-Ok "Windows build $build supports WSL2" } else { Note-Problem "Windows build $build is too old for WSL2 (needs 19041 or newer)" }

    $ramGb = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
    if ($ramGb -ge 8) { Note-Ok "$ramGb GB of memory" } else { Note-Problem "$ramGb GB of memory is too little for WSL2 plus the hub (8 GB or more)" }

    $freeGb = [math]::Round((Get-PSDrive -Name ($env:SystemDrive.TrimEnd(':'))).Free / 1GB)
    if ($freeGb -ge 15) { Note-Ok "$freeGb GB free on $env:SystemDrive" } else { Note-Problem "only $freeGb GB free on $env:SystemDrive (15 GB or more needed for Ubuntu and the hub image)" }

    # The firmware flag reads False once Windows' own hypervisor is running, so a running hypervisor also counts as "on".
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    if ($cpu.VirtualizationFirmwareEnabled -or (Get-CimInstance Win32_ComputerSystem).HypervisorPresent) { Note-Ok "virtualization is available" }
    else { Note-Problem "virtualization looks switched off in the BIOS/UEFI (WSL2 needs it; look for 'Intel VT-x' or 'SVM')" }

    if (Test-Administrator) { Note-Ok "running as administrator" }
    elseif ($CheckOnly) { Say "  (not administrator: fine for a check, needed for the install)" }
    else { Fail "installing needs an administrator PowerShell (right-click PowerShell, Run as administrator)" }

    if (Test-Path (Join-Path $Source "docker-compose.yml")) { Note-Ok "SwarmSentinel found in $Source" }
    else { Note-Problem "no docker-compose.yml in $Source (use -Source <the SwarmSentinel folder>)" }

    if (-not $SkipAgent) {
        if ($AgentExe -and -not (Test-Path $AgentExe)) { Note-Problem "-AgentExe not found: $AgentExe" }
        elseif ($AgentExe) { Note-Ok "Windows agent: $AgentExe" }
        else { Say "  Windows agent: will be downloaded from the latest release (give -AgentExe to use a local build)" }
    }
}

function Get-WslDistros {
    # `wsl --list` writes UTF-16, which PowerShell shows with gaps between letters; strip the NUL characters first.
    $raw = (& wsl.exe --list --quiet 2>$null) -join "`n"
    return ($raw -replace "`0", "") -split "`r?`n" | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
}

function Test-WslReady {
    Say "2. Checking WSL2 and Ubuntu"
    if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { Note-Problem "$Distro is not installed yet"; return $false }
    if (@(Get-WslDistros) -contains $Distro) { Note-Ok "$Distro is installed"; return $true }
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

function Get-FromUbuntu([string]$command) {
    # Same, but returns what the command printed (trimmed), so a secret never has to be shown on screen.
    $out = & wsl.exe -d $Distro -u root -- bash -c $command
    if ($LASTEXITCODE -ne 0) { Fail "this step failed inside Ubuntu: $command" }
    return (($out -join "`n") -replace "`0", "").Trim()
}

function ConvertTo-WslPath([string]$windowsPath) {
    # C:\Users\me\x becomes /mnt/c/Users/me/x. Done here rather than with `wslpath`, because backslashes get eaten on the way in.
    if ($windowsPath -notmatch '^([A-Za-z]):\\(.*)$') { Fail "cannot turn this path into a WSL path (use a normal drive): $windowsPath" }
    return "/mnt/" + $Matches[1].ToLower() + "/" + ($Matches[2] -replace '\\', '/')
}

function Enable-Systemd {
    Say "3. Turning on systemd inside Ubuntu, then installing Docker Engine"
    Invoke-InUbuntu "grep -qs 'systemd *= *true' /etc/wsl.conf || printf '[boot]\nsystemd=true\n' >> /etc/wsl.conf"
    & wsl.exe --terminate $Distro      # the setting is read when Ubuntu starts
    Start-Sleep -Seconds 3
    Invoke-InUbuntu "systemctl is-system-running --wait >/dev/null 2>&1; systemctl --version | head -1"
}

function Install-DockerEngine {
    $have = & wsl.exe -d $Distro -u root -- bash -c "docker compose version >/dev/null 2>&1 && echo yes || echo no"
    if ((($have -join "") -replace "`0", "").Trim() -eq "yes") { Note-Ok "Docker Engine and compose are already installed"; return }
    Say "   adding Docker's package source and installing Docker Engine (a few minutes)"
    $repo = 'install -m 0755 -d /etc/apt/keyrings && ' +
            'curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc && chmod a+r /etc/apt/keyrings/docker.asc && ' +
            'echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list'
    Invoke-InUbuntu "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq ca-certificates curl >/dev/null && $repo"
    Invoke-InUbuntu "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null"
    Invoke-InUbuntu "systemctl enable --now docker && docker run --rm hello-world >/dev/null"
    Note-Ok "Docker Engine works"
}

function Install-Hub {
    Say "4. Copying SwarmSentinel into Ubuntu and starting the hub (the first build takes several minutes)"
    $linuxSource = ConvertTo-WslPath (Resolve-Path $Source).Path
    # Ubuntu's own disk, not /mnt/c: Docker builds and the database are far faster and safer there. .git and logs are left out.
    Invoke-InUbuntu ("mkdir -p $AppDir && cd '$linuxSource' && tar --exclude=.git --exclude=logs --exclude=__pycache__ -cf - . | tar -xf - -C $AppDir && " +
                     "find $AppDir -name '*.sh' -exec sed -i 's/\r$//' {} + && sed -i 's/\r$//' $AppDir/docker/*")
    Invoke-InUbuntu "cd $AppDir && docker compose up -d --build"
    Say "   waiting for the hub to answer"
    Invoke-InUbuntu "for i in `$(seq 1 60); do curl -fsS http://localhost:5000/health >/dev/null 2>&1 && exit 0; sleep 2; done; docker compose -f $AppDir/docker-compose.yml logs --tail 30; exit 1"
    Note-Ok "the hub is running at http://localhost:5000"
}

function Add-KeepAliveTask {
    Say "5. Keeping WSL2 running (Windows stops an idle WSL2, and the hub with it)"
    $action  = New-ScheduledTaskAction -Execute "wsl.exe" -Argument "-d $Distro -u root --exec /bin/sleep infinity"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
    Register-ScheduledTask -TaskName "SwarmSentinel keep WSL running" -Action $action -Trigger $trigger -Settings $settings `
        -User "SYSTEM" -RunLevel Highest -Force | Out-Null
    Start-ScheduledTask -TaskName "SwarmSentinel keep WSL running"
    Note-Ok "scheduled task added (starts at boot)"
}

function Install-WindowsAgent {
    Say "6. Installing the Windows agent, so SwarmSentinel watches Windows itself"
    # The hub's admin key never leaves Ubuntu: the enrollment code is requested there and only the code comes back.
    $request = "cd $AppDir && key=`$(docker compose exec -T swarmsentinel sh -c '. /data/.env; printf %s ""`$SSAI_API_KEY""') && " +
               "curl -fsS -X POST http://localhost:5000/api/nodes/enrollment-codes -H ""X-API-Key: `$key"" -H 'Content-Type: application/json' -d '{""ttl_minutes"":15}' " +
               "| python3 -c 'import json,sys; print(json.load(sys.stdin)[""code""])'"
    $code = Get-FromUbuntu $request
    if (-not $code) { Fail "the hub did not give an enrollment code" }
    $agentScript = Join-Path $PSScriptRoot "install-windows-agent.ps1"
    $arguments = @{ HubUrl = "http://localhost:5000"; EnrollCode = $code }
    if ($AgentExe) { $arguments.ExePath = (Resolve-Path $AgentExe).Path }
    & $agentScript @arguments
    if ($LASTEXITCODE -ne 0) { Fail "the Windows agent did not install (the message above says why). The hub is running; run install-windows-agent.ps1 again with a new code from Settings." }
}

# ---------------------------------------------------------------------------------------------------------------------
Test-ThisPc
$ready = Test-WslReady

if ($CheckOnly) {
    Say ""
    $blockers = @($script:Problems | Where-Object { $_ -notmatch "not installed yet" })
    if ($blockers.Count -gt 0) { Say "$($blockers.Count) thing(s) to sort out first (marked [!]). Nothing was changed." }
    elseif (-not $ready) { Say "This PC is fine. The install will add WSL2 and Ubuntu first. Nothing was changed." }
    else { Say "Everything needed is in place. Run again without -CheckOnly to install." }
    exit 0
}
if ($script:Problems | Where-Object { $_ -notmatch "not installed yet" }) { Fail "fix the items marked [!] above, then run again" }

if (-not $ready) { Install-Wsl }
Enable-Systemd
Install-DockerEngine
Install-Hub
Add-KeepAliveTask
if (-not $SkipAgent) { Install-WindowsAgent }

Say ""
Say "Done. Open http://localhost:5000/setup in your browser to add an AI provider key and set the dashboard password."
Say "The hub runs in Docker inside WSL2; the Windows agent watches this PC and reports to it."
Say "Check the agent any time:  & 'C:\Program Files\SwarmSentinel\ssai-agent.exe' status"
