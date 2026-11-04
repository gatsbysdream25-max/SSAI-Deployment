<#
.SYNOPSIS
  Install the SwarmSentinel agent on this Windows PC. It watches the PC and reports to a SwarmSentinel hub.

.DESCRIPTION
  Needs: an elevated PowerShell (Run as administrator), the hub's address, and a one-time enrollment code
  (hub dashboard -> Settings -> Machines -> New enrollment code).
  What it does: downloads ssai-agent.exe from the latest SSAI-Deployment release and checks its checksum, copies it to
  Program Files, enrolls this PC with the hub, and registers a Windows scheduled task that starts the agent at every boot
  as SYSTEM. It also adds a "SwarmSentinel Dashboard" icon to the Desktop and to the Start menu (it opens the hub's
  dashboard in your browser). Nothing needs Python. Remove it any time with -Uninstall.
  Private releases: if the releases repository is private, pass a read-only GitHub access token with -Token (or set
  $env:SSAI_UPDATE_TOKEN first). It is sent only to api.github.com and is not saved.
  Pin to Start: Windows does not let a program pin itself. Open Start, All apps, right-click SwarmSentinel Dashboard,
  choose Pin to Start.

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
    [ValidateSet("On", "Off")][string]$DesktopIcon = "On", # On: a "SwarmSentinel Dashboard" icon on the Desktop (all users)
    [ValidateSet("On", "Off")][string]$StartMenu = "On",   # On: the same entry in the Start menu's app list
    [string]$ExePath,                                   # use this exe instead of downloading (offline or testing)
    [string]$Repo = "gatsbysdream25-max/SSAI-Deployment",
    [string]$Token = $env:SSAI_UPDATE_TOKEN,            # a read-only GitHub access token, only if the releases repository is private
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

function Get-ShortcutFolders {
    @{ Desktop = [Environment]::GetFolderPath("CommonDesktopDirectory")
       Start   = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\SwarmSentinel" }
}

function Remove-Shortcuts {
    $folders = Get-ShortcutFolders
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $folders.Desktop "SwarmSentinel Dashboard.url")
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $folders.Start
}

# The dashboard address is the hub's address from this PC's own settings file (the agent talks to <hub>/api).
function Get-DashboardUrl {
    $settingsFile = Join-Path $DataDir "agent.json"
    if (-not (Test-Path $settingsFile)) { return $null }
    $api = (Get-Content -Raw $settingsFile | ConvertFrom-Json).api
    if (-not $api) { return $null }
    return ($api -replace '/api/?$', '') + "/dashboard"
}

function Write-Shortcut($folder, $url) {
    New-Item -ItemType Directory -Force -Path $folder | Out-Null
    $lines = @("[InternetShortcut]", "URL=$url", "IconFile=$Exe", "IconIndex=0")
    Set-Content -Path (Join-Path $folder "SwarmSentinel Dashboard.url") -Value $lines -Encoding ASCII
}

function Register-Shortcuts {
    Remove-Shortcuts                                    # this run decides which ones exist
    $url = Get-DashboardUrl
    if (-not $url) { Say "No hub address found, so no dashboard icon was made"; return }
    $folders = Get-ShortcutFolders
    if ($DesktopIcon -eq "On") { Write-Shortcut $folders.Desktop $url; Say "Added the SwarmSentinel Dashboard icon to the Desktop" }
    if ($StartMenu -eq "On")   { Write-Shortcut $folders.Start $url;   Say "Added SwarmSentinel to the Start menu (to pin it: right-click it in Start, Pin to Start)" }
}

function Remove-Agent {
    Say "Stopping and removing the agent"
    Remove-Shortcuts
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
    $target = Join-Path $env:TEMP $file
    if (-not $Token) {
        Invoke-WebRequest -Uri "https://github.com/$Repo/releases/latest/download/$file" -OutFile $target -UseBasicParsing
        return $target
    }
    # A private release has no public download address: find the file through the API, then fetch it with the token.
    $headers = @{ Authorization = "Bearer $Token"; "User-Agent" = "SwarmSentinel-installer" }
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $headers
    } catch {
        throw "Could not read the latest release of $Repo with that access token (is it right, and allowed to read the repository?)"
    }
    $asset = $release.assets | Where-Object { $_.name -eq $file } | Select-Object -First 1
    if (-not $asset) { throw "The latest release of $Repo has no file named $file" }
    $fileHeaders = @{ Authorization = "Bearer $Token"; Accept = "application/octet-stream"; "User-Agent" = "SwarmSentinel-installer" }
    try {
        # GitHub answers with a redirect to a signed address. Follow it without the token (the file store refuses both together).
        Invoke-WebRequest -Uri $asset.url -Headers $fileHeaders -OutFile $target -UseBasicParsing -MaximumRedirection 0 -ErrorAction Stop
    } catch {
        $response = $_.Exception.Response
        if ($response -and ([int]$response.StatusCode -in 301, 302, 303, 307, 308)) {
            $where = if ($response.Headers.Location) { $response.Headers.Location.ToString() } else { $response.Headers["Location"] }
            Invoke-WebRequest -Uri $where -OutFile $target -UseBasicParsing
        } else {
            throw "Download of $file failed: $($_.Exception.Message)"
        }
    }
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
Register-Shortcuts
Show-Result
