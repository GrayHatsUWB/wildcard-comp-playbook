#requires -version 5.1
<#
.SYNOPSIS
  CCDC Wildcard Event Windows triage/hardening helper.
.DESCRIPTION
  Collects evidence, applies a conservative set of defensive remediations, and flags
  findings for manual review. Designed for authorized defensive competition use.

  IMPORTANT:
  - Run from an elevated PowerShell session.
  - Review the transcript/log after execution.
  - This script prefers evidence collection and safe remediations over blind deletion.
  - Some steps are intentionally commented or gated behind -Aggressive because wildcard
    images often contain legitimate-but-unfamiliar software.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Aggressive,
    [string]$OutputRoot = 'C:\CCDC',
    [string[]]$KnownBadUsers = @('DefaultUser','mimakinami','Alan','Bitzi','Molly McDonald','t'),
    [string[]]$KnownBadTasks = @('MicrosoftEdgeUpdateTaskCore'),
    [string[]]$KnownBadFiles = @(
        'C:\inetpub\wwwroot\cmd.aspx',
        'C:\Windows\Temp\taskhelper.ps1',
        'C:\Windows\Temp\$77script.bat',
        'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2211.5-0\MpAup.dll'
    )
)

$ErrorActionPreference = 'Continue'
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Root = Join-Path $OutputRoot $timestamp
$null = New-Item -Path $Root -ItemType Directory -Force
$Log = Join-Path $Root 'triage.log'
$Findings = Join-Path $Root 'findings.txt'
$Actions = Join-Path $Root 'actions.txt'
Start-Transcript -Path (Join-Path $Root 'transcript.txt') -Force | Out-Null

function Write-Log {
    param([string]$Message)
    $line = "[$(Get-Date -Format s)] $Message"
    $line | Tee-Object -FilePath $Log -Append
}

function Add-Finding {
    param([string]$Message)
    "[$(Get-Date -Format s)] $Message" | Out-File -FilePath $Findings -Append -Encoding utf8
    Write-Host "[FINDING] $Message"
}

function Add-Action {
    param([string]$Message)
    "[$(Get-Date -Format s)] $Message" | Out-File -FilePath $Actions -Append -Encoding utf8
    Write-Host "[ACTION]  $Message"
}

function Invoke-Safely {
    param(
        [scriptblock]$Script,
        [string]$Description
    )
    try {
        Write-Log "START: $Description"
        & $Script
        Write-Log "DONE : $Description"
    }
    catch {
        Write-Log "FAIL : $Description :: $($_.Exception.Message)"
    }
}

function Save-Text {
    param([string]$Path,[object]$Data)
    try { $Data | Out-File -FilePath $Path -Width 4096 -Encoding utf8 }
    catch { Write-Log "Save failed for $Path :: $($_.Exception.Message)" }
}

function Export-Basic-SystemState {
    Invoke-Safely -Description 'Collect system baselines' -Script {
        hostname | Out-File (Join-Path $Root 'hostname.txt')
        whoami /all | Out-File (Join-Path $Root 'whoami_all.txt')
        systeminfo | Out-File (Join-Path $Root 'systeminfo.txt')
        ipconfig /all | Out-File (Join-Path $Root 'ipconfig_all.txt')
        route print | Out-File (Join-Path $Root 'route_print.txt')
        arp -a | Out-File (Join-Path $Root 'arp.txt')
        netstat -ano | Out-File (Join-Path $Root 'netstat_ano.txt')
        Get-Process | Sort-Object ProcessName | Format-Table -AutoSize | Out-File (Join-Path $Root 'processes.txt')
        Get-Service | Sort-Object Status,DisplayName | Format-Table -AutoSize | Out-File (Join-Path $Root 'services.txt')
        schtasks /query /fo LIST /v | Out-File (Join-Path $Root 'scheduled_tasks.txt')
        net share | Out-File (Join-Path $Root 'shares.txt')
        Get-SmbShare | Format-Table -AutoSize | Out-File (Join-Path $Root 'smbshares.txt')
        Get-LocalUser | Format-List * | Out-File (Join-Path $Root 'local_users.txt')
        Get-LocalGroup | Format-List * | Out-File (Join-Path $Root 'local_groups.txt')
        foreach ($g in 'Administrators','Remote Desktop Users','Backup Operators','Users') {
            try { Get-LocalGroupMember -Group $g | Format-Table Name,PrincipalSource,ObjectClass -AutoSize | Out-File (Join-Path $Root ("group_{0}.txt" -f ($g -replace ' ','_'))) }
            catch {}
        }
        reg export 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run' (Join-Path $Root 'Run.reg') /y | Out-Null
        reg export 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' (Join-Path $Root 'Run_HKCU.reg') /y | Out-Null
        reg export 'HKCR\mscfile\shell\open\command' (Join-Path $Root 'msc_open_command.reg') /y | Out-Null
    }
}

function Find-KnownBadArtifacts {
    Invoke-Safely -Description 'Hunt for known-bad persistence artifacts' -Script {
        foreach ($task in $KnownBadTasks) {
            $taskInfo = schtasks /query /tn $task 2>$null
            if ($LASTEXITCODE -eq 0) { Add-Finding "Suspicious scheduled task present: $task" }
        }

        $runKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
        try {
            $rk = Get-ItemProperty -Path $runKey
            if ($rk.UpdaterService) { Add-Finding "Suspicious Run key UpdaterService => $($rk.UpdaterService)" }
        } catch {}

        foreach ($path in $KnownBadFiles) {
            if (Test-Path $path) { Add-Finding "Suspicious file present: $path" }
        }

        try {
            $filters = Get-WmiObject -Namespace 'root\subscription' -Class '__EventFilter' -ErrorAction SilentlyContinue
            $consumers = Get-WmiObject -Namespace 'root\subscription' -Class '__EventConsumer' -ErrorAction SilentlyContinue
            $bindings = Get-WmiObject -Namespace 'root\subscription' -Class '__FilterToConsumerBinding' -ErrorAction SilentlyContinue
            if ($filters)  { $filters  | Format-List * | Out-File (Join-Path $Root 'wmi_event_filters.txt') }
            if ($consumers){ $consumers| Format-List * | Out-File (Join-Path $Root 'wmi_event_consumers.txt') }
            if ($bindings) { $bindings | Format-List * | Out-File (Join-Path $Root 'wmi_filter_bindings.txt') }
            if (($filters | Measure-Object).Count -gt 0 -or ($consumers | Measure-Object).Count -gt 0) {
                Add-Finding 'WMI subscription objects found; review for persistence.'
            }
        } catch {}

        try {
            if (Test-Path $PROFILE) {
                Copy-Item $PROFILE (Join-Path $Root 'powershell_profile_backup.ps1') -Force
                Add-Finding "PowerShell profile exists: $PROFILE"
            }
        } catch {}

        try {
            $msc = Get-ItemProperty -Path 'Registry::HKEY_CLASSES_ROOT\mscfile\shell\open\command'
            if ($msc.'BackupCommand') { Add-Finding "MSC hijack backup value present: $($msc.BackupCommand)" }
            if ($msc.'(default)' -ne 'C:\Windows\System32\mmc.exe "%1" %*') {
                Add-Finding "MSC default open command deviates from baseline: $($msc.'(default)')"
            }
        } catch {}

        try {
            Get-ChildItem C:\inetpub\wwwroot -Force -Recurse -ErrorAction SilentlyContinue |
                Select-Object FullName,Length,LastWriteTime |
                Out-File (Join-Path $Root 'inetpub_listing.txt')
        } catch {}
    }
}

function Remove-KnownBadArtifacts {
    Invoke-Safely -Description 'Apply conservative remediations' -Script {
        foreach ($task in $KnownBadTasks) {
            $null = schtasks /query /tn $task 2>$null
            if ($LASTEXITCODE -eq 0 -and $PSCmdlet.ShouldProcess($task,'Unregister-ScheduledTask')) {
                Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
                Add-Action "Removed scheduled task: $task"
            }
        }

        try {
            $rk = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
            if ($rk.UpdaterService -and $PSCmdlet.ShouldProcess('HKLM Run\\UpdaterService','Remove-ItemProperty')) {
                Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'UpdaterService' -Force
                Add-Action 'Removed startup Run key: UpdaterService'
            }
        } catch {}

        foreach ($path in @('C:\inetpub\wwwroot\cmd.aspx','C:\Windows\Temp\taskhelper.ps1')) {
            if (Test-Path $path -and $PSCmdlet.ShouldProcess($path,'Remove-Item')) {
                Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
                Add-Action "Removed file: $path"
            }
        }

        try {
            $shareList = @('WinShare')
            foreach ($share in $shareList) {
                $exists = Get-SmbShare -Name $share -ErrorAction SilentlyContinue
                if ($exists -and $PSCmdlet.ShouldProcess($share,'Remove SMB share')) {
                    net share $share /delete | Out-Null
                    Add-Action "Removed SMB share: $share"
                }
            }
        } catch {}

        try {
            $mscPath = 'Registry::HKEY_CLASSES_ROOT\mscfile\shell\open\command'
            $current = Get-ItemProperty -Path $mscPath -ErrorAction SilentlyContinue
            if ($current -and $PSCmdlet.ShouldProcess($mscPath,'Restore mmc open command')) {
                Set-ItemProperty -Path $mscPath -Name '(Default)' -Value 'C:\Windows\System32\mmc.exe "%1" %*'
                Remove-ItemProperty -Path $mscPath -Name 'BackupCommand' -Force -ErrorAction SilentlyContinue
                Add-Action 'Restored default MSC open handler and removed BackupCommand if present.'
            }
        } catch {}

        if ($Aggressive) {
            try {
                $filters = Get-WmiObject -Namespace 'root\subscription' -Class '__EventFilter' -ErrorAction SilentlyContinue
                $consumers = Get-WmiObject -Namespace 'root\subscription' -Class '__EventConsumer' -ErrorAction SilentlyContinue
                $bindings = Get-WmiObject -Namespace 'root\subscription' -Class '__FilterToConsumerBinding' -ErrorAction SilentlyContinue
                foreach ($obj in @($bindings + $consumers + $filters)) {
                    if ($obj -and $PSCmdlet.ShouldProcess($obj.__PATH,'Remove-WmiObject')) {
                        $obj | Remove-WmiObject -ErrorAction SilentlyContinue
                    }
                }
                Add-Action 'Aggressive mode: removed WMI subscription objects.'
            } catch {}

            try {
                if (Test-Path $PROFILE -and $PSCmdlet.ShouldProcess($PROFILE,'Remove-Item')) {
                    Remove-Item $PROFILE -Force -ErrorAction SilentlyContinue
                    Add-Action 'Aggressive mode: removed PowerShell profile.'
                }
            } catch {}
        }
    }
}

function Review-UsersAndGroups {
    Invoke-Safely -Description 'Review users and privileged memberships' -Script {
        foreach ($user in $KnownBadUsers) {
            try {
                $u = Get-LocalUser -Name $user -ErrorAction SilentlyContinue
                if ($u) { Add-Finding "Potentially unauthorized local user present: $user" }
            } catch {}
        }

        foreach ($group in 'Administrators','Remote Desktop Users') {
            try {
                $members = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue
                foreach ($m in $members) {
                    if ($KnownBadUsers -contains $m.Name -or $KnownBadUsers -contains ($m.Name -split '\\')[-1]) {
                        Add-Finding "Potentially unauthorized privileged membership: $($m.Name) in $group"
                    }
                }
            } catch {}
        }
    }
}

function Harden-DefenderAndFirewall {
    Invoke-Safely -Description 'Harden Defender and firewall' -Script {
        try {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
            Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
            Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
            Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
            Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction SilentlyContinue
            Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue
            Add-Action 'Attempted to re-enable core Defender protections.'
        } catch {}

        try {
            Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection' -Name 'ForceDefenderPassiveMode' -Force -ErrorAction SilentlyContinue
            Add-Action 'Removed ForceDefenderPassiveMode policy if present.'
        } catch {}

        try {
            Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction SilentlyContinue
            Add-Action 'Enabled Windows Firewall profiles and set default inbound block.'
        } catch {}

        try {
            Set-Service -Name mpssvc -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name mpssvc -ErrorAction SilentlyContinue
            Add-Action 'Ensured Windows Defender Firewall service is running.'
        } catch {}
    }
}

function Apply-Basic-LocalPolicyFixes {
    Invoke-Safely -Description 'Apply basic local policy / registry hardening' -Script {
        # Blank passwords only at console
        reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f | Out-Null
        Add-Action 'Enabled blank-passwords-console-only restriction.'

        # Disable SMBv1
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Add-Action 'Attempted to disable SMBv1.'

        # Disable NetBIOS over TCP/IP where possible
        Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True' -ErrorAction SilentlyContinue |
            ForEach-Object { $_.SetTcpipNetbios(2) | Out-Null }
        Add-Action 'Attempted to disable NetBIOS over TCP/IP.'

        # Prevent PowerShell scripts from executing on double click via file association hijack abuse
        reg add 'HKCR\Microsoft.PowerShellScript.1\Shell' /ve /d 'Open' /f | Out-Null
        Add-Action 'Reset default PowerShell script shell verb to Open.'

        # RDP quick hardening
        reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' /v UserAuthentication /t REG_DWORD /d 1 /f | Out-Null
        reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fDenyTSConnections /t REG_DWORD /d 0 /f | Out-Null
        Add-Action 'Enabled NLA for RDP and kept RDP setting explicit.'

        # Screen lock on screensaver for current user context running the script
        reg add 'HKCU\Control Panel\Desktop' /v ScreenSaverIsSecure /t REG_SZ /d 1 /f | Out-Null
        Add-Action 'Enabled secure screensaver lock for current user profile.'
    }
}

function Inspect-WebAnd-IIS {
    Invoke-Safely -Description 'Inspect IIS/webroot' -Script {
        foreach ($p in 'C:\inetpub\wwwroot\Global.asax','C:\inetpub\wwwroot\web.config','C:\inetpub\wwwroot\pydio\web.config') {
            if (Test-Path $p) {
                Copy-Item $p (Join-Path $Root ((Split-Path $p -Leaf) + '.backup')) -Force
                Get-Content $p | Out-File (Join-Path $Root ((Split-Path $p -Leaf) + '.txt'))
                Add-Finding "Review web file: $p"
            }
        }
    }
}

function Inspect-ADS {
    Invoke-Safely -Description 'Check for Alternate Data Streams in common user folders' -Script {
        $targets = @('C:\Users','C:\inetpub\wwwroot')
        foreach ($base in $targets) {
            if (Test-Path $base) {
                Get-ChildItem $base -Recurse -Force -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        try {
                            $streams = Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue
                            foreach ($s in $streams) {
                                if ($s.Stream -ne '::$DATA') {
                                    Add-Finding "ADS found: $($_.FullName) [$($s.Stream)]"
                                }
                            }
                        } catch {}
                    }
            }
        }
    }
}

function Generate-NextSteps {
@'
MANUAL FOLLOW-UP CHECKLIST
==========================
1. AD / LDAP / ApacheDS / pGina
   - Review unauthorized users/groups.
   - Enforce LDAPS and certificate validation if the image uses pGina/LDAP.
   - Require Kerberos pre-auth where applicable.

2. Group Policy / Local Policy
   - Check secpol.msc and gpmc.msc for overrides.
   - Audit privilege use and system events.
   - Restrict delegation, workstation joins, and weak crypto.

3. Defender / Exploit Protection
   - Review exclusions, ASR rules, cloud protection, passive mode, exploit-protection per-program overrides.
   - Inspect twain32.exe, chrome.exe, and any unusual allowed binaries.

4. Services / Persistence
   - Review unquoted service paths.
   - Inspect hidden or oddly named services.
   - Validate startup tasks, WMI consumers, profile scripts, Run keys, and shares.

5. Web / IIS
   - Review webroot for shells, tampered Global.asax / web.config, and suspicious upload/config changes.

6. Forensics
   - Check Edge/Chrome history, MSI installer events, RDP cache artifacts, and ADS.
'@ | Out-File (Join-Path $Root 'NEXT_STEPS.txt') -Encoding utf8
}

Write-Log "Output directory: $Root"
Export-Basic-SystemState
Review-UsersAndGroups
Find-KnownBadArtifacts
Inspect-WebAnd-IIS
Inspect-ADS
Harden-DefenderAndFirewall
Apply-Basic-LocalPolicyFixes
Remove-KnownBadArtifacts
Generate-NextSteps

Write-Log 'Completed.'
Stop-Transcript | Out-Null
Write-Host "Done. Review artifacts in: $Root"
