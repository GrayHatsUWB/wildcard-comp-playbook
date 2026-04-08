[CmdletBinding()]
param(
    [string]$OutputDir = ".\CCDC_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [switch]$SkipFileScan,
    [switch]$SkipAclScan,
    [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

function Add-Finding {
    param(
        [string]$Category,
        [ValidateSet('INFO','LOW','MEDIUM','HIGH')][string]$Severity,
        [string]$Title,
        [string]$Details,
        [string]$Evidence = ''
    )
    $script:Findings.Add([pscustomobject]@{
        Category = $Category
        Severity = $Severity
        Title    = $Title
        Details  = $Details
        Evidence = $Evidence
    }) | Out-Null
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Ensure-OutputDir {
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
}

function Export-Results {
    $csvPath = Join-Path $OutputDir 'findings.csv'
    $txtPath = Join-Path $OutputDir 'summary.txt'
    $jsonPath = Join-Path $OutputDir 'findings.json'

    $script:Findings | Sort-Object Severity, Category, Title | Export-Csv -NoTypeInformation -Path $csvPath -Force
    if ($Json) {
        $script:Findings | ConvertTo-Json -Depth 4 | Out-File -Encoding UTF8 $jsonPath
    }

    $counts = $script:Findings | Group-Object Severity | Sort-Object Name
    $lines = @()
    $lines += "CCDC Wildcard Audit Summary"
    $lines += "Generated: $(Get-Date)"
    $lines += "Computer: $env:COMPUTERNAME"
    $lines += ""
    $lines += "Severity counts:"
    foreach ($c in $counts) { $lines += "  $($c.Name): $($c.Count)" }
    $lines += ""
    foreach ($f in ($script:Findings | Sort-Object Severity, Category, Title)) {
        $lines += "[$($f.Severity)] [$($f.Category)] $($f.Title)"
        $lines += "  $($f.Details)"
        if ($f.Evidence) { $lines += "  Evidence: $($f.Evidence)" }
        $lines += ""
    }
    $lines | Out-File -Encoding UTF8 $txtPath

    Write-Host "Results written to: $OutputDir"
    Write-Host "CSV:  $csvPath"
    Write-Host "TXT:  $txtPath"
    if ($Json) { Write-Host "JSON: $jsonPath" }
}

function Get-RegValue {
    param([string]$Path,[string]$Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

function Test-CommandExists {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Audit-LocalUsersAndGroups {
    Write-Host "[*] Auditing local users and groups..."
    $admins = @()
    try { $admins = Get-LocalGroupMember -Group 'Administrators' } catch {}
    foreach ($m in $admins) {
        if ($m.Name -notmatch '^(Administrator|Domain Admins|Enterprise Admins|BUILTIN\\Administrators|NT AUTHORITY\\SYSTEM)$') {
            Add-Finding 'Accounts' 'MEDIUM' 'Review local Administrators group membership' \
                'A non-default member is present in the local Administrators group. Validate it is authorized.' $m.Name
        }
    }

    try {
        Get-LocalUser | ForEach-Object {
            if ($_.Enabled -and $_.PasswordNeverExpires) {
                Add-Finding 'Accounts' 'LOW' 'Local account has PasswordNeverExpires' \
                    'A local account is configured to never expire. This is often acceptable only for tightly controlled service accounts.' $_.Name
            }
            if ($_.Enabled -and -not $_.PasswordRequired) {
                Add-Finding 'Accounts' 'HIGH' 'Local account without required password' \
                    'An enabled local account does not require a password.' $_.Name
            }
        }
    } catch {}
}

function Audit-PasswordPolicy {
    Write-Host "[*] Auditing password and lockout policy..."
    $out = net accounts
    if ($LASTEXITCODE -eq 0 -and $out) {
        $joined = $out -join "`n"
        if ($joined -match 'Minimum password length\s+(\d+)') {
            $minLen = [int]$Matches[1]
            if ($minLen -lt 10) {
                Add-Finding 'Policy' 'HIGH' 'Weak minimum password length' 'Minimum password length is below 10.' "Minimum length: $minLen"
            }
        }
        if ($joined -match 'Lockout threshold\s+(\d+)') {
            $threshold = [int]$Matches[1]
            if ($threshold -eq 0 -or $threshold -gt 10) {
                Add-Finding 'Policy' 'MEDIUM' 'Weak account lockout threshold' 'Lockout threshold is disabled or too permissive.' "Threshold: $threshold"
            }
        }
    }

    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $blankPw = Get-RegValue $lsaPath 'LimitBlankPasswordUse'
    if ($blankPw -ne 1) {
        Add-Finding 'Policy' 'HIGH' 'Blank-password console restriction not enabled' \
            'Accounts with blank passwords may be usable beyond local console logon.' "LimitBlankPasswordUse=$blankPw"
    }

    $cad = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'DisableCAD'
    if ($cad -eq 1) {
        Add-Finding 'Policy' 'LOW' 'CTRL+ALT+DEL not required at logon' 'Secure attention sequence is disabled.' 'DisableCAD=1'
    }

    $fips = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' 'Enabled'
    if ($fips -ne 1) {
        Add-Finding 'Policy' 'LOW' 'FIPS mode not enabled' 'Some walkthroughs scored FIPS-compliant crypto as enabled.' "Enabled=$fips"
    }
}

function Audit-DefenderFirewall {
    Write-Host "[*] Auditing Defender and firewall..."
    if (Test-CommandExists 'Get-MpComputerStatus') {
        $status = Get-MpComputerStatus
        if (-not $status.AntivirusEnabled) {
            Add-Finding 'Defender' 'HIGH' 'Microsoft Defender Antivirus disabled' 'Antivirus engine is not enabled.' ''
        }
        if (-not $status.RealTimeProtectionEnabled) {
            Add-Finding 'Defender' 'HIGH' 'Real-time protection disabled' 'Real-time protection is off.' ''
        }

        $pref = Get-MpPreference
        if ($pref.DisableRealtimeMonitoring) {
            Add-Finding 'Defender' 'HIGH' 'Realtime monitoring disabled by policy/preference' 'DisableRealtimeMonitoring is set.' ''
        }
        if ($pref.AttackSurfaceReductionOnlyExclusions.Count -gt 0) {
            Add-Finding 'Defender' 'MEDIUM' 'ASR exclusions present' 'Attack Surface Reduction exclusions exist. Review them.' ($pref.AttackSurfaceReductionOnlyExclusions -join '; ')
        }
        if ($pref.ExclusionPath.Count -gt 0 -or $pref.ExclusionProcess.Count -gt 0 -or $pref.ExclusionExtension.Count -gt 0) {
            Add-Finding 'Defender' 'MEDIUM' 'Defender exclusions present' 'Defender has path/process/extension exclusions. Review for abuse.' \
                ("Paths=$($pref.ExclusionPath -join '; ') | Procs=$($pref.ExclusionProcess -join '; ') | Ext=$($pref.ExclusionExtension -join '; ')")
        }
    } else {
        Add-Finding 'Defender' 'INFO' 'Defender cmdlets unavailable' 'Microsoft Defender module may be missing or third-party AV may be installed.' ''
    }

    try {
        $profiles = Get-NetFirewallProfile
        foreach ($p in $profiles) {
            if (-not $p.Enabled) {
                Add-Finding 'Firewall' 'HIGH' 'Firewall profile disabled' 'A Windows Defender Firewall profile is disabled.' $p.Name
            }
        }
    } catch {
        Add-Finding 'Firewall' 'INFO' 'Firewall profile query failed' 'Could not query firewall profiles.' $_.Exception.Message
    }
}

function Audit-ServicesAndFeatures {
    Write-Host "[*] Auditing services and Windows features..."
    $serviceChecks = @(
        @{ Name='WinDefend'; Expect='Running'; Severity='HIGH'; Title='Defender service not running' },
        @{ Name='MpsSvc'; Expect='Running'; Severity='HIGH'; Title='Firewall service not running' },
        @{ Name='EventLog'; Expect='Running'; Severity='HIGH'; Title='Event Log service not running' },
        @{ Name='Spooler'; Expect='Stopped'; Severity='LOW'; Title='Print Spooler enabled/running' },
        @{ Name='RemoteRegistry'; Expect='Stopped'; Severity='MEDIUM'; Title='Remote Registry enabled/running' },
        @{ Name='sshd'; Expect='Stopped'; Severity='MEDIUM'; Title='OpenSSH server enabled/running' },
        @{ Name='WinRM'; Expect='Stopped'; Severity='LOW'; Title='WinRM enabled/running' }
    )
    foreach ($check in $serviceChecks) {
        $svc = Get-Service -Name $check.Name
        if ($svc) {
            if ($check.Expect -eq 'Running' -and $svc.Status -ne 'Running') {
                Add-Finding 'Services' $check.Severity $check.Title 'Service state differs from expected secure baseline.' "$($svc.Name): $($svc.Status)"
            }
            if ($check.Expect -eq 'Stopped' -and $svc.Status -eq 'Running') {
                Add-Finding 'Services' $check.Severity $check.Title 'Service is running and may expand attack surface.' "$($svc.Name): $($svc.Status)"
            }
            if ($check.Name -in @('Spooler','RemoteRegistry','sshd','WinRM') -and $svc.StartType -eq 'Automatic') {
                Add-Finding 'Services' 'LOW' "Service starts automatically: $($svc.Name)" 'Auto-start service should be justified.' "$($svc.Name): StartType=$($svc.StartType)"
            }
        }
    }

    try {
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
        if ($smb1.State -eq 'Enabled') {
            Add-Finding 'Features' 'HIGH' 'SMBv1 enabled' 'SMB1Protocol is installed/enabled.' "State=$($smb1.State)"
        }
    } catch {}

    try {
        $ps2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
        if ($ps2.State -eq 'Enabled') {
            Add-Finding 'Features' 'MEDIUM' 'PowerShell 2.0 enabled' 'PowerShell v2 is enabled.' "State=$($ps2.State)"
        }
    } catch {}
}

function Audit-RemoteAccessAndNetwork {
    Write-Host "[*] Auditing RDP / SMB / WinRM / LDAP-related settings..."
    $ts = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    if ($ts -eq 0) {
        Add-Finding 'RemoteAccess' 'LOW' 'RDP enabled' 'RDP is enabled. Ensure this is required and properly hardened.' 'fDenyTSConnections=0'
    }
    $nla = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
    if ($ts -eq 0 -and $nla -ne 1) {
        Add-Finding 'RemoteAccess' 'HIGH' 'RDP Network Level Authentication not required' 'NLA is not enabled on RDP.' "UserAuthentication=$nla"
    }
    $secLayer = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'SecurityLayer'
    if ($ts -eq 0 -and $secLayer -lt 2) {
        Add-Finding 'RemoteAccess' 'MEDIUM' 'RDP not set to SSL/TLS security layer' 'SecurityLayer is not SSL/TLS.' "SecurityLayer=$secLayer"
    }

    $smbSigningServer = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature'
    if ($smbSigningServer -ne 1) {
        Add-Finding 'SMB' 'MEDIUM' 'SMB server signing not required' 'SMB server does not require message signing.' "RequireSecuritySignature=$smbSigningServer"
    }

    try {
        $smbServerConfig = Get-SmbServerConfiguration
        if (-not $smbServerConfig.EncryptData) {
            Add-Finding 'SMB' 'LOW' 'SMB encryption not enabled globally' 'Some images score SMB encryption/hardening checks.' ''
        }
    } catch {}

    $llmnr = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
    if ($llmnr -ne 0 -and $null -ne $llmnr) {
        Add-Finding 'Network' 'LOW' 'LLMNR enabled' 'LLMNR can aid name-resolution spoofing attacks.' "EnableMulticast=$llmnr"
    }

    $netbiosPaths = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue
    foreach ($p in $netbiosPaths) {
        $nb = Get-RegValue $p.PSPath 'NetbiosOptions'
        if ($nb -ne 2) {
            Add-Finding 'Network' 'LOW' 'NetBIOS over TCP/IP not disabled' 'NetBIOS can aid legacy enumeration/spoofing.' "$($p.PSChildName): NetbiosOptions=$nb"
        }
    }

    $ldapSign = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LDAPServerIntegrity'
    if ($null -ne $ldapSign -and $ldapSign -lt 2) {
        Add-Finding 'AD' 'HIGH' 'LDAP signing not required' 'Domain controller LDAP signing requirement is weak.' "LDAPServerIntegrity=$ldapSign"
    }
}

function Audit-ADSettings {
    Write-Host "[*] Auditing Active Directory settings (if domain controller / RSAT present)..."
    if (-not (Test-CommandExists 'Get-ADDomain')) {
        Add-Finding 'AD' 'INFO' 'AD cmdlets unavailable' 'Skipping deep AD checks because the ActiveDirectory module is unavailable.' ''
        return
    }

    try {
        $domain = Get-ADDomain
        $maq = $domain.'ms-DS-MachineAccountQuota'
        if ($maq -gt 0) {
            Add-Finding 'AD' 'MEDIUM' 'MachineAccountQuota is above zero' 'Unprivileged users may be able to add computers to the domain.' "ms-DS-MachineAccountQuota=$maq"
        }
    } catch {}

    try {
        $asrepUsers = Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' -Properties userAccountControl
        foreach ($u in $asrepUsers) {
            Add-Finding 'AD' 'HIGH' 'Kerberos pre-auth disabled for account' 'Account is vulnerable to AS-REP roasting unless explicitly justified.' $u.SamAccountName
        }
    } catch {}

    try {
        $revUsers = Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))'
        foreach ($u in $revUsers) {
            Add-Finding 'AD' 'HIGH' 'Password stored with reversible encryption' 'User account stores password using reversible encryption.' $u.SamAccountName
        }
    } catch {}

    try {
        $trustedForDelegation = Get-ADObject -LDAPFilter '(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216))' -Properties userAccountControl,samAccountName,name
        foreach ($o in $trustedForDelegation) {
            $name = if ($o.samAccountName) { $o.samAccountName } else { $o.Name }
            Add-Finding 'AD' 'MEDIUM' 'Object trusted for delegation' 'Delegation should be reviewed carefully.' $name
        }
    } catch {}

    try {
        $dnsAdmins = Get-ADGroupMember 'DnsAdmins'
        foreach ($m in $dnsAdmins) {
            Add-Finding 'AD' 'MEDIUM' 'Review DnsAdmins membership' 'DnsAdmins can be abused for escalation via ServerLevelPluginDll.' $m.SamAccountName
        }
    } catch {}
}

function Audit-Persistence {
    Write-Host "[*] Auditing common persistence mechanisms..."
    try {
        $tasks = Get-ScheduledTask | Where-Object {
            $_.TaskPath -notlike '\Microsoft*' -or $_.Actions.Execute -match '(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|curl|wget|nc|netcat)'
        }
        foreach ($t in $tasks) {
            $acts = ($t.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' || '
            Add-Finding 'Persistence' 'MEDIUM' 'Review scheduled task' 'Task path or action looks suspicious or non-standard.' "$($t.TaskPath)$($t.TaskName) -> $acts"
        }
    } catch {}

    $runLocations = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($loc in $runLocations) {
        try {
            $item = Get-ItemProperty -Path $loc
            foreach ($p in $item.PSObject.Properties) {
                if ($p.Name -notmatch '^PS') {
                    Add-Finding 'Persistence' 'MEDIUM' 'Review Run-key persistence' 'Startup persistence entry present.' "$loc :: $($p.Name) = $($p.Value)"
                }
            }
        } catch {}
    }

    try {
        $cons = Get-WmiObject -Namespace root\subscription -Class __EventConsumer
        foreach ($c in $cons) {
            Add-Finding 'Persistence' 'HIGH' 'WMI event consumer present' 'WMI permanent event subscriptions are a common persistence mechanism.' "$($c.Name) [$($c.__CLASS)]"
        }
        $filters = Get-WmiObject -Namespace root\subscription -Class __EventFilter
        foreach ($f in $filters) {
            Add-Finding 'Persistence' 'HIGH' 'WMI event filter present' 'Review WMI event subscriptions.' "$($f.Name) :: $($f.Query)"
        }
    } catch {}

    try {
        Get-CimInstance Win32_Service | ForEach-Object {
            if ($_.PathName -and $_.PathName -match '^[A-Za-z]:\\Program Files .*\.exe' -and $_.PathName -notmatch '^"') {
                Add-Finding 'Persistence' 'MEDIUM' 'Service has unquoted executable path' 'Unquoted service paths can enable privilege escalation.' "$($_.Name) -> $($_.PathName)"
            }
            if ($_.StartMode -eq 'Auto' -and $_.PathName -match '(temp|appdata|programdata|users\\public|downloads)') {
                Add-Finding 'Persistence' 'HIGH' 'Auto-start service runs from suspicious path' 'Auto-start service binary is located in a user-writable or unusual directory.' "$($_.Name) -> $($_.PathName)"
            }
        }
    } catch {}

    $pluginDll = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters' 'ServerLevelPluginDll'
    if ($pluginDll) {
        Add-Finding 'Persistence' 'HIGH' 'DNS ServerLevelPluginDll configured' 'DnsAdmins/ServerLevelPluginDll abuse is a known privilege-escalation and persistence path.' $pluginDll
    }
}

function Audit-WebAndAppSettings {
    Write-Host "[*] Auditing web and application settings..."
    $inetpub = 'C:\inetpub\wwwroot'
    if (Test-Path $inetpub) {
        $webshellPatterns = '*.aspx','*.php','*.jsp','*.ashx'
        foreach ($pattern in $webshellPatterns) {
            Get-ChildItem -Path $inetpub -Recurse -Filter $pattern -File | ForEach-Object {
                if ($_.Length -lt 500KB) {
                    Add-Finding 'Web' 'MEDIUM' 'Review web-executable file in webroot' 'A script/executable web file exists under inetpub and should be validated.' $_.FullName
                }
            }
        }
        $webConfig = Join-Path $inetpub 'web.config'
        if (Test-Path $webConfig) {
            Add-Finding 'Web' 'INFO' 'Review web.config permissions' 'Several walkthroughs scored dangerous ACLs on web.config.' $webConfig
        }
    }

    $phpIni = 'C:\PHP\php.ini'
    if (Test-Path $phpIni) {
        $content = Get-Content $phpIni
        if ($content -match '^\s*display_errors\s*=\s*On') {
            Add-Finding 'AppSec' 'LOW' 'PHP display_errors enabled' 'Detailed remote error output can leak information.' $phpIni
        }
        if ($content -notmatch '^\s*disable_functions\s*=.*\bexec\b') {
            Add-Finding 'AppSec' 'LOW' 'PHP exec() not disabled' 'Some walkthroughs explicitly scored disabling exec in php.ini.' $phpIni
        }
    }

    $mailEnable = 'C:\Program Files (x86)\Mail Enable\Bin\MailAdmin.exe'
    if (Test-Path $mailEnable) {
        Add-Finding 'Mail' 'INFO' 'MailEnable detected' 'Review SMTP/IMAP auth settings, catch-all domains, config ACLs, and AUTH.TAB exposure.' $mailEnable
    }
}

function Audit-ACLs {
    if ($SkipAclScan) { return }
    Write-Host "[*] Auditing selected ACLs..."
    $targets = @(
        'C:\Windows\NTDS\ntds.dit',
        'C:\Windows\SYSVOL',
        'C:\inetpub\wwwroot\web.config',
        'C:\Program Files (x86)\Mail Enable\Config',
        'C:\inetpub\wwwroot\pydio'
    )
    foreach ($t in $targets) {
        if (Test-Path $t) {
            try {
                $acl = Get-Acl $t
                foreach ($ace in $acl.Access) {
                    if ($ace.IdentityReference -match 'Everyone|Users|Authenticated Users|Domain Users' -and $ace.FileSystemRights.ToString() -match 'FullControl|Modify|Write') {
                        Add-Finding 'ACL' 'HIGH' 'Overly permissive ACL on sensitive path' 'Broad principal has dangerous rights on a sensitive location.' "$t :: $($ace.IdentityReference) -> $($ace.FileSystemRights)"
                    }
                }
            } catch {}
        }
    }
}

function Audit-FilesAndTools {
    if ($SkipFileScan) { return }
    Write-Host "[*] Scanning for prohibited tools and obvious artifacts..."
    $roots = @('C:\Users','C:\Program Files','C:\Program Files (x86)','C:\Temp','C:\Windows\Temp','C:\inetpub\wwwroot','C:\')
    $toolNames = @(
        'teamviewer','wireshark','nmap','mimikatz','nc.exe','netcat','rubeus','powerview','powerup','sharphound',
        'bloodhound','metasploit','goosedesktop','steam','anydesk'
    )
    foreach ($root in $roots | Select-Object -Unique) {
        if (-not (Test-Path $root)) { continue }
        foreach ($name in $toolNames) {
            Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -match [regex]::Escape($name)
            } | Select-Object -First 10 | ForEach-Object {
                Add-Finding 'Files' 'MEDIUM' 'Suspicious/prohibited tool or artifact detected' 'Review whether this file is authorized.' $_.FullName
            }
        }
    }

    Get-ChildItem 'C:\Users' -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
        $_.Extension -in '.txt','.csv','.config','.xml','.ini','.ps1','.bat','.cmd','.vbs' -and $_.Length -lt 2MB
    } | Select-Object -First 400 | ForEach-Object {
        try {
            $sample = Get-Content $_.FullName -TotalCount 20 -ErrorAction Stop
            if ($sample -match 'password\s*=|passwd\s*=|pwd\s*=|apikey|api_key|secret|BEGIN RSA PRIVATE KEY|BEGIN OPENSSH PRIVATE KEY|credit card') {
                Add-Finding 'Files' 'HIGH' 'Potential plaintext secret found' 'A text-like file appears to contain credentials or secrets.' $_.FullName
            }
        } catch {}
    }

    Get-ChildItem 'C:\Users' -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
        $_.Extension -in '.mp3','.mp4','.wav','.ogg','.avi','.mkv','.mov','.zip','.7z','.rar','.tar','.gz'
    } | Select-Object -First 200 | ForEach-Object {
        Add-Finding 'Files' 'LOW' 'Review media/archive file' 'Many competition images score unauthorized media and archive files.' $_.FullName
    }
}

function Audit-ADS {
    Write-Host "[*] Looking for Alternate Data Streams on common user files..."
    Get-ChildItem 'C:\Users' -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 300 | ForEach-Object {
        try {
            $streams = Get-Item -Path $_.FullName -Stream *
            foreach ($s in $streams) {
                if ($s.Stream -ne ':$DATA') {
                    Add-Finding 'Files' 'MEDIUM' 'Alternate Data Stream detected' 'ADS can be abused to hide content.' "$($_.FullName) :: $($s.Stream)"
                }
            }
        } catch {}
    }
}

$script:Findings = New-Object System.Collections.Generic.List[object]
Ensure-OutputDir

if (-not (Test-IsAdmin)) {
    Add-Finding 'Execution' 'INFO' 'Script not run as Administrator' 'Some checks will be incomplete without elevation.' ''
}

Audit-LocalUsersAndGroups
Audit-PasswordPolicy
Audit-DefenderFirewall
Audit-ServicesAndFeatures
Audit-RemoteAccessAndNetwork
Audit-ADSettings
Audit-Persistence
Audit-WebAndAppSettings
Audit-ACLs
Audit-FilesAndTools
Audit-ADS
Export-Results
