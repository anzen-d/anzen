<#
.SYNOPSIS
    Anzen (安全) for Windows — security audit with the same report format as anzen.sh.

.DESCRIPTION
    Runs local hardening checks and prints FAIL / WARN / OK / INFO findings with a
    per-section and overall score. Reports use the same JSON layout, finding-ID
    scheme, accept-file format and history layout as the Linux edition, so one
    anzen dashboard covers Linux and Windows hosts.

    Run from an elevated PowerShell for complete results:
        powershell -ExecutionPolicy Bypass -File .\anzen.ps1 -Json

.PARAMETER Check
    Run only these modules (repeatable / comma-separated).
.PARAMETER Json
    Write a JSON report (reports\anzen_<timestamp>.json, or -Output).
.PARAMETER Output
    Path for the JSON report.
.PARAMETER History
    Save the run as <History>\<host>\<UTC timestamp>.json (the anzen history layout).
.PARAMETER AcceptFile
    Accepted risks: "ID YYYY-MM-DD reason" per line (default: anzen.accept next to this script).
.PARAMETER Quiet
    Hide INFO lines and section banners.
.PARAMETER Strict
    Exit 1 on WARN as well as FAIL.
.PARAMETER List
    List modules and exit.
#>
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
[CmdletBinding()]
param(
    [string[]]$Check = @(),
    [switch]$Json,
    [string]$Output = "",
    [string]$History = "",
    [string]$AcceptFile = "",
    [switch]$Quiet,
    [switch]$Strict,
    [switch]$List
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$AnzenVersion = '0.9.1'
$ScriptDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$FailPenalty  = 10
$WarnPenalty  = 3

# ── Findings, IDs and accepted risks ─────────────────────────────────────────

$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Section  = 'General'
$script:Accepted = @{}

# Same scheme as lib/output.sh _finding_id: section slug + first 8 hex of the MD5
# of the lower-cased message with volatile numbers (percent, sizes, durations,
# counts) normalised, so values that change between runs keep the ID
function Get-FindingId([string]$Section, [string]$Message) {
    $slug = ($Section.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
    $n = ($Message.ToLowerInvariant() -replace "[`t`r`n]", ' ')
    $n = [regex]::Replace($n, '[0-9]+(\.[0-9]+)? ?(%|[kmgtp]i?b?\b|days?\b|hours?\b|minutes?\b|seconds?\b|ms\b)', '#$2')
    $n = [regex]::Replace($n, '\(([0-9]+)( [a-z]+)*\)', '(#)')
    $n = [regex]::Replace($n, '\b[0-9]+ (found|files?|entries|items|packages?|updates?|failed|attempts?|services?|containers?|users?|accounts?|rules?|processes|connections?)\b', '# $1')
    $n = [regex]::Replace($n, '\s+', ' ')
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $hash = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($n))
    $hex = -join ($hash[0..3] | ForEach-Object { $_.ToString('x2') })
    return "$slug-$hex"
}

function Import-AcceptFile([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        $parts = $t -split '\s+', 3
        if ($parts.Count -lt 2 -or $parts[1] -notmatch '^\d{4}-\d{2}-\d{2}$') {
            Write-Warning "${Path}: '$($parts[0])' needs an expiry date (YYYY-MM-DD) — ignored"
            continue
        }
        $reason = 'no reason given'
        if ($parts.Count -ge 3) { $reason = $parts[2] }
        $script:Accepted[$parts[0]] = @{ Until = $parts[1]; Reason = $reason }
    }
}

function Add-Finding([string]$Level, [string]$Message, [string]$Remedy = '') {
    $msg = $Message -replace "[`t`r`n]", ' '
    $id = Get-FindingId $script:Section $msg
    $shown = $msg
    if ($Level -eq 'FAIL' -or $Level -eq 'WARN') {
        $acc = $script:Accepted[$id]
        if ($acc) {
            if ($acc.Until -ge (Get-Date -Format 'yyyy-MM-dd')) {
                $Level = 'INFO'
                $shown = "$msg [accepted until $($acc.Until): $($acc.Reason)]"
            } else {
                $shown = "$msg [acceptance expired $($acc.Until): $($acc.Reason)]"
            }
        }
    }
    $script:Findings.Add([pscustomobject]@{
        id = $id; level = $Level; section = $script:Section; message = $shown; remedy = $Remedy })

    if ($Level -eq 'INFO' -and $Quiet) { return }
    $color = @{ FAIL = 'Red'; WARN = 'Yellow'; OK = 'Green'; INFO = 'Cyan' }[$Level]
    $tag = @{ FAIL = '[FAIL]'; WARN = '[WARN]'; OK = '[ OK ]'; INFO = '[INFO]' }[$Level]
    Write-Host $tag -ForegroundColor $color -NoNewline
    Write-Host " $shown"
}

function Ok([string]$m)                     { Add-Finding 'OK'   $m }
function Info([string]$m)                   { Add-Finding 'INFO' $m }
function Warn([string]$m, [string]$r = '')  { Add-Finding 'WARN' $m $r }
function Fail([string]$m, [string]$r = '')  { Add-Finding 'FAIL' $m $r }

function Section([string]$Name) {
    $script:Section = $Name
    if ($Quiet) { return }
    Write-Host ''
    Write-Host ('━' * 42) -ForegroundColor Cyan
    Write-Host "  $Name" -ForegroundColor Cyan
    Write-Host ('━' * 42) -ForegroundColor Cyan
}

# Registry value or $null — most checks read policy from the registry
function Get-RegValue([string]$Path, [string]$Name) {
    try { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

# Lower-case host name; $env:COMPUTERNAME is Windows-only (tests also run on pwsh/Linux)
function Get-HostName { return ([Environment]::MachineName).ToLowerInvariant() }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ── Checks ───────────────────────────────────────────────────────────────────

function Invoke-SystemCheck {
    Section 'System Information'
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($os) {
        Info "OS: $($os.Caption) $($os.Version) (build $($os.BuildNumber))"
        $days = [int]((Get-Date) - $os.LastBootUpTime).TotalDays
        Info "Uptime: $days days"
        if ($days -gt 45) {
            Warn "System not rebooted for $days days — updates may be pending activation" 'Restart-Computer'
        }
    }
    $pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
               (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    if ($pending) { Warn 'Reboot required to finish installing updates' 'Restart-Computer' }
    else          { Ok 'No pending reboot' }

    foreach ($d in Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue) {
        if (-not $d.Size) { continue }
        $pct = [int](100 - ($d.FreeSpace * 100 / $d.Size))
        if ($pct -ge 90)     { Fail "Disk $($d.DeviceID) $pct% used" 'cleanmgr /sageset:1 ; cleanmgr /sagerun:1' }
        elseif ($pct -ge 75) { Warn "Disk $($d.DeviceID) $pct% used" }
        else                 { Ok   "Disk $($d.DeviceID) $pct% used" }
    }
}

function Invoke-UpdatesCheck {
    Section 'Windows Update'
    $last = Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } |
            Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($last) {
        $age = [int]((Get-Date) - $last.InstalledOn).TotalDays
        if ($age -gt 60)     { Fail "Last update installed $age days ago ($($last.HotFixID))" 'Start-Process ms-settings:windowsupdate' }
        elseif ($age -gt 35) { Warn "Last update installed $age days ago ($($last.HotFixID))" 'Start-Process ms-settings:windowsupdate' }
        else                 { Ok   "Last update installed $age days ago ($($last.HotFixID))" }
    } else {
        Warn 'No installed updates found (Get-HotFix)' 'Start-Process ms-settings:windowsupdate'
    }
    $wu = Get-Service wuauserv -ErrorAction SilentlyContinue
    if ($wu -and $wu.StartType -eq 'Disabled') {
        Fail 'Windows Update service is disabled' 'Set-Service wuauserv -StartupType Manual'
    }
}

function Invoke-DefenderCheck {
    Section 'Microsoft Defender'
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        Info 'Defender cmdlets not available — third-party antivirus? Verify it manually'
        return
    }
    try { $s = Get-MpComputerStatus -ErrorAction Stop } catch {
        Warn "Defender status unavailable: $($_.Exception.Message)"; return
    }
    if ($s.AntivirusEnabled)          { Ok 'Antivirus enabled' }
    else                              { Fail 'Defender antivirus disabled' 'Set-MpPreference -DisableRealtimeMonitoring $false' }
    if ($s.RealTimeProtectionEnabled) { Ok 'Real-time protection enabled' }
    else                              { Fail 'Real-time protection disabled' 'Set-MpPreference -DisableRealtimeMonitoring $false' }
    $sigAge = [int]$s.AntivirusSignatureAge
    if ($sigAge -gt 7) { Warn "Antivirus signatures $sigAge days old" 'Update-MpSignature' }
    else               { Ok   "Antivirus signatures $sigAge days old" }
    if ($s.PSObject.Properties['IsTamperProtected']) {
        if ($s.IsTamperProtected) { Ok 'Tamper protection on' }
        else                      { Warn 'Tamper protection off' 'Start-Process windowsdefender://threatsettings' }
    }
}

function Invoke-FirewallCheck {
    Section 'Windows Firewall'
    $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    if (-not $profiles) { Warn 'Firewall profiles unavailable (needs NetSecurity module)'; return }
    foreach ($p in $profiles) {
        if (-not $p.Enabled) {
            Fail "Firewall profile $($p.Name) disabled" "Set-NetFirewallProfile -Profile $($p.Name) -Enabled True"
        } elseif ($p.DefaultInboundAction -eq 'Allow') {
            Fail "Firewall profile $($p.Name) allows inbound by default" "Set-NetFirewallProfile -Profile $($p.Name) -DefaultInboundAction Block"
        } else {
            Ok "Firewall profile $($p.Name) enabled, inbound blocked by default"
        }
    }
}

function Invoke-AccountsCheck {
    Section 'Local Accounts'
    if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
        Info 'LocalAccounts module not available — skipping'; return
    }
    $guest = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }
    if ($guest -and $guest.Enabled) { Fail 'Guest account enabled' "Disable-LocalUser -SID $($guest.SID)" }
    else                            { Ok 'Guest account disabled' }
    $admin = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }
    if ($admin -and $admin.Enabled) { Warn "Built-in Administrator account '$($admin.Name)' enabled" "Disable-LocalUser -SID $($admin.SID)" }

    foreach ($u in Get-LocalUser | Where-Object { $_.Enabled }) {
        if (-not $u.PasswordRequired) { Fail "Account $($u.Name) does not require a password" "net user `"$($u.Name)`" /passwordreq:yes" }
    }
    try {
        $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
        Info "Local Administrators: $(($members | ForEach-Object { $_.Name }) -join ', ')"
        if ($members.Count -gt 3) { Warn "$($members.Count) members in local Administrators — review" 'lusrmgr.msc' }
    } catch { Info 'Could not list local Administrators' }

    $al = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon'
    if ($al -eq '1') {
        $pw = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultPassword'
        if ($pw) { Fail 'Auto-logon enabled with a plain-text password in the registry' "Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' DefaultPassword; Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' AutoAdminLogon 0" }
        else     { Warn 'Auto-logon enabled' "Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' AutoAdminLogon 0" }
    } else { Ok 'Auto-logon disabled' }
}

function Invoke-PasswordPolicyCheck {
    Section 'Password Policy'
    $out = net accounts 2>$null
    if (-not $out) { Info 'net accounts unavailable'; return }
    $minLen = ($out | Select-String 'Minimum password length' | ForEach-Object { ($_ -split ':')[-1].Trim() })
    $lock   = ($out | Select-String 'Lockout threshold'       | ForEach-Object { ($_ -split ':')[-1].Trim() })
    if ($minLen -match '^\d+$') {
        if ([int]$minLen -lt 8)       { Fail "Minimum password length $minLen" 'net accounts /minpwlen:12' }
        elseif ([int]$minLen -lt 12)  { Warn "Minimum password length $minLen (12+ recommended)" 'net accounts /minpwlen:12' }
        else                          { Ok   "Minimum password length $minLen" }
    }
    if ($lock -match 'Never' -or $lock -eq '0') { Warn 'No account lockout threshold' 'net accounts /lockoutthreshold:10' }
    elseif ($lock)                              { Ok   "Account lockout after $lock attempts" }
}

function Invoke-UacCheck {
    Section 'User Account Control'
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    if ((Get-RegValue $key 'EnableLUA') -eq 0) {
        Fail 'UAC disabled (EnableLUA=0)' "Set-ItemProperty '$key' EnableLUA 1   # reboot required"
    } else { Ok 'UAC enabled' }
    $c = Get-RegValue $key 'ConsentPromptBehaviorAdmin'
    if ($c -eq 0) { Fail 'UAC elevates administrators without prompting' "Set-ItemProperty '$key' ConsentPromptBehaviorAdmin 5" }
    if ((Get-RegValue $key 'PromptOnSecureDesktop') -eq 0) {
        Warn 'UAC prompt not on the secure desktop' "Set-ItemProperty '$key' PromptOnSecureDesktop 1"
    }
}

function Invoke-BitLockerCheck {
    Section 'BitLocker'
    if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        Info 'BitLocker cmdlets not available (Home edition or not elevated)'; return
    }
    try { $v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop } catch {
        Info "BitLocker status unavailable: $($_.Exception.Message)"; return
    }
    if ($v.ProtectionStatus -eq 'On') { Ok "System drive $($v.MountPoint) encrypted ($($v.EncryptionMethod))" }
    else { Warn "System drive $($v.MountPoint) not protected by BitLocker" "Enable-BitLocker -MountPoint $env:SystemDrive -TpmProtector" }
}

function Invoke-SmbCheck {
    Section 'SMB'
    $cfg = $null
    try { $cfg = Get-SmbServerConfiguration -ErrorAction Stop } catch { $cfg = $null }
    if (-not $cfg) { Info 'SMB server configuration unavailable'; return }
    if ($cfg.EnableSMB1Protocol) { Fail 'SMBv1 server enabled' 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force' }
    else                         { Ok 'SMBv1 server disabled' }
    if (-not $cfg.RequireSecuritySignature) {
        Warn 'SMB server does not require signing' 'Set-SmbServerConfiguration -RequireSecuritySignature $true -Force'
    } else { Ok 'SMB signing required' }
}

function Invoke-RdpCheck {
    Section 'Remote Desktop'
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    if ((Get-RegValue $ts 'fDenyTSConnections') -ne 0) { Ok 'Remote Desktop disabled'; return }
    Info 'Remote Desktop enabled'
    $rdp = "$ts\WinStations\RDP-Tcp"
    if ((Get-RegValue $rdp 'UserAuthentication') -ne 1) {
        Fail 'Remote Desktop without Network Level Authentication' "Set-ItemProperty '$rdp' UserAuthentication 1"
    } else { Ok 'Remote Desktop requires Network Level Authentication' }
    $port = Get-RegValue $rdp 'PortNumber'
    if ($port) { Info "Remote Desktop port $port" }
}

function Invoke-CredentialProtectionCheck {
    Section 'Credential Protection'
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    if ((Get-RegValue $lsa 'RunAsPPL') -ge 1) { Ok 'LSA protection (RunAsPPL) on' }
    else { Warn 'LSA protection (RunAsPPL) off' "Set-ItemProperty '$lsa' RunAsPPL 1   # reboot required" }
    $lm = Get-RegValue $lsa 'LmCompatibilityLevel'
    if ($null -ne $lm -and $lm -lt 3) { Fail "LmCompatibilityLevel $lm allows LM/NTLMv1" "Set-ItemProperty '$lsa' LmCompatibilityLevel 5" }
    if ((Get-RegValue $lsa 'NoLMHash') -eq 0) { Fail 'LM password hashes are stored' "Set-ItemProperty '$lsa' NoLMHash 1" }
    $wd = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
    if ($wd -eq 1) { Fail 'WDigest stores plain-text credentials in memory' "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential 0" }
    else           { Ok 'WDigest plain-text credential caching off' }
}

function Invoke-PowerShellCheck {
    Section 'PowerShell'
    $sbl = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
    if ($sbl -eq 1) { Ok 'Script block logging enabled' }
    else { Warn 'PowerShell script block logging disabled' "New-Item -Force 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' | Out-Null; Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' EnableScriptBlockLogging 1" }
    if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
        try {
            $v2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop
            if ($v2.State -eq 'Enabled') { Warn 'PowerShell 2.0 enabled (bypasses logging and AMSI)' 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root' }
            else                         { Ok 'PowerShell 2.0 disabled' }
        } catch { Info 'PowerShell 2.0 state unavailable (needs elevation)' }
    }
}

function Invoke-SecureBootCheck {
    Section 'Secure Boot'
    try {
        if (Confirm-SecureBootUEFI -ErrorAction Stop) { Ok 'Secure Boot enabled' }
        else { Warn 'Secure Boot disabled' '# enable Secure Boot in the UEFI firmware settings' }
    } catch { Info 'Secure Boot state unavailable (legacy BIOS, VM or not elevated)' }
}

function Invoke-NetworkCheck {
    Section 'Listening Ports'
    if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) { Info 'Get-NetTCPConnection unavailable'; return }
    $listen = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
              Where-Object { $_.LocalAddress -in @('0.0.0.0', '::') }
    $risky = @{ 21 = 'FTP'; 23 = 'Telnet'; 135 = 'RPC'; 139 = 'NetBIOS'; 445 = 'SMB'; 3389 = 'RDP'; 5985 = 'WinRM HTTP'; 5900 = 'VNC' }
    $ports = $listen | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object
    Info "Ports listening on all interfaces: $($ports -join ', ')"
    foreach ($p in $ports) {
        if ($risky.ContainsKey([int]$p)) {
            $proc = ($listen | Where-Object LocalPort -eq $p | Select-Object -First 1).OwningProcess
            $name = (Get-Process -Id $proc -ErrorAction SilentlyContinue).ProcessName
            Warn "Port $p ($($risky[[int]$p])) listening on all interfaces ($name) — restrict it in the firewall" "Get-NetFirewallRule -Enabled True -Direction Inbound | Get-NetFirewallPortFilter | Where-Object LocalPort -eq $p"
        }
    }
}

$Modules = [ordered]@{
    system      = 'Invoke-SystemCheck'
    updates     = 'Invoke-UpdatesCheck'
    defender    = 'Invoke-DefenderCheck'
    firewall    = 'Invoke-FirewallCheck'
    accounts    = 'Invoke-AccountsCheck'
    passwords   = 'Invoke-PasswordPolicyCheck'
    uac         = 'Invoke-UacCheck'
    bitlocker   = 'Invoke-BitLockerCheck'
    smb         = 'Invoke-SmbCheck'
    rdp         = 'Invoke-RdpCheck'
    credentials = 'Invoke-CredentialProtectionCheck'
    powershell  = 'Invoke-PowerShellCheck'
    secureboot  = 'Invoke-SecureBootCheck'
    network     = 'Invoke-NetworkCheck'
}

# ── Scores and report ────────────────────────────────────────────────────────

function Get-SectionScores {
    $seen = [ordered]@{}
    foreach ($f in $script:Findings) {
        if ($f.level -notin @('FAIL', 'WARN', 'OK')) { continue }
        if (-not $seen.Contains($f.section)) { $seen[$f.section] = @{ fail = 0; warn = 0; ok = 0 } }
        $seen[$f.section][$f.level.ToLowerInvariant()]++
    }
    foreach ($name in $seen.Keys) {
        $c = $seen[$name]
        $score = [Math]::Max(0, 100 - $c.fail * $FailPenalty - $c.warn * $WarnPenalty)
        [pscustomobject]@{ name = $name; fail = $c.fail; warn = $c.warn; ok = $c.ok; score = $score }
    }
}

# Same line layout as lib/report_json.sh — the history/dashboard parsers rely on it
function ConvertTo-JsonString([string]$s) {
    $s = $s -replace '\\', '\\' -replace '"', '\"' -replace "`t", '\t' -replace "`r", '' -replace "`n", ' '
    return $s
}

function Write-JsonReport([string]$Path, $Sections, [int]$Score) {
    $os = $null
    if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    }
    $osName = ''; $osVer = ''
    if ($os) { $osName = "$($os.Caption)"; $osVer = "$($os.Version)" }
    $count = { param($l) @($script:Findings | Where-Object level -eq $l).Count }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("{`n")
    [void]$sb.Append("  `"hostname`": `"$(ConvertTo-JsonString (Get-HostName))`",`n")
    [void]$sb.Append("  `"os`": `"$(ConvertTo-JsonString $osName)`",`n")
    [void]$sb.Append("  `"kernel`": `"$(ConvertTo-JsonString $osVer)`",`n")
    [void]$sb.Append("  `"arch`": `"$(ConvertTo-JsonString $env:PROCESSOR_ARCHITECTURE)`",`n")
    [void]$sb.Append("  `"public_ip`": `"`",`n")
    [void]$sb.Append("  `"audited_by`": `"$(ConvertTo-JsonString ([Environment]::UserName))`",`n")
    [void]$sb.Append("  `"version`": `"$AnzenVersion`",`n")
    [void]$sb.Append("  `"date`": `"$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))`",`n")
    [void]$sb.Append(("  `"summary`": {{`"fail`": {0}, `"warn`": {1}, `"ok`": {2}, `"info`": {3}, `"score`": {4}}},`n" -f
        (& $count 'FAIL'), (& $count 'WARN'), (& $count 'OK'), (& $count 'INFO'), $Score))
    [void]$sb.Append('  "sections": [')
    $first = $true
    foreach ($s in $Sections) {
        if (-not $first) { [void]$sb.Append(',') }
        $first = $false
        [void]$sb.Append(("`n    {{`"name`": `"{0}`", `"fail`": {1}, `"warn`": {2}, `"ok`": {3}, `"score`": {4}}}" -f
            (ConvertTo-JsonString $s.name), $s.fail, $s.warn, $s.ok, $s.score))
    }
    [void]$sb.Append("`n  ],`n  `"findings`": [`n")
    $lines = foreach ($f in $script:Findings) {
        '    {{"id": "{0}", "level": "{1}", "section": "{2}", "message": "{3}", "remedy": "{4}"}}' -f
            $f.id, $f.level, (ConvertTo-JsonString $f.section), (ConvertTo-JsonString $f.message), (ConvertTo-JsonString $f.remedy)
    }
    [void]$sb.Append(($lines -join ",`n"))
    [void]$sb.Append("`n  ]`n}`n")
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    # UTF-8 without BOM, LF line endings — same bytes as the Linux edition
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object System.Text.UTF8Encoding $false))
}

# ── Main ─────────────────────────────────────────────────────────────────────

# Dot-sourcing (". .\anzen.ps1", as the Pester tests do) loads the functions only
if ($MyInvocation.InvocationName -eq '.') { return }

if ($List) { $Modules.Keys | ForEach-Object { $_ }; exit 0 }

$selected = @($Check | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
foreach ($m in $selected) {
    if (-not $Modules.Contains($m)) {
        Write-Error "Unknown module: $m  (valid: $($Modules.Keys -join ' '))"; exit 1
    }
}
if (-not $AcceptFile) { $AcceptFile = Join-Path $ScriptDir 'anzen.accept' }
Import-AcceptFile $AcceptFile

if (-not $Quiet) {
    Write-Host ''
    Write-Host "   安全  Anzen $AnzenVersion — Windows Security Audit" -ForegroundColor Cyan
    Write-Host "   Host: $(Get-HostName)  |  $(Get-Date)" -ForegroundColor Cyan
}
if (-not (Test-Admin)) { Write-Warning 'Not running elevated — several checks will be incomplete.' }

foreach ($m in $Modules.Keys) {
    if ($selected.Count -and $m -notin $selected) { continue }
    try { & $Modules[$m] } catch {
        Section $m
        Warn "Module $m failed: $($_.Exception.Message)"
    }
}

$sections = @(Get-SectionScores)
$overall = 100
if ($sections.Count) { $overall = [int][Math]::Round(($sections | Measure-Object score -Average).Average) }
$nFail = @($script:Findings | Where-Object level -eq 'FAIL').Count
$nWarn = @($script:Findings | Where-Object level -eq 'WARN').Count
$nOk   = @($script:Findings | Where-Object level -eq 'OK').Count

Write-Host ''
Write-Host ('━' * 42)
Write-Host '  SUMMARY'
Write-Host ('━' * 42)
foreach ($s in $sections) {
    if ($s.fail -or $s.warn) { Write-Host ('  {0,-36} {1,3}%   FAIL {2,-3} WARN {3}' -f $s.name, $s.score, $s.fail, $s.warn) }
}
Write-Host ('━' * 42)
Write-Host "  FAIL: $nFail   WARN: $nWarn   OK: $nOk   Score: $overall%"
Write-Host ('━' * 42)

if ($Json -or $Output) {
    if (-not $Output) { $Output = Join-Path $ScriptDir ("reports\anzen_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss')) }
    Write-JsonReport $Output $sections $overall
    Write-Host "  JSON      : $Output" -ForegroundColor Cyan
}
if ($History) {
    $hostDir = Join-Path $History (Get-HostName)
    $file = Join-Path $hostDir ((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') + '.json')
    Write-JsonReport $file $sections $overall
    Write-Host "  History   : $file" -ForegroundColor Cyan
}

if ($nFail -gt 0) { exit 1 }
if ($Strict -and $nWarn -gt 0) { exit 1 }
exit 0
