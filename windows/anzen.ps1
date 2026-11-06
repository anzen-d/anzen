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
.PARAMETER Html
    Write an HTML report (reports\anzen_<timestamp>.html, or -Output).
.PARAMETER Txt
    Write a plain-text report.
.PARAMETER Sarif
    Write a SARIF 2.1.0 report (GitHub/GitLab code scanning).
.PARAMETER Csv
    Write the findings as CSV, with NIST SP 800-53 / CIS Controls references.
.PARAMETER Output
    Report path. With several formats the extension is swapped per format
    (out.json -> out.html, out.txt, out.sarif.json). Alone it means -Json.
.PARAMETER History
    Save the run as <History>\<host>\<UTC timestamp>.json (the anzen history layout).
.PARAMETER AcceptFile
    Accepted risks: "ID YYYY-MM-DD reason" per line (default: anzen.accept next to this script).
.PARAMETER Quiet
    Hide INFO lines and section banners.
.PARAMETER Strict
    Exit 1 on WARN as well as FAIL.
.PARAMETER Remote
    Audit these Windows hosts over PowerShell remoting (WinRM) instead of this
    one: host names, comma-separated. Reports and -History stay on this machine.
.PARAMETER Credential
    Credential for -Remote (default: the current user, e.g. Kerberos in a domain).
.PARAMETER NtfyUrl
    ntfy topic URL for a notification after the audit (default: $env:NOTIFY_NTFY_URL).
    The access token is read only from $env:NOTIFY_NTFY_TOKEN.
.PARAMETER NotifyOn
    always (default), fail (only with FAIL findings) or regression (only with
    FAIL findings that were not in the previous -History run). Default: $env:NOTIFY_ON.
.PARAMETER HeartbeatUrl
    URL fetched after every full run, for a dead-man switch (default: $env:HEARTBEAT_URL).
.PARAMETER Offline
    No network connections (no notification, no heartbeat).
.PARAMETER List
    List modules and exit.
#>
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
[CmdletBinding()]
# Several parameters are read by functions in script scope, which the analyzer does not follow
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
param(
    [string[]]$Check = @(),
    [switch]$Json,
    [switch]$Html,
    [switch]$Txt,
    [switch]$Sarif,
    [switch]$Csv,
    [string]$Output = "",
    [string]$History = "",
    [string]$AcceptFile = "",
    [switch]$Quiet,
    [switch]$Strict,
    [string[]]$Remote = @(),
    [pscredential]$Credential = $null,
    [string]$NtfyUrl = $env:NOTIFY_NTFY_URL,
    [string]$NotifyOn = $(if ($env:NOTIFY_ON) { $env:NOTIFY_ON } else { 'always' }),
    [string]$HeartbeatUrl = $env:HEARTBEAT_URL,
    [switch]$Offline,
    [switch]$List
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$AnzenVersion = '0.25.0'
$ScriptPath   = $MyInvocation.MyCommand.Path
$ScriptDir    = Split-Path -Parent $ScriptPath
$FailPenalty  = 10
$WarnPenalty  = 3

# ── Findings, IDs and accepted risks ─────────────────────────────────────────

$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Section  = 'General'
$script:Accepted = @{}
$script:OsInfo   = $null
$script:Controls = $null

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

# Single-quoted PowerShell literal for a system value put into a remedy
# (PowerShell also treats curly single quotes as quotes, so double those too)
function ConvertTo-PsLiteral([string]$s) {
    return "'" + ($s -replace "(['\u2018\u2019\u201A\u201B])", '$1$1') + "'"
}

# Executable from a service or task command line: quoted part, or up to the
# first .exe/.com/.bat/.cmd, or the first word
function Get-ExePath([string]$CommandLine) {
    $c = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim()) -replace '^\\\?\?\\', ''
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { return $c.Substring(1, $end - 1) }
        return $null
    }
    $m = [regex]::Match($c, '^(.+?\.(exe|com|bat|cmd))(\s|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
}

# Everyone, Authenticated Users, Users, INTERACTIVE
$script:LowPrivSids = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4')

# True when a non-admin group may change the file (or create files in the folder)
function Test-UserWritable([string]$Path, [switch]$Folder) {
    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop } catch { return $false }
    $fsr = [Security.AccessControl.FileSystemRights]
    $mask = if ($Folder) { [int64]$fsr::CreateFiles } else {
        [int64]($fsr::WriteData -bor $fsr::AppendData -bor $fsr::ChangePermissions -bor $fsr::TakeOwnership) }
    foreach ($r in $acl.Access) {
        if ("$($r.AccessControlType)" -ne 'Allow') { continue }
        if ($r.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        try { $sid = $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { continue }
        if ($sid -notin $script:LowPrivSids) { continue }
        $rights = [int64]$r.FileSystemRights
        # 0x50000000 = GENERIC_ALL | GENERIC_WRITE
        if (($rights -band $mask) -or ($rights -band 0x50000000)) { return $true }
    }
    return $false
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

# Asset inventory (INFO only, no score)
function Invoke-InventoryCheck {
    Section 'Inventory'
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($cs) {
        Info "Hardware: $($cs.Manufacturer) $($cs.Model)"
        Info ("Memory: {0:N1} GiB" -f ($cs.TotalPhysicalMemory / 1GB))
        if ($cs.PartOfDomain) { Info "Domain: $($cs.Domain)" } else { Info "Workgroup: $($cs.Workgroup)" }
    }
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    if ($bios -and $bios.SerialNumber) { Info "Serial number: $($bios.SerialNumber)" }
    $cpu = @(Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue) | Select-Object -First 1
    if ($cpu) { Info "CPU: $("$($cpu.Name)".Trim()) ($($cpu.NumberOfLogicalProcessors) threads)" }
    $nt = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $dv = Get-RegValue $nt 'DisplayVersion'
    if ($dv) { Info "Windows version: $dv (build $(Get-RegValue $nt 'CurrentBuild').$(Get-RegValue $nt 'UBR'))" }
    $apps = @(foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                             'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName }
    })
    if ($apps.Count) { Info "Installed programs: $(@($apps.DisplayName | Select-Object -Unique).Count)" }
    if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
        try {
            $t = Get-Tpm -ErrorAction Stop
            Info "TPM: present=$($t.TpmPresent) ready=$($t.TpmReady)"
        } catch { Info 'TPM state unavailable (needs elevation)' }
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
    # WSUS over plain HTTP: anyone on the path can inject an "update" that runs as SYSTEM
    $wsus = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $server = "$(Get-RegValue $wsus 'WUServer')"
    if ($server -and (Get-RegValue "$wsus\AU" 'UseWUServer') -eq 1) {
        if ($server -match '^http://') {
            Fail "Updates come from WSUS over plain HTTP ($server)" '# GPO: Specify intranet Microsoft update service location = https://<server>:8531 (WSUS with TLS)'
        } else { Ok "Updates come from WSUS over HTTPS ($server)" }
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
    # Cloud lookups and PUA blocking: only meaningful while Defender is the active antivirus
    $mode = $s | Select-Object -ExpandProperty AMRunningMode -ErrorAction SilentlyContinue
    if ($mode -and $mode -ne 'Normal') { return }
    $p = Get-MpPreference -ErrorAction SilentlyContinue
    if (-not $p) { return }
    $maps = $p | Select-Object -ExpandProperty MAPSReporting -ErrorAction SilentlyContinue
    if ($null -ne $maps) {
        if ([int]$maps -eq 0) { Warn 'Cloud-delivered protection off (MAPS reporting disabled)' 'Set-MpPreference -MAPSReporting Advanced' }
        else                  { Ok 'Cloud-delivered protection on' }
    }
    $pua = $p | Select-Object -ExpandProperty PUAProtection -ErrorAction SilentlyContinue
    if ($null -ne $pua) {
        if ([int]$pua -eq 1) { Ok 'Potentially unwanted app blocking on' }
        else                 { Warn 'Potentially unwanted app blocking off' 'Set-MpPreference -PUAProtection Enabled' }
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

    # Enabled inbound allow rules with no port, program or remote-address
    # limit open the whole host, whatever the default action says
    $rules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue)
    if (-not $rules) { return }
    $ports = @{}; foreach ($f in @(Get-NetFirewallPortFilter -All -ErrorAction SilentlyContinue)) { $ports[$f.InstanceID] = $f }
    $addrs = @{}; foreach ($f in @(Get-NetFirewallAddressFilter -All -ErrorAction SilentlyContinue)) { $addrs[$f.InstanceID] = $f }
    $apps = @{};  foreach ($f in @(Get-NetFirewallApplicationFilter -All -ErrorAction SilentlyContinue)) { $apps[$f.InstanceID] = $f }
    $any = 0
    foreach ($r in $rules) {
        $pf = $ports[$r.Name]; $af = $addrs[$r.Name]; $ap = $apps[$r.Name]
        if (-not ($pf -and $af -and $ap)) { continue }
        if ("$($pf.Protocol)" -eq 'Any' -and "$($af.RemoteAddress)" -eq 'Any' -and "$($ap.Program)" -eq 'Any') {
            $any++
            Warn "Firewall rule '$($r.DisplayName)' allows any inbound traffic" "Disable-NetFirewallRule -Name $(ConvertTo-PsLiteral $r.Name)"
        }
    }
    if (-not $any) { Ok "No inbound rule allows any traffic ($($rules.Count) allow rules)" }
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
    # Windows Hello PIN policy (when set) and the old convenience PIN, which
    # stores the domain password instead of using a Hello key
    $hello = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity'
    $pin = Get-RegValue $hello 'MinimumPINLength'
    if ($null -ne $pin) {
        if ([int]$pin -lt 6) { Warn "Windows Hello PIN minimum length ($pin) below 6" "Set-ItemProperty '$hello' MinimumPINLength 6" }
        else                 { Ok "Windows Hello PIN minimum length ($pin)" }
    }
    $sys = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
    if ((Get-RegValue $sys 'AllowDomainPINLogon') -eq 1) {
        Warn 'Convenience PIN sign-in on for domain users (stores the password; use Windows Hello for Business)' "Set-ItemProperty '$sys' AllowDomainPINLogon 0"
    }

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
    try {
        $cc = Get-SmbClientConfiguration -ErrorAction Stop
        if ($cc.RequireSecuritySignature) { Ok 'SMB client requires signing' }
        else { Warn 'SMB client does not require signing' 'Set-SmbClientConfiguration -RequireSecuritySignature $true -Force' }
    } catch { Info 'SMB client configuration unavailable' }
    $cfg = $null
    try { $cfg = Get-SmbServerConfiguration -ErrorAction Stop } catch { $cfg = $null }
    if (-not $cfg) { Info 'SMB server configuration unavailable'; return }
    if ($cfg.EnableSMB1Protocol) { Fail 'SMBv1 server enabled' 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force' }
    else                         { Ok 'SMBv1 server disabled' }
    if (-not $cfg.RequireSecuritySignature) {
        Warn 'SMB server does not require signing' 'Set-SmbServerConfiguration -RequireSecuritySignature $true -Force'
    } else { Ok 'SMB signing required' }

    # Anonymous (null session) access: share and account enumeration, named pipes
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $srv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
    if ((Get-RegValue $srv 'RestrictNullSessAccess') -eq 0) {
        Fail 'SMB server allows null-session access to shares and named pipes' "Set-ItemProperty '$srv' RestrictNullSessAccess 1"
    }
    if ((Get-RegValue $lsa 'RestrictAnonymousSAM') -eq 0) {
        Fail 'Anonymous users can enumerate local accounts (RestrictAnonymousSAM=0)' "Set-ItemProperty '$lsa' RestrictAnonymousSAM 1"
    }
    if ((Get-RegValue $lsa 'EveryoneIncludesAnonymous') -eq 1) {
        Fail 'Anonymous users get Everyone permissions (EveryoneIncludesAnonymous=1)' "Set-ItemProperty '$lsa' EveryoneIncludesAnonymous 0"
    }
    if ((Get-RegValue $lsa 'RestrictAnonymous') -ge 1) { Ok 'Anonymous enumeration of shares restricted' }
    else { Warn 'Anonymous users can enumerate shares (RestrictAnonymous=0)' "Set-ItemProperty '$lsa' RestrictAnonymous 1" }
    $nss = @(Get-RegValue $srv 'NullSessionShares' | Where-Object { $_ })
    if ($nss.Count) { Warn "Shares open to null sessions: $($nss -join ', ')" "Set-ItemProperty '$srv' NullSessionShares ([string[]]@())" }
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

    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    if (-not $dg) { Info 'Credential Guard state unavailable'; return }
    $caption = "$((Get-OsInfo).Name)"
    if (@($dg.SecurityServicesRunning) -contains 1) { Ok 'Credential Guard running' }
    elseif (@($dg.AvailableSecurityProperties) -notcontains 1) { Info 'Credential Guard unavailable: no virtualization-based security support (hardware or VM)' }
    elseif ($caption -notmatch 'Enterprise|Education|Server') { Info 'Credential Guard needs the Enterprise, Education or Server edition' }
    else { Warn 'Credential Guard not running' '# GPO: Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security (Credential Guard: Enabled with UEFI lock)' }
}

# App Control for Business (WDAC) and AppLocker: allow-listing is the strongest
# answer to malware a user downloads and runs
function Invoke-AppControlCheck {
    Section 'Application Control'
    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    $wdac = $dg | Select-Object -First 1 -ExpandProperty UsermodeCodeIntegrityPolicyEnforcementStatus -ErrorAction SilentlyContinue
    $enforced = @(); $audit = @()
    if (Get-Command Get-AppLockerPolicy -ErrorAction SilentlyContinue) {
        $pol = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
        foreach ($c in @($pol | Select-Object -ExpandProperty RuleCollections -ErrorAction SilentlyContinue)) {
            if (-not $c -or -not @($c).Count) { continue }
            $type = "$($c | Select-Object -ExpandProperty RuleCollectionType -ErrorAction SilentlyContinue)"
            switch ("$($c | Select-Object -ExpandProperty EnforcementMode -ErrorAction SilentlyContinue)") {
                'Enabled'   { $enforced += $type }
                'AuditOnly' { $audit += $type }
            }
        }
    }
    if ($wdac -eq 2) { Ok 'App Control for Business (WDAC) enforces user-mode code integrity' }
    if ($enforced) {
        $svc = Get-Service AppIDSvc -ErrorAction SilentlyContinue
        if ($svc -and "$($svc.Status)" -eq 'Running') { Ok "AppLocker enforced for: $($enforced -join ', ')" }
        else { Warn 'AppLocker rules are enforced but the Application Identity service is not running' 'sc.exe config AppIDSvc start= auto; Start-Service AppIDSvc' }
    }
    if ($wdac -eq 2 -or $enforced) { return }
    if ($wdac -eq 1 -or $audit) { Info 'Application control (WDAC or AppLocker) in audit mode only' }
    else { Info 'No application control policy (AppLocker or WDAC): any program a user can write can run' }
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

# Distrusted CA certificates (same list as the Linux truststore module):
# FAIL/WARN when one is trusted in a machine/user store and not blocked by the
# Disallowed store, which Microsoft updates automatically
function Get-DistrustedList([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^\s*(#|$)') { continue }
        $f = $line -split "`t"
        if ($f.Count -ge 4) {
            [pscustomobject]@{ Sha256 = $f[0].ToUpperInvariant(); Severity = $f[1]; Incident = $f[2]; Name = $f[3]; Ref = $(if ($f.Count -ge 5) { $f[4] } else { '' }) }
        }
    }
}

function Get-CertSha256($Cert) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    return (-join ($sha.ComputeHash($Cert.RawData) | ForEach-Object { $_.ToString('X2') }))
}

function Invoke-TrustStoreCheck {
    Section 'Trust Stores'
    $listPath = Join-Path $ScriptDir '..\lib\data\distrusted-certs.tsv'
    $list = @(Get-DistrustedList $listPath)
    if (-not $list.Count) { Info "Distrusted certificate list not found ($listPath)"; return }
    if (-not (Test-Path 'Cert:\LocalMachine')) { Info 'Certificate stores not available on this platform'; return }
    Info "Distrusted certificate list: $($list.Count) entries"

    $trusted = @{}; $thumb = @{}; $blocked = @{}; $checked = 0
    foreach ($store in 'LocalMachine\Root', 'LocalMachine\AuthRoot', 'LocalMachine\CA', 'LocalMachine\TrustedPublisher',
                       'CurrentUser\Root', 'CurrentUser\CA') {
        foreach ($c in @(Get-ChildItem "Cert:\$store" -ErrorAction SilentlyContinue)) {
            $checked++
            $h = Get-CertSha256 $c
            if (-not $trusted.ContainsKey($h)) { $trusted[$h] = New-Object System.Collections.Generic.List[string] }
            $trusted[$h].Add($store)
            $thumb[$h] = $c.Thumbprint
        }
    }
    foreach ($store in 'LocalMachine\Disallowed', 'CurrentUser\Disallowed') {
        foreach ($c in @(Get-ChildItem "Cert:\$store" -ErrorAction SilentlyContinue)) { $blocked[(Get-CertSha256 $c)] = $true }
    }

    $found = 0
    foreach ($e in $list) {
        if (-not $trusted.ContainsKey($e.Sha256)) { continue }
        $where = ($trusted[$e.Sha256] | Select-Object -Unique) -join ', '
        if ($blocked.ContainsKey($e.Sha256)) {
            Ok "$($e.Name) [$($e.Incident)] is blocked by the Disallowed store ($where)"
            continue
        }
        $found++
        $msg = "Distrusted certificate trusted in ${where}: $($e.Name) [$($e.Incident)]"
        $fix = "Install the latest Windows updates (Disallowed certificate list), or: Get-ChildItem Cert:\LocalMachine\Root,Cert:\LocalMachine\CA | Where-Object { `$_.Thumbprint -eq '$($thumb[$e.Sha256])' } | Move-Item -Destination Cert:\LocalMachine\Disallowed  # $($e.Ref)"
        if ($e.Severity -eq 'WARN') { Warn $msg $fix } else { Fail $msg $fix }
    }
    if (-not $found) { Ok "No distrusted CA certificates trusted ($checked certificates checked)" }
}

# Windows LAPS (built in since April 2023) or legacy Microsoft LAPS on joined machines
function Invoke-LapsCheck {
    Section 'LAPS'
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $joined = [bool]($cs -and $cs.PartOfDomain)
    if (-not $joined -and (Get-Command dsregcmd -ErrorAction SilentlyContinue)) {
        $joined = [bool]((dsregcmd /status 2>$null) -match 'AzureAdJoined\s*:\s*YES')
    }
    if (-not $joined) {
        Info 'Not joined to a domain or Entra ID: LAPS does not apply (keep the built-in Administrator disabled)'
        return
    }
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS',
                   'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS',
                   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config') {
        $v = Get-RegValue $k 'BackupDirectory'
        if ($v -eq 1) { Ok 'Windows LAPS backs up the local admin password to Entra ID'; return }
        if ($v -eq 2) { Ok 'Windows LAPS backs up the local admin password to Active Directory'; return }
    }
    if ((Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled') -eq 1) {
        Ok 'Legacy Microsoft LAPS enabled'; return
    }
    Warn 'LAPS not configured: the local admin password is not rotated' '# enable Windows LAPS by GPO or Intune (BackupDirectory: 1 = Entra ID, 2 = Active Directory)'
}

# Attack Surface Reduction rules Microsoft recommends for most organisations
$script:AsrRules = [ordered]@{
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block Office apps from creating child processes'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email and webmail'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript/VBScript from launching downloaded executables'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
}

function Invoke-AsrCheck {
    Section 'Attack Surface Reduction'
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
        Info 'Defender cmdlets not available: ASR rules need Microsoft Defender'; return
    }
    try { $st = Get-MpComputerStatus -ErrorAction Stop } catch { $st = $null }
    if ($st -and $st.PSObject.Properties['AMRunningMode'] -and $st.AMRunningMode -and $st.AMRunningMode -ne 'Normal') {
        Info "Defender runs in $($st.AMRunningMode): ASR rules need Defender as the primary antivirus"; return
    }
    try { $p = Get-MpPreference -ErrorAction Stop } catch { Info "Defender preferences unavailable: $($_.Exception.Message)"; return }
    $ids = @($p.AttackSurfaceReductionRules_Ids); $acts = @($p.AttackSurfaceReductionRules_Actions)
    $mode = @{}
    for ($i = 0; $i -lt $ids.Count; $i++) { if ($ids[$i]) { $mode["$($ids[$i])".ToLowerInvariant()] = [int]$acts[$i] } }
    # 1 = block, 2 = audit, 6 = warn
    $missing = @($script:AsrRules.Keys | Where-Object { $mode[$_] -ne 1 })
    if (-not $missing.Count) { Ok "All recommended Attack Surface Reduction rules in block mode ($($script:AsrRules.Count) rules)"; return }
    $fix = 'Add-MpPreference -AttackSurfaceReductionRules_Ids {0} -AttackSurfaceReductionRules_Actions {1}' -f
        ($missing -join ','), ((@('Enabled') * $missing.Count) -join ',')
    Warn "Recommended Attack Surface Reduction rules not in block mode ($($missing.Count) rules)" $fix
    foreach ($g in $missing) {
        $state = switch ($mode[$g]) { 2 { 'audit' } 6 { 'warn' } default { 'off' } }
        Info "ASR rule $state`: $($script:AsrRules[$g]) ($g)"
    }
}

# LLMNR and NetBIOS name resolution let anyone on the LAN answer name lookups
# and capture NTLM hashes (Responder)
function Invoke-NameResolutionCheck {
    Section 'Name Resolution'
    $dns = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    if ((Get-RegValue $dns 'EnableMulticast') -eq 0) { Ok 'LLMNR disabled' }
    else { Warn 'LLMNR enabled (name spoofing on the local network)' "New-Item -Force '$dns' | Out-Null; Set-ItemProperty '$dns' EnableMulticast 0" }
    $ad = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' -ErrorAction SilentlyContinue)
    if (-not $ad.Count) { Info 'No network adapters with IP found'; return }
    $on = @($ad | Where-Object { $_.TcpipNetbiosOptions -ne 2 })
    if ($on.Count) {
        Warn "NetBIOS over TCP/IP enabled ($($on.Count) adapters)" "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions = 2}"
    } else { Ok 'NetBIOS over TCP/IP disabled on every adapter' }
}

# Services and scheduled tasks a normal user could swap for their own program,
# unquoted service paths, and AlwaysInstallElevated
function Test-PrivilegedBinary([string]$What, [string]$Exe) {
    if (-not $Exe -or -not (Test-Path -LiteralPath $Exe -PathType Leaf)) { return 0 }
    if (Test-UserWritable $Exe) {
        Fail "$What from a user-writable file: $Exe" "icacls $(ConvertTo-PsLiteral $Exe)   # then remove the write grants of Users, Authenticated Users, Everyone"
        return 1
    }
    $dir = Split-Path -Parent $Exe
    if ($dir -and (Test-UserWritable $dir -Folder)) {
        Warn "$What from a user-writable folder: $dir" "icacls $(ConvertTo-PsLiteral $dir)   # users can plant DLLs here: remove their create-files grant"
        return 1
    }
    return 0
}

# Script file a task's script host (PowerShell, cmd, Windows Script Host) runs, or $null
function Get-TaskScriptPath([string]$Exe, [string]$Arguments) {
    # Split on both separators: GetFileName only knows "/" when tests run on Linux
    if (($Exe -split '[\\/]')[-1] -notmatch '^(powershell|pwsh|cmd|wscript|cscript)\.exe$') { return $null }
    $m = [regex]::Match([Environment]::ExpandEnvironmentVariables($Arguments),
        '(?i)"?([a-z]:\\[^"]*?\.(ps1|bat|cmd|vbs|js))(?="|\s|$)')
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function Invoke-PrivEscCheck {
    Section 'Privilege Escalation'
    $bad = 0; $checked = 0
    foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
        if (-not $s.PathName) { continue }
        $checked++
        $exe = Get-ExePath $s.PathName
        $account = if ($s.StartName) { "$($s.StartName)" } else { 'LocalSystem' }
        $raw = $s.PathName.Trim()
        $m = [regex]::Match($raw, '^(.+?\.(exe|com|bat|cmd))(\s|$)', 'IgnoreCase')
        if (-not $raw.StartsWith('"') -and $m.Success -and $m.Groups[1].Value -match ' ') {
            $bad++
            $quoted = '"' + $m.Groups[1].Value + '"' + $raw.Substring($m.Groups[1].Length)
            Warn "Service $($s.Name) has an unquoted path with spaces: $exe" ("Set-ItemProperty {0} ImagePath {1}" -f
                (ConvertTo-PsLiteral "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)"), (ConvertTo-PsLiteral $quoted))
        }
        $bad += Test-PrivilegedBinary "Service $($s.Name) runs as $account" $exe
    }
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            $uid = "$($t.Principal.UserId)"
            $as = if ($uid -match '^(SYSTEM|NT AUTHORITY\\SYSTEM|S-1-5-18|LocalSystem)$') { 'as SYSTEM' }
                  elseif ("$($t.Principal.RunLevel)" -eq 'Highest') { 'elevated' } else { '' }
            if (-not $as) { continue }
            foreach ($a in @($t.Actions)) {
                if (-not $a -or -not $a.PSObject.Properties['Execute'] -or -not $a.Execute) { continue }
                $exe = [Environment]::ExpandEnvironmentVariables("$($a.Execute)".Trim().Trim('"'))
                if (-not [IO.Path]::IsPathRooted($exe)) { continue }
                $checked++
                $bad += Test-PrivilegedBinary "Scheduled task $($t.TaskPath)$($t.TaskName) runs $as" $exe
                # A script host runs a script file: that file is what a user would swap
                $script = Get-TaskScriptPath $exe "$($a.Arguments)"
                if ($script) { $checked++; $bad += Test-PrivilegedBinary "Scheduled task $($t.TaskPath)$($t.TaskName) runs $as a script" $script }
            }
        }
    }
    if (-not $bad) { Ok "No service or scheduled task binaries writable by users ($checked entries)" }

    $inst = 'SOFTWARE\Policies\Microsoft\Windows\Installer'
    $m = Get-RegValue "HKLM:\$inst" 'AlwaysInstallElevated'
    $u = Get-RegValue "HKCU:\$inst" 'AlwaysInstallElevated'
    if ($m -eq 1 -and $u -eq 1) {
        Fail 'AlwaysInstallElevated on: any user can install MSI packages as SYSTEM' "Remove-ItemProperty 'HKLM:\$inst' AlwaysInstallElevated; Remove-ItemProperty 'HKCU:\$inst' AlwaysInstallElevated"
    } elseif ($m -eq 1) {
        Warn 'AlwaysInstallElevated set for the machine (users who set it too install MSI packages as SYSTEM)' "Remove-ItemProperty 'HKLM:\$inst' AlwaysInstallElevated"
    } else { Ok 'AlwaysInstallElevated off' }

    # Print Spooler: PrintNightmare-class bugs give SYSTEM, and on a domain
    # controller the spooler also lets any user coerce DC authentication
    $role = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty DomainRole -ErrorAction SilentlyContinue
    $spool = Get-Service Spooler -ErrorAction SilentlyContinue
    if ($spool -and "$($spool.Status)" -eq 'Running') {
        $off = 'Stop-Service Spooler; Set-Service Spooler -StartupType Disabled'
        if ($role -ge 4)     { Fail 'Print Spooler running on a domain controller' $off }
        elseif ($role -ge 2) { Warn 'Print Spooler running on a server (disable it unless this host shares printers)' $off }
    }
    $pp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    if ((Get-RegValue $pp 'RestrictDriverInstallationToAdministrators') -eq 0) {
        Fail 'Point and Print lets non-admins install printer drivers (PrintNightmare)' "Set-ItemProperty '$pp' RestrictDriverInstallationToAdministrators 1"
    } elseif ((Get-RegValue $pp 'NoWarningNoElevationOnInstall') -eq 1) {
        Fail 'Point and Print installs printer drivers without elevation (PrintNightmare)' "Set-ItemProperty '$pp' NoWarningNoElevationOnInstall 0"
    }
}

# Advanced audit policy subcategories (GUIDs are language-independent) and the
# bits they need: 1 = success, 2 = failure
$script:AuditSubcategories = [ordered]@{
    '{0CCE923F-69AE-11D9-BED3-505054503030}' = @('Credential Validation', 3)
    '{0CCE9215-69AE-11D9-BED3-505054503030}' = @('Logon', 3)
    '{0CCE9217-69AE-11D9-BED3-505054503030}' = @('Account Lockout', 2)
    '{0CCE921B-69AE-11D9-BED3-505054503030}' = @('Special Logon', 1)
    '{0CCE9235-69AE-11D9-BED3-505054503030}' = @('User Account Management', 1)
    '{0CCE9237-69AE-11D9-BED3-505054503030}' = @('Security Group Management', 1)
    '{0CCE922B-69AE-11D9-BED3-505054503030}' = @('Process Creation', 1)
    '{0CCE922F-69AE-11D9-BED3-505054503030}' = @('Audit Policy Change', 1)
}

# Audit policy rows from "auditpol /backup" CSV: GUID -> setting value
function Read-AuditPolicy([string]$CsvPath) {
    $map = @{}
    foreach ($r in @(Import-Csv -LiteralPath $CsvPath)) {
        $v = @($r.PSObject.Properties | ForEach-Object { "$($_.Value)" })
        if ($v.Count -ge 7 -and $v[3] -match '^\{[0-9A-Fa-f-]{36}\}$' -and $v[6] -match '^\d+$') {
            $map[$v[3].ToUpperInvariant()] = [int]$v[6]
        }
    }
    return $map
}

function Invoke-AuditPolicyCheck {
    Section 'Audit Policy'
    if (-not (Test-Admin)) { Info 'Audit policy needs an elevated prompt' }
    elseif (Get-Command auditpol -ErrorAction SilentlyContinue) {
        $csv = Join-Path ([IO.Path]::GetTempPath()) ("anzen-auditpol-{0}.csv" -f [guid]::NewGuid().ToString('N'))
        auditpol /backup /file:$csv 2>$null | Out-Null
        if (Test-Path -LiteralPath $csv) {
            $map = Read-AuditPolicy $csv
            Remove-Item -LiteralPath $csv -Force -ErrorAction SilentlyContinue
            foreach ($g in $script:AuditSubcategories.Keys) {
                $name, $need = $script:AuditSubcategories[$g]
                $have = 0; if ($map.ContainsKey($g)) { $have = $map[$g] }
                if (($have -band $need) -eq $need) { Ok "Audit policy records $name"; continue }
                $flags = @(); if ($need -band 1) { $flags += '/success:enable' }; if ($need -band 2) { $flags += '/failure:enable' }
                $what = @(); if (($need -band 1) -and -not ($have -band 1)) { $what += 'success' }; if (($need -band 2) -and -not ($have -band 2)) { $what += 'failure' }
                Warn "Audit policy does not record $name ($($what -join ' and '))" "auditpol /set /subcategory:`"$g`" $($flags -join ' ')"
            }
        } else { Info 'auditpol /backup failed' }
    }
    # Process creation events (4688) are of little use without the command line
    $pa = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    if ((Get-RegValue $pa 'ProcessCreationIncludeCmdLine_Enabled') -eq 1) { Ok 'Process creation events include the command line' }
    else { Warn 'Process creation events do not include the command line' "New-Item -Force '$pa' | Out-Null; Set-ItemProperty '$pa' ProcessCreationIncludeCmdLine_Enabled 1" }
    try {
        $log = Get-WinEvent -ListLog Security -ErrorAction Stop
        $mb = [int]($log.MaximumSizeInBytes / 1MB)
        if ($mb -lt 192) { Warn "Security event log max size $mb MB (192 MB+ recommended)" 'wevtutil sl Security /ms:201326592' }
        else             { Ok   "Security event log max size $mb MB" }
    } catch { Info 'Security event log size unavailable (needs elevation)' }
}

$Modules = [ordered]@{
    system      = 'Invoke-SystemCheck'
    inventory   = 'Invoke-InventoryCheck'
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
    laps        = 'Invoke-LapsCheck'
    asr         = 'Invoke-AsrCheck'
    nameres     = 'Invoke-NameResolutionCheck'
    privesc     = 'Invoke-PrivEscCheck'
    auditpol    = 'Invoke-AuditPolicyCheck'
    appcontrol  = 'Invoke-AppControlCheck'
    powershell  = 'Invoke-PowerShellCheck'
    secureboot  = 'Invoke-SecureBootCheck'
    network     = 'Invoke-NetworkCheck'
    truststore  = 'Invoke-TrustStoreCheck'
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

# OS caption and version, read once (Get-CimInstance is Windows-only)
function Get-OsInfo {
    if (-not $script:OsInfo) {
        $n = ''; $v = ''
        if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
            if ($os) { $n = "$($os.Caption)"; $v = "$($os.Version)" }
        }
        $script:OsInfo = @{ Name = $n; Version = $v }
    }
    return $script:OsInfo
}

# UTF-8 without BOM, LF line endings — same bytes as the Linux edition
function Save-Text([string]$Path, [string]$Text) {
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding $false))
}

# NIST / CIS references from lib/data/controls.tsv (shared with the Linux and
# macOS editions): first line whose section regex matches the whole section and
# whose message regex matches the message
function Get-Controls([string]$Section, [string]$Message) {
    if ($null -eq $script:Controls) {
        $script:Controls = @()
        $path = [IO.Path]::Combine((Split-Path -Parent $ScriptDir), 'lib', 'data', 'controls.tsv')
        if (Test-Path -LiteralPath $path) {
            $script:Controls = @(foreach ($line in Get-Content -LiteralPath $path -Encoding UTF8) {
                if ($line -match '^\s*(#|$)') { continue }
                $f = $line -split "`t"
                if ($f.Count -ge 3) { [pscustomobject]@{ Section = "^($($f[0]))`$"; Message = $f[1]; Controls = $f[2] } }
            })
        }
    }
    foreach ($c in $script:Controls) {
        if ($Section -match $c.Section -and $Message -match $c.Message) { return $c.Controls }
    }
    return ''
}

function Get-LevelCount([string]$Level) { return @($script:Findings | Where-Object level -eq $Level).Count }

function Write-JsonReport([string]$Path, $Sections, [int]$Score) {
    $osName = (Get-OsInfo).Name; $osVer = (Get-OsInfo).Version
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
        (Get-LevelCount 'FAIL'), (Get-LevelCount 'WARN'), (Get-LevelCount 'OK'), (Get-LevelCount 'INFO'), $Score))
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
    Save-Text $Path $sb.ToString()
}

# Plain-text report, same layout as lib/report_txt.sh
function Write-TxtReport([string]$Path, $Sections, [int]$Score) {
    $os = Get-OsInfo
    $bar = '=' * 60
    $L = New-Object System.Collections.Generic.List[string]
    $L.Add($bar); $L.Add('  ANZEN (安全) — Windows Security Audit Report'); $L.Add("  Anzen $AnzenVersion"); $L.Add($bar); $L.Add('')
    $L.Add("  Hostname   : $(Get-HostName)")
    $L.Add("  OS         : $($os.Name)")
    $L.Add("  Version    : $($os.Version)")
    $L.Add("  Audited by : $([Environment]::UserName)")
    $L.Add("  Date       : $(Get-Date)"); $L.Add(''); $L.Add($bar)
    $L.Add(('  SUMMARY:  FAIL={0,-3}  WARN={1,-3}  OK={2,-3}  SCORE={3}%' -f (Get-LevelCount 'FAIL'), (Get-LevelCount 'WARN'), (Get-LevelCount 'OK'), $Score))
    $L.Add($bar); $L.Add(''); $L.Add('  Section scores:')
    foreach ($s in $Sections) { $L.Add(('    {0,-36} {1,3}%  FAIL={2,-3} WARN={3}' -f $s.name, $s.score, $s.fail, $s.warn)) }
    $L.Add('')
    $cur = $null
    foreach ($f in $script:Findings) {
        if ($f.section -ne $cur) { $L.Add(''); $L.Add("--- $($f.section) ---"); $cur = $f.section }
        $L.Add(('  [{0,-4}] {1}' -f $f.level, $f.message))
        if ($f.level -ne 'OK') { $L.Add("         ID:  $($f.id)") }
        if ($f.remedy -and $f.level -in @('FAIL', 'WARN')) { $L.Add("         Fix: $($f.remedy)") }
        $ctl = Get-Controls $f.section $f.message
        if ($ctl -and $f.level -in @('FAIL', 'WARN')) { $L.Add("         Ref: $ctl") }
    }
    $L.Add(''); $L.Add($bar); $L.Add("  END OF REPORT — $(Get-Date)"); $L.Add($bar)
    Save-Text $Path (($L -join "`n") + "`n")
}

function ConvertTo-HtmlText([string]$s) { return [System.Net.WebUtility]::HtmlEncode($s) }

# Self-contained HTML report in the Linux edition's look (lib/report_html.sh)
function Write-HtmlReport([string]$Path, $Sections, [int]$Score) {
    $os = Get-OsInfo
    $n = @{}; foreach ($l in 'FAIL', 'WARN', 'OK', 'INFO') { $n[$l] = Get-LevelCount $l }
    $scoreColor = if ($Score -lt 50) { '#dc2626' } elseif ($Score -lt 80) { '#d97706' } else { '#059669' }
    $hostName = ConvertTo-HtmlText (Get-HostName)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Anzen — $hostName — $(Get-Date -Format 'yyyy-MM-dd')</title>
<style>
:root { --bg:#0f172a; --surface:#1e293b; --surface2:#263548; --border:#334155; --text:#e2e8f0; --muted:#64748b;
  --FAIL:#ef4444; --FAIL-bg:#7f1d1d; --WARN:#f59e0b; --WARN-bg:#78350f; --OK:#10b981; --OK-bg:#14532d; --INFO:#93c5fd; --INFO-bg:#1e3a5f; }
body.light { --bg:#f1f5f9; --surface:#fff; --surface2:#f8fafc; --border:#e2e8f0; --text:#0f172a;
  --FAIL:#dc2626; --FAIL-bg:#fee2e2; --WARN:#d97706; --WARN-bg:#fef3c7; --OK:#16a34a; --OK-bg:#dcfce7; --INFO:#2563eb; --INFO-bg:#dbeafe; }
* { box-sizing:border-box; margin:0; padding:0; }
body { font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; background:var(--bg); color:var(--text); }
.header { background:var(--surface); border-bottom:1px solid var(--border); padding:1.5rem 2rem; }
.top { display:flex; justify-content:space-between; margin-bottom:1.25rem; }
.logo { font-size:1.75rem; font-weight:800; color:#38bdf8; } .logo span { color:var(--text); }
.tagline { color:var(--muted); font-size:.8rem; }
.btn { padding:.4rem .9rem; border-radius:6px; font-size:.8rem; font-weight:600; cursor:pointer; border:1px solid var(--border); background:var(--surface2); color:var(--text); }
.meta { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:.75rem; }
.meta div { background:var(--bg); border:1px solid var(--border); border-radius:8px; padding:.6rem 1rem; font-family:monospace; font-size:.85rem; }
.meta b { display:block; font-family:sans-serif; font-size:.65rem; text-transform:uppercase; color:var(--muted); font-weight:400; }
.summary { display:grid; grid-template-columns:repeat(4,1fr); gap:1rem; padding:1.25rem 2rem; border-bottom:1px solid var(--border); }
.card { border-radius:10px; padding:1rem; text-align:center; border:1px solid var(--border); background:var(--surface); }
.card b { display:block; font-size:.7rem; text-transform:uppercase; color:var(--muted); }
.card span { font-size:2.5rem; font-weight:800; }
.filters { display:flex; gap:.5rem; padding:1rem 2rem 0; flex-wrap:wrap; }
.filter { padding:.3rem .8rem; border-radius:999px; font-size:.75rem; font-weight:600; cursor:pointer; border:1px solid var(--border); background:var(--surface2); color:var(--muted); }
.filter.active { background:#475569; color:#fff; }
.content { padding:1rem 2rem 2rem; }
details { background:var(--surface); border:1px solid var(--border); border-radius:10px; margin-bottom:.75rem; overflow:hidden; }
summary { padding:.9rem 1.25rem; cursor:pointer; display:flex; justify-content:space-between; font-weight:600; font-size:.9rem; }
.mini { font-size:.65rem; font-weight:700; padding:2px 7px; border-radius:999px; margin-left:.35rem; background:var(--border); }
.finding { padding:.6rem 1.25rem; border-top:1px solid var(--surface2); display:flex; gap:.75rem; font-size:.85rem; }
.badge { padding:2px 8px; border-radius:4px; font-size:.68rem; font-weight:700; height:fit-content; }
.FAIL { background:var(--FAIL-bg); color:var(--FAIL); } .WARN { background:var(--WARN-bg); color:var(--WARN); }
.OK { background:var(--OK-bg); color:var(--OK); } .INFO { background:var(--INFO-bg); color:var(--INFO); }
.msg, .id, code { font-family:"Cascadia Code",Consolas,monospace; word-break:break-word; }
.id { font-size:.68rem; color:var(--muted); }
code { display:inline-block; margin-top:.35rem; font-size:.78rem; color:#38bdf8; background:var(--bg); border:1px solid var(--border); border-radius:4px; padding:2px 6px; cursor:pointer; }
.footer { text-align:center; padding:1.5rem; color:var(--muted); font-size:.75rem; border-top:1px solid var(--border); }
@media print { .btn, .filters { display:none; } details:not([open]) { display:none; } }
</style>
</head>
<body>
<div class="header">
  <div class="top">
    <div><div class="logo">安<span>zen</span></div><div class="tagline">Windows Security Audit</div></div>
    <div><button class="btn" onclick="theme()">☀ / ☾</button> <button class="btn" onclick="window.print()">⎙ Print</button></div>
  </div>
  <div class="meta">
    <div><b>Hostname</b>$hostName</div>
    <div><b>OS</b>$(ConvertTo-HtmlText $os.Name)</div>
    <div><b>Version</b>$(ConvertTo-HtmlText $os.Version)</div>
    <div><b>Audited By</b>$(ConvertTo-HtmlText ([Environment]::UserName))</div>
    <div><b>Date</b>$(Get-Date -Format 'yyyy-MM-dd HH:mm')</div>
  </div>
</div>
<div class="summary">
  <div class="card"><b>Failed</b><span style="color:var(--FAIL)">$($n.FAIL)</span></div>
  <div class="card"><b>Warnings</b><span style="color:var(--WARN)">$($n.WARN)</span></div>
  <div class="card"><b>Passed</b><span style="color:var(--OK)">$($n.OK)</span></div>
  <div class="card"><b>Score</b><span style="color:$scoreColor">$Score%</span></div>
</div>
<div class="filters">
  <button class="filter active" data-f="ALL" onclick="filt('ALL')">All</button>
  <button class="filter" data-f="FAIL" onclick="filt('FAIL')">FAIL ($($n.FAIL))</button>
  <button class="filter" data-f="WARN" onclick="filt('WARN')">WARN ($($n.WARN))</button>
  <button class="filter" data-f="OK" onclick="filt('OK')">OK ($($n.OK))</button>
  <button class="filter" data-f="INFO" onclick="filt('INFO')">INFO ($($n.INFO))</button>
</div>
<div class="content">

"@)
    $scores = @{}; foreach ($s in $Sections) { $scores[$s.name] = $s }
    $order = New-Object System.Collections.Generic.List[string]
    foreach ($f in $script:Findings) { if (-not $order.Contains($f.section)) { $order.Add($f.section) } }
    foreach ($sec in $order) {
        $items = @($script:Findings | Where-Object section -eq $sec)
        $nf = @($items | Where-Object level -eq 'FAIL').Count
        $nw = @($items | Where-Object level -eq 'WARN').Count
        $badges = ''
        if ($nf) { $badges += "<span class=""mini FAIL"">$nf FAIL</span>" }
        if ($nw) { $badges += "<span class=""mini WARN"">$nw WARN</span>" }
        if ($scores.ContainsKey($sec)) { $badges += "<span class=""mini"">$($scores[$sec].score)%</span>" }
        $open = if ($nf) { ' open' } else { '' }
        [void]$sb.Append("<details$open><summary><span>$(ConvertTo-HtmlText $sec)</span><span>$badges</span></summary>`n")
        foreach ($f in $items) {
            $fix = ''
            $ctl = Get-Controls $f.section $f.message
            $ref = if ($ctl -and $f.level -in @('FAIL', 'WARN')) { " · $(ConvertTo-HtmlText $ctl)" } else { '' }
            if ($f.remedy -and $f.level -in @('FAIL', 'WARN')) { $fix = "<br><code title=""Click to copy"" onclick=""navigator.clipboard.writeText(this.textContent)"">$(ConvertTo-HtmlText $f.remedy)</code>" }
            [void]$sb.Append("<div class=""finding"" data-level=""$($f.level)""><span class=""badge $($f.level)"">$($f.level)</span><div><div class=""msg"">$(ConvertTo-HtmlText $f.message)</div><div class=""id"">$($f.id)$ref</div>$fix</div></div>`n")
        }
        [void]$sb.Append("</details>`n")
    }
    [void]$sb.Append(@"
</div>
<div class="footer">Generated by <strong>Anzen $AnzenVersion</strong> &mdash; $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
<script>
function theme() { document.body.classList.toggle('light'); localStorage.setItem('anzen-theme', document.body.classList.contains('light') ? 'light' : 'dark'); }
if (localStorage.getItem('anzen-theme') === 'light') document.body.classList.add('light');
function filt(l) {
  document.querySelectorAll('.finding').forEach(e => e.style.display = (l === 'ALL' || e.dataset.level === l) ? '' : 'none');
  document.querySelectorAll('details').forEach(d => d.style.display = [...d.querySelectorAll('.finding')].some(e => e.style.display !== 'none') ? '' : 'none');
  document.querySelectorAll('.filter').forEach(b => b.classList.toggle('active', b.dataset.f === l));
}
</script>
</body>
</html>

"@)
    Save-Text $Path ($sb.ToString() -replace "`r`n", "`n")
}

# SARIF 2.1.0, same rules/results/fingerprints as lib/report_sarif.sh
function Write-SarifReport([string]$Path) {
    $rules = [ordered]@{}; $results = New-Object System.Collections.Generic.List[object]
    foreach ($f in $script:Findings) {
        if ($f.level -notin @('FAIL', 'WARN')) { continue }
        $lvl = if ($f.level -eq 'FAIL') { 'error' } else { 'warning' }
        $rid = ($f.section.ToLowerInvariant() -replace '[ /]', '-') -replace '[^a-z0-9-]', ''
        if (-not $rules.Contains($rid)) {
            $rules[$rid] = [ordered]@{ id = $rid; name = $f.section; defaultConfiguration = @{ level = $lvl }; help = @{ text = "Anzen check: $($f.section)" } }
        }
        $res = [ordered]@{
            ruleId = $rid; level = $lvl; message = @{ text = $f.message }
            partialFingerprints = @{ 'anzenFindingId/v1' = $f.id }
            locations = @(@{ physicalLocation = @{ artifactLocation = @{ uri = "///$(Get-HostName)" } } })
        }
        $ctl = Get-Controls $f.section $f.message
        if ($ctl) { $res['properties'] = @{ controls = $ctl } }
        $results.Add($res)
    }
    $doc = [ordered]@{
        '$schema' = 'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json'
        version   = '2.1.0'
        runs      = @(@{ tool = @{ driver = @{ name = 'anzen'; version = $AnzenVersion; rules = @($rules.Values | ForEach-Object { $_ }) } }; results = $results.ToArray() })
    }
    Save-Text $Path ((ConvertTo-Json $doc -Depth 12) -replace "`r`n", "`n")
}

# CSV (RFC 4180), same columns as lib/report_csv.sh. A leading = + - @ gets an
# apostrophe so spreadsheets do not run it as a formula (CSV injection)
function ConvertTo-CsvField([string]$v) {
    if ($v -match '^[=+@-]') { $v = "'" + $v }
    return '"' + ($v -replace '"', '""') + '"'
}

function Write-CsvReport([string]$Path) {
    $h = Get-HostName; $d = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $rows = New-Object System.Collections.Generic.List[string]
    $rows.Add('host,date,level,section,id,message,remedy,controls')
    foreach ($f in $script:Findings) {
        $rows.Add((@($h, $d, $f.level, $f.section, $f.id, $f.message, $f.remedy, (Get-Controls $f.section $f.message)) |
            ForEach-Object { ConvertTo-CsvField $_ }) -join ',')
    }
    Save-Text $Path (($rows -join "`r`n") + "`r`n")
}

# Report path for EXT: -Output (extension swapped when several formats), else
# reports\<Prefix>_<Stamp>.<ext> next to the script — same rule as anzen.sh
function Get-ReportPath([string]$Ext, [int]$Count, [string]$Stamp, [string]$Prefix = 'anzen') {
    if (-not $Output) { return Join-Path (Join-Path $ScriptDir 'reports') "${Prefix}_$Stamp.$Ext" }
    if ($Count -le 1) { return $Output }
    $base = $Output
    if ([IO.Path]::GetFileName($base) -match '\.') { $base = $base.Substring(0, $base.LastIndexOf('.')) }
    if ($base.EndsWith('.sarif')) { $base = $base.Substring(0, $base.Length - 6) }
    return "$base.$Ext"
}

function Write-Report([string]$Ext, [string]$Path, $Sections, [int]$Score) {
    switch ($Ext) {
        'json'       { Write-JsonReport $Path $Sections $Score }
        'html'       { Write-HtmlReport $Path $Sections $Score }
        'txt'        { Write-TxtReport $Path $Sections $Score }
        'sarif.json' { Write-SarifReport $Path }
        'csv'        { Write-CsvReport $Path }
    }
}

# ── History, notifications, heartbeat ────────────────────────────────────────

# Newest run in a host's history dir, or $null
function Get-LatestHistory([string]$HostDir) {
    if (-not (Test-Path -LiteralPath $HostDir)) { return $null }
    $f = Get-ChildItem -LiteralPath $HostDir -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
    if ($f) { return $f.FullName }
    return $null
}

# Store a JSON report as <HostDir>\<UTC timestamp>.json (never overwrite), print the path
function Save-History([string]$HostDir, [string]$JsonText) {
    $base = Join-Path $HostDir ((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))
    $file = "$base.json"; $i = 1
    while (Test-Path -LiteralPath $file) { $file = "$base-$i.json"; $i++ }
    Save-Text $file $JsonText
    return $file
}

# Messages of FAIL findings in $Current whose IDs were not FAIL in the $Previous report file
function Get-NewFails([string]$Previous, $Current) {
    $seen = @{}
    if ($Previous -and (Test-Path -LiteralPath $Previous)) {
        try {
            foreach ($f in @((Get-Content -LiteralPath $Previous -Raw | ConvertFrom-Json).findings)) {
                if ($f.level -eq 'FAIL') { $seen[$f.id] = $true }
            }
        } catch { Write-Verbose "unreadable history file $Previous" }
    }
    return @($Current | Where-Object { $_.level -eq 'FAIL' -and -not $seen.ContainsKey($_.id) } | ForEach-Object { $_.message })
}

# ntfy notification (same title/priority/body as lib/notify.sh); -NotifyOn applies
function Send-Notification([int]$Fails, [int]$Score, [string[]]$NewFails, [string]$HostName) {
    if ($Offline -or -not $NtfyUrl) { return }
    $nNew = @($NewFails | Where-Object { $_ }).Count
    switch ($NotifyOn) {
        'always'     { }
        'fail'       { if (-not $Fails) { return } }
        'regression' { if (-not $nNew) { return } }
        default      { Write-Warning "Unknown -NotifyOn '$NotifyOn' (always|fail|regression)"; return }
    }
    $body = "Score: $Score% | $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    if ($nNew) {
        $title = "Anzen: $nNew new FAIL(s) on $HostName"; $prio = 'high'
        $body += "`n" + ((@($NewFails | Where-Object { $_ }) | Select-Object -First 5 | ForEach-Object { "+ $_" }) -join "`n")
        if ($nNew -gt 5) { $body += "`n… and $($nNew - 5) more" }
    } elseif ($Fails) {
        $title = "Anzen: $Fails FAIL(s) on $HostName"; $prio = 'high'
    } else {
        $title = "Anzen: Clean audit on $HostName"; $prio = 'default'
    }
    $headers = @{ Title = $title; Priority = $prio }
    # Token only from the environment: parameters show up in process listings
    if ($env:NOTIFY_NTFY_TOKEN) { $headers['Authorization'] = "Bearer $env:NOTIFY_NTFY_TOKEN" }
    try {
        Invoke-RestMethod -Method Post -Uri $NtfyUrl -Headers $headers -TimeoutSec 15 `
            -Body ([Text.Encoding]::UTF8.GetBytes($body)) -ContentType 'text/plain; charset=utf-8' | Out-Null
    } catch { Write-Warning "Notification to ntfy failed: $($_.Exception.Message)" }
}

function Send-Heartbeat {
    if ($Offline -or -not $HeartbeatUrl) { return }
    try { Invoke-WebRequest -Uri $HeartbeatUrl -UseBasicParsing -TimeoutSec 10 | Out-Null }
    catch { Write-Warning 'Heartbeat to HeartbeatUrl failed' }
}

# ── Fleet (-Remote) ──────────────────────────────────────────────────────────

# Runs on the remote host: write this script, the distrusted list and the accept
# file to a temp dir, audit with the requested formats, return the reports, clean up
$script:RemoteAudit = {
    param($Src, $Tsv, $Accept, $Checks, $Formats, $ControlsTsv)
    $d = Join-Path ([IO.Path]::GetTempPath()) ('anzen.' + [guid]::NewGuid().ToString('N').Substring(0, 12))
    New-Item -ItemType Directory -Force -Path (Join-Path $d 'windows'), (Join-Path $d 'lib\data') | Out-Null
    $noBom = New-Object Text.UTF8Encoding $false
    # BOM: Windows PowerShell 5.1 reads BOM-less scripts as ANSI
    [IO.File]::WriteAllText((Join-Path $d 'windows\anzen.ps1'), $Src, (New-Object Text.UTF8Encoding $true))
    if ($Tsv)    { [IO.File]::WriteAllText((Join-Path $d 'lib\data\distrusted-certs.tsv'), $Tsv, $noBom) }
    if ($Accept) { [IO.File]::WriteAllText((Join-Path $d 'windows\anzen.accept'), $Accept, $noBom) }
    if ($ControlsTsv) { [IO.File]::WriteAllText((Join-Path $d 'lib\data\controls.tsv'), $ControlsTsv, $noBom) }
    $a = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $d 'windows\anzen.ps1'),
           '-Quiet', '-Offline', '-Output', (Join-Path $d 'out.json'))
    foreach ($fmt in $Formats -split ',') {
        switch ($fmt) { 'json' { $a += '-Json' } 'html' { $a += '-Html' } 'txt' { $a += '-Txt' } 'sarif.json' { $a += '-Sarif' } 'csv' { $a += '-Csv' } }
    }
    if ($Checks) { $a += '-Check'; $a += $Checks }
    & powershell.exe @a *> $null
    $out = @{ rc = $LASTEXITCODE }
    foreach ($ext in $Formats -split ',') {
        $p = Join-Path $d "out.$ext"
        if (Test-Path -LiteralPath $p) { $out[$ext] = [IO.File]::ReadAllText($p) }
    }
    Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue
    $out
}

# Host name safe for a history directory: the report's own name if it is a
# plain host name, else the name we connected to
function Get-SafeHostName([string]$Reported, [string]$Connected) {
    $r = "$Reported".ToLowerInvariant()
    if ($r -match '^[a-z0-9][a-z0-9._-]{0,252}$' -and $r -notmatch '\.\.') { return $r }
    return $Connected.ToLowerInvariant()
}

# Audit each host over remoting; returns the worst exit code (255 > 2 > 1 > 0)
function Invoke-Fleet([string[]]$Hosts, [string[]]$Formats, [string[]]$Checks) {
    foreach ($h in $Hosts) {
        if ($h -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { Write-Error "Invalid -Remote host '$h'"; return 255 }
    }
    $src = [IO.File]::ReadAllText($ScriptPath)
    $tsvPath = Join-Path $ScriptDir '..\lib\data\distrusted-certs.tsv'
    $tsv = if (Test-Path -LiteralPath $tsvPath) { [IO.File]::ReadAllText($tsvPath) } else { '' }
    $acc = if ($AcceptFile -and (Test-Path -LiteralPath $AcceptFile)) { [IO.File]::ReadAllText($AcceptFile) } else { '' }
    $ctlPath = [IO.Path]::Combine((Split-Path -Parent $ScriptDir), 'lib', 'data', 'controls.tsv')
    $ctl = if (Test-Path -LiteralPath $ctlPath) { [IO.File]::ReadAllText($ctlPath) } else { '' }
    $wanted = @('json') + @($Formats | Where-Object { $_ -ne 'json' })
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $worst = 0
    foreach ($h in $Hosts) {
        Write-Host ''
        Write-Host "━━━ $h ━━━" -ForegroundColor Cyan
        $ic = @{ ComputerName = $h; ScriptBlock = $script:RemoteAudit; ErrorAction = 'Stop'
                 ArgumentList = @($src, $tsv, $acc, ($Checks -join ','), ($wanted -join ','), $ctl) }
        if ($Credential) { $ic['Credential'] = $Credential }
        try { $r = Invoke-Command @ic } catch { Write-Warning "${h}: $($_.Exception.Message)"; $worst = 255; continue }
        if (-not $r -or -not $r['json']) { Write-Warning "${h}: no JSON report produced"; $worst = 255; continue }
        try { $rep = $r['json'] | ConvertFrom-Json } catch { Write-Warning "${h}: unreadable JSON report"; $worst = 255; continue }
        $name = Get-SafeHostName $rep.hostname $h
        Write-Host ("  FAIL: {0}   WARN: {1}   OK: {2}   Score: {3}%" -f $rep.summary.fail, $rep.summary.warn, $rep.summary.ok, $rep.summary.score)
        $new = @()
        if ($History -and -not $Checks.Count) {
            $hostDir = Join-Path $History $name
            $prev = Get-LatestHistory $hostDir
            $new = Get-NewFails $prev @($rep.findings)
            Write-Host "  History   : $(Save-History $hostDir $r['json'])" -ForegroundColor Cyan
        }
        foreach ($ext in $Formats) {
            if (-not $r[$ext]) { continue }
            $dest = if ($Hosts.Count -eq 1 -and $Output) { Get-ReportPath $ext $Formats.Count $stamp }
                    else { Join-Path (Join-Path $ScriptDir 'reports') "anzen_$(($name -split '\.')[0])_$stamp.$ext" }
            Save-Text $dest $r[$ext]
            Write-Host "  Report    : $dest" -ForegroundColor Cyan
        }
        if (-not $Checks.Count) { Send-Notification ([int]$rep.summary.fail) ([int]$rep.summary.score) $new $name }
        $rc = [int]$r['rc']
        if ($rc -notin 0, 1, 2) { $rc = 255 }
        if ($rc -gt $worst) { $worst = $rc }
    }
    if (-not $Checks.Count) { Send-Heartbeat }
    return $worst
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

# -Output alone keeps meaning -Json
$formats = @()
if ($Json -or ($Output -and -not ($Html -or $Txt -or $Sarif -or $Csv))) { $formats += 'json' }
if ($Html)  { $formats += 'html' }
if ($Txt)   { $formats += 'txt' }
if ($Sarif) { $formats += 'sarif.json' }
if ($Csv)   { $formats += 'csv' }

# Windows PowerShell 5.1 on older .NET may not offer TLS 1.2 by default
if ($PSVersionTable.PSVersion.Major -lt 6) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

$remoteHosts = @($Remote | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
if ($remoteHosts.Count) { exit (Invoke-Fleet $remoteHosts $formats $selected) }

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
$nFail = Get-LevelCount 'FAIL'
$nWarn = Get-LevelCount 'WARN'
$nOk   = Get-LevelCount 'OK'

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

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$labels = @{ json = 'JSON'; html = 'HTML'; txt = 'Text'; 'sarif.json' = 'SARIF'; csv = 'CSV' }
foreach ($ext in $formats) {
    $path = Get-ReportPath $ext $formats.Count $stamp
    Write-Report $ext $path $sections $overall
    Write-Host ('  {0,-10}: {1}' -f $labels[$ext], $path) -ForegroundColor Cyan
}
$newFails = @()
if ($History) {
    $hostDir = Join-Path $History (Get-HostName)
    $prev = Get-LatestHistory $hostDir
    $newFails = Get-NewFails $prev $script:Findings
    $file = Save-History $hostDir ''
    Write-JsonReport $file $sections $overall
    Write-Host "  History   : $file" -ForegroundColor Cyan
}
# -Check runs are partial: no alerts, no heartbeat (same as anzen.sh)
if (-not $selected.Count) {
    Send-Notification $nFail $overall $newFails (Get-HostName)
    Send-Heartbeat
}

if ($nFail -gt 0) { exit 1 }
if ($Strict -and $nWarn -gt 0) { exit 1 }
exit 0
