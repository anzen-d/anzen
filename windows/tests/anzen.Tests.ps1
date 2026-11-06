# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# windows/tests/anzen.Tests.ps1 — Pester 5 tests for the platform-independent
# parts of anzen.ps1 (IDs, accept file, scores, JSON layout). Windows-only checks
# need a real Windows host; these run anywhere pwsh runs, including Linux CI.

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'anzen.ps1')
    function Reset-Findings { $script:Findings.Clear(); $script:Accepted = @{}; $script:Section = 'General' }
    $Quiet = $true
}

Describe 'Get-FindingId' {
    It 'matches the Linux edition for the same section and message' {
        # Expected values computed by lib/output.sh _finding_id
        Get-FindingId 'System Information' 'Disk C: 93% used' | Should -Be 'system-information-abe54821'
        Get-FindingId 'Local Accounts' '3 users found (x)' | Should -Be 'local-accounts-c2175ccc'
        Get-FindingId 'Container Security' '[docker] portainer mounts sensitive path: /var/run/docker.sock  [CIS 5.5]' |
            Should -Be 'container-security-9bdb5279'
    }
    It 'ignores volatile numbers' {
        Get-FindingId 'Windows Update' 'Last update installed 12 days ago (KB1)' |
            Should -Be (Get-FindingId 'Windows Update' 'Last update installed 40 days ago (KB1)')
    }
}

Describe 'Accepted risks' {
    BeforeEach { Reset-Findings }
    It 'turns an accepted FAIL into INFO until the expiry date' {
        $script:Section = 'SMB'
        $id = Get-FindingId 'SMB' 'SMBv1 server enabled'
        $f = New-TemporaryFile
        Set-Content $f "$id 2999-01-01 legacy scanner"
        Import-AcceptFile $f
        Fail 'SMBv1 server enabled' 'x' 6>$null
        $script:Findings[0].level | Should -Be 'INFO'
        $script:Findings[0].message | Should -Match 'accepted until 2999-01-01: legacy scanner'
    }
    It 'keeps FAIL after the expiry date' {
        $script:Section = 'SMB'
        $f = New-TemporaryFile
        Set-Content $f "$(Get-FindingId 'SMB' 'SMBv1 server enabled') 2000-01-01 old"
        Import-AcceptFile $f
        Fail 'SMBv1 server enabled' 'x' 6>$null
        $script:Findings[0].level | Should -Be 'FAIL'
        $script:Findings[0].message | Should -Match 'acceptance expired'
    }
}

Describe 'Scores and JSON report' {
    BeforeEach { Reset-Findings }
    It 'scores sections like the Linux edition' {
        $script:Section = 'A'; Fail 'one' 6>$null; Warn 'two' 6>$null
        $script:Section = 'B'; Ok 'fine' 6>$null
        $s = @(Get-SectionScores)
        ($s | Where-Object name -eq 'A').score | Should -Be 87
        ($s | Where-Object name -eq 'B').score | Should -Be 100
    }
    It 'writes valid JSON in the line layout the history parser expects' {
        $script:Section = 'SMB'; Fail 'quote " and back\slash' 'cmd "x"' 6>$null
        $out = Join-Path ([IO.Path]::GetTempPath()) 'anzen-test.json'
        Write-JsonReport $out @(Get-SectionScores) 90
        $j = Get-Content $out -Raw | ConvertFrom-Json
        $j.findings[0].message | Should -Be 'quote " and back\slash'
        $j.summary.score | Should -Be 90
        (Get-Content $out) -match '^    \{"id": "smb-[0-9a-f]{8}", "level": "FAIL", "section": "SMB", "message": ' | Should -Not -BeNullOrEmpty
    }
}

Describe 'Trust store check helpers' {
    It 'computes the same SHA-256 fingerprint as the Linux edition' {
        $pem = Get-Content (Join-Path $PSScriptRoot '..' '..' 'tests' 'fixtures' 'emudhra-dv-g3b.pem') -Raw
        $b64 = ($pem -replace '-----[^-]+-----', '') -replace '\s', ''
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($b64))
        Get-CertSha256 $cert | Should -Be '42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493'
    }
    It 'reads the shared distrusted list' {
        $list = @(Get-DistrustedList (Join-Path $PSScriptRoot '..' '..' 'lib' 'data' 'distrusted-certs.tsv'))
        $list.Count | Should -BeGreaterThan 15
        ($list | Where-Object Sha256 -eq '42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493').Severity | Should -Be 'FAIL'
    }
}

Describe 'Remedy and path helpers' {
    It 'quotes values as PowerShell literals, curly quotes included' {
        ConvertTo-PsLiteral "it's" | Should -Be "'it''s'"
        ConvertTo-PsLiteral "a$([char]0x2019)b" | Should -Be "'a$([char]0x2019)$([char]0x2019)b'"
    }
    It 'finds the executable in service command lines' {
        Get-ExePath '"C:\Program Files\App\svc.exe" -k x' | Should -Be 'C:\Program Files\App\svc.exe'
        Get-ExePath 'C:\Program Files\App\svc.exe -k x'   | Should -Be 'C:\Program Files\App\svc.exe'
        Get-ExePath 'C:\Windows\system32\svchost.exe -k netsvcs' | Should -Be 'C:\Windows\system32\svchost.exe'
    }
    It 'reads the audit policy backup CSV by GUID' {
        $csv = Join-Path ([IO.Path]::GetTempPath()) 'anzen-auditpol-test.csv'
        Set-Content $csv @(
            'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value',
            'PC,System,Anmeldung,{0cce9215-69ae-11d9-bed3-505054503030},Erfolg und Fehler,,3',
            'PC,System,Prozesserstellung,{0CCE922B-69AE-11D9-BED3-505054503030},Keine Überwachung,,0',
            ',,Option:CrashOnAuditFail,,Disabled,,0')
        $m = Read-AuditPolicy $csv
        $m['{0CCE9215-69AE-11D9-BED3-505054503030}'] | Should -Be 3
        $m['{0CCE922B-69AE-11D9-BED3-505054503030}'] | Should -Be 0
        $m.Count | Should -Be 2
    }
}

Describe 'New Windows checks' {
    BeforeAll {
        # Windows-only cmdlets: stand-ins so Pester can mock them on any platform
        foreach ($c in 'Get-CimInstance', 'Get-ScheduledTask', 'Get-MpPreference', 'Get-MpComputerStatus', 'Get-Service',
                       'Get-NetFirewallProfile', 'Get-NetFirewallRule', 'Get-NetFirewallPortFilter', 'Get-NetFirewallAddressFilter', 'Get-NetFirewallApplicationFilter') {
            if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { New-Item -Path "function:global:$c" -Value { } | Out-Null }
        }
    }
    BeforeEach { Reset-Findings }

    It 'flags writable service binaries and unquoted paths' {
        Mock Get-CimInstance { @(
            [pscustomobject]@{ Name = 'Good'; PathName = 'C:\Windows\system32\svchost.exe -k x'; StartName = 'LocalSystem' },
            [pscustomobject]@{ Name = 'BadBin'; PathName = '"C:\Apps\bad.exe"'; StartName = 'LocalSystem' },
            [pscustomobject]@{ Name = 'VendorSvc'; PathName = 'C:\Program Files\Vendor App\svc.exe -run'; StartName = 'LocalSystem' }) }
        Mock Get-ScheduledTask { @() }
        Mock Test-Path { $true }
        Mock Test-UserWritable { $Path -eq 'C:\Apps\bad.exe' }
        Mock Get-RegValue { $null }
        Invoke-PrivEscCheck 6>$null
        $f = $script:Findings
        ($f | Where-Object { $_.level -eq 'FAIL' -and $_.message -eq 'Service BadBin runs as LocalSystem from a user-writable file: C:\Apps\bad.exe' }) | Should -Not -BeNullOrEmpty
        $u = $f | Where-Object { $_.message -like 'Service VendorSvc has an unquoted path*' }
        $u.level | Should -Be 'WARN'
        $u.remedy | Should -Be "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\VendorSvc' ImagePath '`"C:\Program Files\Vendor App\svc.exe`" -run'"
        @($f | Where-Object message -like 'Service Good*').Count | Should -Be 0
        ($f | Where-Object message -eq 'AlwaysInstallElevated off').level | Should -Be 'OK'
    }
    It 'flags the Print Spooler on a domain controller and unsafe Point and Print' {
        Mock Get-CimInstance { if ("$args $(Get-Variable ClassName -ValueOnly -ErrorAction SilentlyContinue)" -match 'ComputerSystem') { [pscustomobject]@{ DomainRole = 5 } } }
        Mock Get-ScheduledTask { @() }
        Mock Get-Service { [pscustomobject]@{ Name = 'Spooler'; Status = 'Running' } }
        Mock Get-RegValue { if ($Name -eq 'RestrictDriverInstallationToAdministrators') { 0 } }
        Invoke-PrivEscCheck 6>$null
        $f = $script:Findings
        ($f | Where-Object message -eq 'Print Spooler running on a domain controller').level | Should -Be 'FAIL'
        ($f | Where-Object message -eq 'Point and Print lets non-admins install printer drivers (PrintNightmare)').level | Should -Be 'FAIL'
    }
    It 'leaves the Print Spooler alone on workstations' {
        Mock Get-CimInstance { if ("$args $(Get-Variable ClassName -ValueOnly -ErrorAction SilentlyContinue)" -match 'ComputerSystem') { [pscustomobject]@{ DomainRole = 1 } } }
        Mock Get-ScheduledTask { @() }
        Mock Get-Service { [pscustomobject]@{ Name = 'Spooler'; Status = 'Running' } }
        Mock Get-RegValue { $null }
        Invoke-PrivEscCheck 6>$null
        @($script:Findings | Where-Object message -like '*Spooler*').Count | Should -Be 0
    }
    It 'reports application control state' {
        if (-not (Get-Command Get-AppLockerPolicy -ErrorAction SilentlyContinue)) { New-Item -Path function:global:Get-AppLockerPolicy -Value { } | Out-Null }
        Mock Get-CimInstance { [pscustomobject]@{ UsermodeCodeIntegrityPolicyEnforcementStatus = 0 } }
        Mock Get-AppLockerPolicy { [pscustomobject]@{ RuleCollections = @(
            [pscustomobject]@{ RuleCollectionType = 'Exe'; EnforcementMode = 'Enabled' },
            [pscustomobject]@{ RuleCollectionType = 'Script'; EnforcementMode = 'AuditOnly' }) } }
        Mock Get-Service { [pscustomobject]@{ Name = 'AppIDSvc'; Status = 'Stopped' } }
        Invoke-AppControlCheck 6>$null
        ($script:Findings | Where-Object message -eq 'AppLocker rules are enforced but the Application Identity service is not running').level | Should -Be 'WARN'
        Reset-Findings
        Mock Get-Service { [pscustomobject]@{ Name = 'AppIDSvc'; Status = 'Running' } }
        Invoke-AppControlCheck 6>$null
        ($script:Findings | Where-Object message -eq 'AppLocker enforced for: Exe').level | Should -Be 'OK'
        Reset-Findings
        Mock Get-AppLockerPolicy { }
        Mock Get-CimInstance { [pscustomobject]@{ UsermodeCodeIntegrityPolicyEnforcementStatus = 1 } }
        Invoke-AppControlCheck 6>$null
        ($script:Findings | Where-Object message -like '*audit mode only').level | Should -Be 'INFO'
        Reset-Findings
        Mock Get-CimInstance { [pscustomobject]@{ UsermodeCodeIntegrityPolicyEnforcementStatus = 2 } }
        Invoke-AppControlCheck 6>$null
        ($script:Findings | Where-Object message -like 'App Control for Business*').level | Should -Be 'OK'
        $script:Findings.Count | Should -Be 1
    }
    It 'flags inbound rules that allow any traffic' {
        Mock Get-NetFirewallProfile { [pscustomobject]@{ Name = 'Domain'; Enabled = $true; DefaultInboundAction = 'Block' } }
        Mock Get-NetFirewallRule { @(
            [pscustomobject]@{ Name = 'open-all'; DisplayName = "Bob's test" },
            [pscustomobject]@{ Name = 'rdp'; DisplayName = 'Remote Desktop' }) }
        Mock Get-NetFirewallPortFilter { @(
            [pscustomobject]@{ InstanceID = 'open-all'; Protocol = 'Any' },
            [pscustomobject]@{ InstanceID = 'rdp'; Protocol = 'TCP' }) }
        Mock Get-NetFirewallAddressFilter { @(
            [pscustomobject]@{ InstanceID = 'open-all'; RemoteAddress = 'Any' },
            [pscustomobject]@{ InstanceID = 'rdp'; RemoteAddress = 'Any' }) }
        Mock Get-NetFirewallApplicationFilter { @(
            [pscustomobject]@{ InstanceID = 'open-all'; Program = 'Any' },
            [pscustomobject]@{ InstanceID = 'rdp'; Program = 'Any' }) }
        Invoke-FirewallCheck 6>$null
        $w = @($script:Findings | Where-Object message -like 'Firewall rule *')
        $w.Count | Should -Be 1
        $w[0].message | Should -Be "Firewall rule 'Bob's test' allows any inbound traffic"
        $w[0].remedy | Should -Be "Disable-NetFirewallRule -Name 'open-all'"
    }

    It 'lists recommended ASR rules that are not in block mode' {
        Mock Get-MpComputerStatus { [pscustomobject]@{ AMRunningMode = 'Normal' } }
        Mock Get-MpPreference { [pscustomobject]@{
            AttackSurfaceReductionRules_Ids = @('9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2', '56a863a9-875e-4185-98a7-b882c64b5ce5')
            AttackSurfaceReductionRules_Actions = @(1, 2) } }
        Invoke-AsrCheck 6>$null
        $w = $script:Findings | Where-Object level -eq 'WARN'
        $w.message | Should -Be 'Recommended Attack Surface Reduction rules not in block mode (6 rules)'
        $w.remedy | Should -Match '^Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5,'
        $w.remedy | Should -Not -Match '9e6c4e1f'
        ($script:Findings | Where-Object message -like 'ASR rule audit:*').Count | Should -Be 1
    }

    It 'checks Defender cloud protection and PUA blocking' {
        Mock Get-MpComputerStatus { [pscustomobject]@{ AMRunningMode = 'Normal'; AntivirusEnabled = $true; RealTimeProtectionEnabled = $true; AntivirusSignatureAge = 1 } }
        Mock Get-MpPreference { [pscustomobject]@{ MAPSReporting = 0; PUAProtection = 0 } }
        Invoke-DefenderCheck 6>$null
        ($script:Findings | Where-Object message -eq 'Cloud-delivered protection off (MAPS reporting disabled)').level | Should -Be 'WARN'
        ($script:Findings | Where-Object message -eq 'Potentially unwanted app blocking off').remedy | Should -Be 'Set-MpPreference -PUAProtection Enabled'
        Reset-Findings
        Mock Get-MpComputerStatus { [pscustomobject]@{ AMRunningMode = 'Passive Mode'; AntivirusEnabled = $true; RealTimeProtectionEnabled = $true; AntivirusSignatureAge = 1 } }
        Invoke-DefenderCheck 6>$null
        @($script:Findings | Where-Object message -like '*unwanted*').Count | Should -Be 0
    }
    It 'checks the Windows Hello PIN policy and convenience PIN' {
        if (-not (Get-Command net -ErrorAction SilentlyContinue)) { New-Item -Path function:global:net -Value { } | Out-Null }
        Mock Get-RegValue { switch ($Name) { 'MinimumPINLength' { 4 } 'AllowDomainPINLogon' { 1 } default { $null } } }
        Invoke-PasswordPolicyCheck 6>$null
        ($script:Findings | Where-Object message -eq 'Windows Hello PIN minimum length (4) below 6').level | Should -Be 'WARN'
        ($script:Findings | Where-Object message -like 'Convenience PIN sign-in on*').level | Should -Be 'WARN'
    }
    It 'skips ASR when Defender is passive' {
        Mock Get-MpComputerStatus { [pscustomobject]@{ AMRunningMode = 'Passive Mode' } }
        Mock Get-MpPreference { throw 'not called' }
        Invoke-AsrCheck 6>$null
        $script:Findings[0].level | Should -Be 'INFO'
    }
}

Describe 'HTML, TXT and SARIF reports' {
    BeforeEach {
        Reset-Findings
        $script:Section = 'Credential Protection'
        Fail 'evil <script>alert(1)</script>' 'fix "now"' 6>$null
        $script:Section = 'SMB'; Ok 'SMBv1 server disabled' 6>$null
        $dir = Join-Path ([IO.Path]::GetTempPath()) ('anzen-rep-' + [guid]::NewGuid().ToString('N'))
    }
    It 'escapes findings in HTML' {
        Write-HtmlReport (Join-Path $dir 'r.html') @(Get-SectionScores) 90
        $h = Get-Content (Join-Path $dir 'r.html') -Raw
        $h | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
        $h | Should -Not -Match '<script>alert'
        $h | Should -Match 'fix &quot;now&quot;'
    }
    It 'writes the text report with IDs and fixes' {
        Write-TxtReport (Join-Path $dir 'r.txt') @(Get-SectionScores) 90
        $t = Get-Content (Join-Path $dir 'r.txt') -Raw
        $t | Should -Match '--- Credential Protection ---'
        $t | Should -Match 'Fix: fix "now"'
        $t | Should -Match 'ID:  credential-protection-[0-9a-f]{8}'
    }
    It 'writes SARIF with the Linux rule IDs and fingerprints' {
        Write-SarifReport (Join-Path $dir 'r.sarif.json')
        $j = Get-Content (Join-Path $dir 'r.sarif.json') -Raw | ConvertFrom-Json
        $j.version | Should -Be '2.1.0'
        @($j.runs[0].results).Count | Should -Be 1
        $j.runs[0].results[0].ruleId | Should -Be 'credential-protection'
        $j.runs[0].results[0].level | Should -Be 'error'
        $j.runs[0].results[0].partialFingerprints.'anzenFindingId/v1' | Should -Be $script:Findings[0].id
    }
    It 'swaps the -Output extension per format like anzen.sh' {
        $Output = 'C:\r\out.json'
        Get-ReportPath 'html' 3 's' | Should -Be 'C:\r\out.html'
        Get-ReportPath 'sarif.json' 3 's' | Should -Be 'C:\r\out.sarif.json'
        Get-ReportPath 'json' 1 's' | Should -Be 'C:\r\out.json'
        $Output = 'C:\r\out.sarif.json'
        Get-ReportPath 'txt' 2 's' | Should -Be 'C:\r\out.txt'
    }
}

Describe 'Regressions and notifications' {
    BeforeEach { Reset-Findings }
    It 'reports only FAILs missing from the previous run' {
        $script:Section = 'SMB'; Fail 'old one' 6>$null; Fail 'new one' 6>$null
        $prev = Join-Path ([IO.Path]::GetTempPath()) 'anzen-prev.json'
        Set-Content $prev ('{"findings": [{"id": "' + (Get-FindingId 'SMB' 'old one') + '", "level": "FAIL"}]}')
        Get-NewFails $prev $script:Findings | Should -Be @('new one')
        Get-NewFails '' $script:Findings | Should -HaveCount 2
    }
    It 'applies -NotifyOn and sends the token from the environment only' {
        $NtfyUrl = 'https://ntfy.example.com/topic'; $Offline = $false
        $env:NOTIFY_NTFY_TOKEN = 'tk_test'
        Mock Invoke-RestMethod { }
        $NotifyOn = 'regression'
        Send-Notification 2 70 @() 'pc1'
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
        Send-Notification 2 70 @('a new fail') 'pc1'
        Should -Invoke Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
            $Headers.Title -eq 'Anzen: 1 new FAIL(s) on pc1' -and $Headers.Priority -eq 'high' -and
            $Headers.Authorization -eq 'Bearer tk_test' -and $Uri -eq 'https://ntfy.example.com/topic' }
        $NotifyOn = 'always'; $Offline = $true
        Send-Notification 0 100 @() 'pc1'
        Should -Invoke Invoke-RestMethod -Times 1 -Exactly
        Remove-Item Env:NOTIFY_NTFY_TOKEN
    }
}

Describe 'Fleet (-Remote)' {
    It 'keeps unsafe reported host names out of history paths' {
        Get-SafeHostName 'PC1.corp.example' 'pc1' | Should -Be 'pc1.corp.example'
        Get-SafeHostName '..\..\evil' 'pc1' | Should -Be 'pc1'
        Get-SafeHostName 'a..b' 'pc1' | Should -Be 'pc1'
    }
    It 'stores remote reports in history and returns the remote exit code' {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('anzen-fleet-' + [guid]::NewGuid().ToString('N'))
        $History = Join-Path $tmp 'history'; $Output = Join-Path $tmp 'out.json'; $NtfyUrl = ''
        $json = '{"hostname": "pc1", "summary": {"fail": 1, "warn": 0, "ok": 2, "info": 0, "score": 90}, "findings": [{"id": "smb-00000000", "level": "FAIL", "message": "x"}]}'
        Mock Invoke-Command { @{ rc = 1; json = $json; html = '<html></html>' } }
        $rc = Invoke-Fleet @('pc1') @('json', 'html') @() 6>$null
        $rc | Should -Be 1
        @(Get-ChildItem (Join-Path $History 'pc1') -Filter *.json).Count | Should -Be 1
        Get-Content (Join-Path $tmp 'out.html') -Raw | Should -Be '<html></html>'
        Invoke-Fleet @('bad host') @('json') @() 2>$null 6>$null | Should -Be 255
    }
}

Describe 'Controls and CSV' {
    BeforeEach { Reset-Findings }
    It 'maps findings with the shared controls.tsv' {
        Get-Controls 'SSH Configuration' 'PermitRootLogin yes' | Should -Be 'NIST AC-6(2), IA-2; CIS 5.4'
        Get-Controls 'BitLocker' 'System drive C: not protected by BitLocker' | Should -Be 'NIST SC-28; CIS 3.11'
        Get-Controls 'Made Up' 'x' | Should -Be ''
    }
    It 'writes CSV with quoting and formula defusing' {
        $script:Section = 'SMB'; Fail 'say "hi", go' '=cmd' 6>$null
        $out = Join-Path ([IO.Path]::GetTempPath()) 'anzen-test.csv'
        Write-CsvReport $out
        $rows = @(Import-Csv $out)
        $rows[0].message | Should -Be 'say "hi", go'
        $rows[0].remedy | Should -Be "'=cmd"
        $rows[0].controls | Should -Be 'NIST CM-7, SC-7; CIS 4.8'
    }
}

Describe 'Null sessions, WSUS and task scripts' {
    BeforeEach { Reset-Findings }
    It 'finds the script a task script host runs' {
        Get-TaskScriptPath 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' '-NoProfile -File "C:\Ops\My Scripts\backup.ps1" -x' |
            Should -Be 'C:\Ops\My Scripts\backup.ps1'
        Get-TaskScriptPath 'C:\Windows\System32\cmd.exe' '/c C:\Ops\run.bat' | Should -Be 'C:\Ops\run.bat'
        Get-TaskScriptPath 'C:\Apps\tool.exe' '-f C:\Ops\x.ps1' | Should -BeNullOrEmpty
    }
    It 'flags null-session settings' {
        if (-not (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue)) { New-Item -Path function:global:Get-SmbServerConfiguration -Value { } | Out-Null }
        if (-not (Get-Command Get-SmbClientConfiguration -ErrorAction SilentlyContinue)) { New-Item -Path function:global:Get-SmbClientConfiguration -Value { } | Out-Null }
        Mock Get-SmbClientConfiguration { [pscustomobject]@{ RequireSecuritySignature = $true } }
        Mock Get-SmbServerConfiguration { [pscustomobject]@{ EnableSMB1Protocol = $false; RequireSecuritySignature = $true } }
        Mock Get-RegValue { switch ($Name) { 'RestrictNullSessAccess' { 0 } 'RestrictAnonymousSAM' { 1 } 'EveryoneIncludesAnonymous' { 0 } 'RestrictAnonymous' { 0 } 'NullSessionShares' { @('PUBLIC') } default { $null } } }
        Invoke-SmbCheck 6>$null
        $f = $script:Findings
        ($f | Where-Object message -eq 'SMB server allows null-session access to shares and named pipes').level | Should -Be 'FAIL'
        ($f | Where-Object message -eq 'Anonymous users can enumerate shares (RestrictAnonymous=0)').level | Should -Be 'WARN'
        ($f | Where-Object message -eq 'Shares open to null sessions: PUBLIC').level | Should -Be 'WARN'
        @($f | Where-Object message -like '*RestrictAnonymousSAM*').Count | Should -Be 0
    }
    It 'fails WSUS over plain HTTP' {
        if (-not (Get-Command Get-HotFix -ErrorAction SilentlyContinue)) { New-Item -Path function:global:Get-HotFix -Value { } | Out-Null }
        if (-not (Get-Command Get-Service -ErrorAction SilentlyContinue)) { New-Item -Path function:global:Get-Service -Value { } | Out-Null }
        Mock Get-HotFix { }
        Mock Get-Service { }
        Mock Get-RegValue { switch ($Name) { 'WUServer' { 'http://wsus.corp.example:8530' } 'UseWUServer' { 1 } default { $null } } }
        Invoke-UpdatesCheck 6>$null
        ($script:Findings | Where-Object message -like 'Updates come from WSUS over plain HTTP*').level | Should -Be 'FAIL'
    }
}
