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
