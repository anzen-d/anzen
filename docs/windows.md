# Windows edition


`windows/anzen.ps1` is the Windows edition (Windows PowerShell 5.1+ / PowerShell 7,
Windows 10/11 and Server 2016+). It uses the same finding IDs, scores,
accept-file format and JSON report, so Windows hosts show up in the same
history and dashboard as Linux hosts.

```powershell
# Elevated PowerShell
powershell -ExecutionPolicy Bypass -File .\windows\anzen.ps1 -Json
.\windows\anzen.ps1 -Check firewall,smb,rdp -Quiet
.\windows\anzen.ps1 -History \\server\anzen\history   # shared HISTORY_DIR for the dashboard
.\windows\anzen.ps1 -List                               # modules
```

| Module | Checks |
|--------|--------|
| `system` | Pending reboot, uptime, disk usage |
| `updates` | Days since last installed update, Windows Update service |
| `defender` | Antivirus and real-time protection, signature age, tamper protection |
| `firewall` | Every profile enabled and blocking inbound by default |
| `accounts` | Guest and built-in Administrator, accounts without passwords, local admins, auto-logon with stored password |
| `passwords` | Minimum length, lockout threshold |
| `uac` | UAC on, admin consent prompt, secure desktop |
| `bitlocker` | System drive protection |
| `smb` | SMBv1, signing required |
| `rdp` | Remote Desktop with Network Level Authentication |
| `credentials` | LSA protection, LM/NTLMv1, stored LM hashes, WDigest |
| `powershell` | Script block logging, PowerShell 2.0 |
| `secureboot` | Secure Boot |
| `network` | Risky ports (SMB, RDP, WinRM, Telnet…) listening on all interfaces |

Options: `-Check`, `-Json`, `-Output`, `-History`, `-AcceptFile`, `-Quiet`,
`-Strict`, `-List`. Exit codes match the Linux edition (1 on FAIL, or on WARN
with `-Strict`). Not yet in the Windows edition: HTML/TXT/SARIF reports, CVE
and container modules, notifications, `--remote`.

---

[← Back to README](../README.md)
