# Windows edition


`windows/anzen.ps1` is the Windows edition (Windows PowerShell 5.1+ / PowerShell 7,
Windows 10/11 and Server 2016+). It uses the same finding IDs, scores,
accept-file format and JSON report, so Windows hosts show up in the same
history and dashboard as Linux hosts.

```powershell
# Elevated PowerShell
powershell -ExecutionPolicy Bypass -File .\windows\anzen.ps1 -Json
.\windows\anzen.ps1 -Html -Txt -Sarif -Output C:\reports\pc1.json   # pc1.json, .html, .txt, .sarif.json
.\windows\anzen.ps1 -Check firewall,smb,rdp -Quiet
.\windows\anzen.ps1 -History \\server\anzen\history   # shared HISTORY_DIR for the dashboard
.\windows\anzen.ps1 -List                               # modules
```

| Module | Checks |
|--------|--------|
| `system` | Pending reboot, uptime, disk usage |
| `inventory` | INFO only: manufacturer, model, serial, CPU, memory, domain/workgroup, Windows version and build, installed program count, TPM |
| `updates` | Days since last installed update, Windows Update service, WSUS over plain HTTP (FAIL) |
| `defender` | Antivirus and real-time protection, signature age, tamper protection, cloud-delivered protection, PUA blocking, exclusions of whole drives, user-writable folders, executable file types and script hosts |
| `firewall` | Every profile enabled and blocking inbound by default, inbound allow rules open to any traffic |
| `accounts` | Guest and built-in Administrator, accounts without passwords, local admins, auto-logon with stored password |
| `passwords` | Minimum length, lockout threshold, Windows Hello PIN length, convenience PIN |
| `uac` | UAC on, admin consent prompt, secure desktop |
| `bitlocker` | System drive protection, recovery password protector |
| `smb` | SMBv1, signing required on server and client, null sessions (`RestrictNullSessAccess`, `RestrictAnonymous`, `RestrictAnonymousSAM`, `EveryoneIncludesAnonymous`, null-session shares), shares giving Everyone, anonymous or Authenticated Users change/full access, share folders whose NTFS ACL lets Everyone, Users or Authenticated Users write |
| `rdp` | Remote Desktop with Network Level Authentication |
| `credentials` | LSA protection, LM/NTLMv1, stored LM hashes, WDigest, Credential Guard (Enterprise/Education/Server) |
| `laps` | Windows LAPS or legacy LAPS on domain- or Entra-joined machines |
| `asr` | Seven recommended Attack Surface Reduction rules in block mode (Defender as primary antivirus) |
| `nameres` | LLMNR and NetBIOS over TCP/IP (name spoofing, NTLM hash capture) |
| `privesc` | Service and SYSTEM/elevated scheduled-task binaries, the scripts those tasks run, or their folders writable by users, unquoted service paths, AlwaysInstallElevated, Print Spooler on servers and domain controllers, Point and Print (PrintNightmare) |
| `auditpol` | Advanced audit policy for logons, lockouts, account and group changes, process creation, policy changes; command line in process creation events; Security log size |
| `appcontrol` | App Control for Business (WDAC) or AppLocker enforced, AppLocker without the Application Identity service |
| `screenlock` | Machine inactivity limit (`InactivityTimeoutSecs`) of 15 minutes or less, otherwise a password-protected screen saver within 15 minutes for the user running the audit |
| `powershell` | Script block logging, PowerShell 2.0 |
| `secureboot` | Secure Boot |
| `network` | Risky ports (SMB, RDP, WinRM, Telnet…) listening on all interfaces |
| `truststore` | Distrusted CA certificates (same list as Linux) in machine and user stores, unless blocked by the Disallowed store |
| `compromise` | Supply-chain indicators (same list as Linux, `lib/data/ioc.tsv`): established connections to known malware servers, the ChainDrop `setup.mjs` loader in `.claude` / `.vscode` project folders under the profiles folder |

Options: `-Check`, `-Json`, `-Html`, `-Txt`, `-Sarif`, `-Csv`, `-Output`, `-History`,
`-AcceptFile`, `-Quiet`, `-Strict`, `-Remote`, `-Credential`, `-NtfyUrl`,
`-NotifyOn`, `-HeartbeatUrl`, `-Offline`, `-List`. Exit codes match the Linux
edition (1 on FAIL, or on WARN with `-Strict`). `-Check` runs are partial: no
notification and no heartbeat. Not yet in the Windows edition: CVE and
container modules, the dashboard (build it on Linux from the same history).

## Fleet: `-Remote`

Audit other Windows hosts over PowerShell remoting (WinRM). The script, the
distrusted-certificate list and your accept file are copied to a temp folder on
each host, the audit runs there, and the reports come back. History,
notifications and the heartbeat stay on the machine you run it from.

```powershell
# Domain: Kerberos as the current user. Elsewhere: -Credential (Get-Credential)
.\windows\anzen.ps1 -Remote pc1,pc2,srv1 -Html -History \\server\anzen\history
```

Each host's reports land in `reports\anzen_<host>_<timestamp>.<ext>` (with one
host, `-Output` sets the path). The exit code is the worst of all hosts, 255
when a host could not be reached. Enable remoting on the targets with
`Enable-PSRemoting` (on by default on Windows Server).

## Notifications and heartbeat

The same ntfy alert as the Linux edition, after each full run:

```powershell
$env:NOTIFY_NTFY_TOKEN = 'tk_...'          # only from the environment
.\windows\anzen.ps1 -History C:\anzen\history -NtfyUrl https://ntfy.example.com/anzen -NotifyOn regression
```

`-NotifyOn` is `always`, `fail` or `regression` (FAIL findings that were not in
the previous run of that host in `-History`). `-NtfyUrl`, `-NotifyOn` and
`-HeartbeatUrl` default to `$env:NOTIFY_NTFY_URL`, `$env:NOTIFY_ON` and
`$env:HEARTBEAT_URL`, so a scheduled task can set them as machine environment
variables instead of command-line arguments.

---

[← Back to README](../README.md)
