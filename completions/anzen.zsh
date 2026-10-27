#compdef anzen anzen.sh
# zsh completion for anzen

_anzen() {
    local -a modules
    modules=(
        'system:CPU, memory, disk and basic OS checks'
        'users:User accounts, sudo, password policies'
        'ssh:SSH daemon configuration'
        'network:Firewall and open ports'
        'network2:Advanced network (forwarding, IPv6, sysctl)'
        'packages:Package updates and integrity'
        'files:File permissions and SUID binaries'
        'secrets:Credentials, keys and .env files'
        'systemd_hardening:Per-service systemd sandbox options'
        'tls:TLS certificate expiry'
        'compiler:Compiler and offensive tool detection'
        'path_check:PATH security and LD_PRELOAD'
        'modules:Kernel module security'
        'services:Docker, databases, fail2ban'
        'docker_security:Container runtimes (Docker, Podman, nerdctl, LXD, LXC, k8s)'
        'logins:Recent logins and cron jobs'
        'kernel:Kernel hardening sysctl parameters'
        'auditd:Audit daemon, NTP and rootkit scanners'
        'images:Container image age, pinning and available updates'
        'cve:Known CVEs in host packages and container images (trivy)'
        'pentest:Active local self-pentest (ports, banners, HTTP)'
        'pentest_external:Active external endpoint pentest (requires --target)'
    )

    _arguments -s \
        '--html[Generate HTML report]' \
        '--txt[Generate plain-text report]' \
        '--json[Generate JSON report]' \
        '--remediate[Generate remediation script]' \
        '--sarif[Generate SARIF 2.1.0 report]' \
        '--strict[Exit non-zero on WARN too]' \
        '--wan[Also scan WAN/public IP]' \
        '--target=[Endpoint for pentest_external]:target:' \
        '--resolve-to=[Force probes at this IP]:ip:' \
        '--remote-pentest=[Run pentest_external from remote host]:host:_hosts' \
        '--history=[Save run to history dir]:dir:_files -/' \
        '--dashboard=[Build static dashboard from history and exit]:file:_files' \
        '(-p --parallel)'{-p,--parallel}'[Run modules in parallel]' \
        '--baseline[Save current run as baseline]' \
        '--diff[Compare to saved baseline]' \
        '(-q --quiet)'{-q,--quiet}'[Suppress INFO output]' \
        '--no-color[Disable ANSI colors]' \
        '(-v --version)'{-v,--version}'[Print version]' \
        '(-h --help)'{-h,--help}'[Show help]' \
        '--output=[Override output file path]:file:_files' \
        '--config=[Load config from file]:file:_files' \
        '*--check=[Run specific module]:module:(($modules))' \
        '--remote=[Run on remote host via SSH]:host:_hosts' \
        '--schedule=[Install cron job]:frequency:(daily weekly monthly)'
}

_anzen
