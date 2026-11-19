#!/usr/bin/env bats
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# tests/test_remediate.bats — Tests for lib/remediate.sh

setup() {
    ANZEN_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    FINDINGS_FILE="$(mktemp)"
    NO_COLOR=true QUIET=true
    export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/output.sh"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/remediate.sh"
    REMEDIATE_OUT="$(mktemp)"
}

teardown() {
    rm -f "$FINDINGS_FILE" "${FINDINGS_FILE}.tmp" "$REMEDIATE_OUT"
}

@test "generate_remediate_script() creates executable script" {
    fail "issue"; remedy "apt-get install fix"
    generate_remediate_script "$REMEDIATE_OUT"
    [ -f "$REMEDIATE_OUT" ]
    [ -x "$REMEDIATE_OUT" ]
}

@test "generate_remediate_script() includes shebang" {
    fail "issue"; remedy "echo fix"
    generate_remediate_script "$REMEDIATE_OUT"
    run head -1 "$REMEDIATE_OUT"
    [[ "$output" == "#!/bin/bash" ]]
}

@test "generate_remediate_script(): a failing command does not stop the rest" {
    fail 'first "$(x)"'; remedy "false  # an inspection that finds nothing"
    fail "advice"; remedy "# edit the config by hand"
    fail "second"; remedy "echo second-ran"
    generate_remediate_script "$REMEDIATE_OUT"
    bash -n "$REMEDIATE_OUT"
    run bash "$REMEDIATE_OUT"
    [ "$status" -eq 1 ]
    [[ "$output" == *'FAILED: first "$(x)"'* ]]
    [[ "$output" == *second-ran* ]]
    [[ "$output" == *"1 command(s) failed"* ]]
}

@test "generate_remediate_script() includes remedy command" {
    fail "issue"; remedy "apt-get install -y nginx"
    generate_remediate_script "$REMEDIATE_OUT"
    run grep "apt-get install -y nginx" "$REMEDIATE_OUT"
    [ "$status" -eq 0 ]
}

@test "generate_remediate_script() skips OK findings" {
    ok "fine"; fail "broken"; remedy "fix it"
    generate_remediate_script "$REMEDIATE_OUT"
    # only the FAIL remedy should appear, not the ok message
    run grep "fine" "$REMEDIATE_OUT"
    [ "$status" -ne 0 ]
}

@test "generate_remediate_script() skips findings without remedy" {
    fail "no remedy here"
    generate_remediate_script "$REMEDIATE_OUT"
    run grep "no remedy here" "$REMEDIATE_OUT"
    [ "$status" -ne 0 ]
    run bash "$REMEDIATE_OUT"
    [ "$status" -eq 0 ]
}

@test "generate_remediate_script() returns count of remedies" {
    fail "a"; remedy "fix a"
    fail "b"; remedy "fix b"
    ok "c"
    run bash -c "
        ANZEN_DIR='$ANZEN_DIR'
        FINDINGS_FILE='$FINDINGS_FILE'
        source '$ANZEN_DIR/lib/output.sh'
        source '$ANZEN_DIR/lib/remediate.sh'
        generate_remediate_script '$REMEDIATE_OUT'
    "
    # count written to stdout
    [ "$output" = "2" ]
}

@test "generate_remediate_script() groups by section" {
    section "SSH"
    fail "ssh issue"; remedy "systemctl reload sshd"
    section "Kernel"
    fail "kernel issue"; remedy "sysctl -w net.ipv4.tcp_syncookies=1"
    generate_remediate_script "$REMEDIATE_OUT"
    run grep "SSH" "$REMEDIATE_OUT"
    [ "$status" -eq 0 ]
    run grep "Kernel" "$REMEDIATE_OUT"
    [ "$status" -eq 0 ]
}

@test "generate_remediate_script() handles special chars in remedy" {
    fail "issue"
    remedy "sed -i \"s/#PermitRootLogin yes/PermitRootLogin no/\" /etc/ssh/sshd_config"
    generate_remediate_script "$REMEDIATE_OUT"
    run grep "sshd_config" "$REMEDIATE_OUT"
    [ "$status" -eq 0 ]
}

@test "remediate: a hostile file name stays one argument (_q)" {
    local name="/srv/x'; touch $BATS_TEST_TMPDIR/pwned #\$(id)"
    fail "World-writable file: $name"; remedy "chmod o-w $(_q "$name")"
    generate_remediate_script "$REMEDIATE_OUT" >/dev/null
    # Run the generated script with chmod stubbed to print its last argument
    run bash -c "chmod() { printf '%s\n' \"\${@: -1}\"; }; export -f chmod; bash $REMEDIATE_OUT"
    [ "$status" -eq 0 ]
    [ "${lines[0]}" = "$name" ]
    [ ! -e "$BATS_TEST_TMPDIR/pwned" ]
}

@test "remediate: no remedy contains a literal \\n (remedies run verbatim, one line each)" {
    run grep -nE 'remedy "[^"]*\\n' "$ANZEN_DIR"/lib/checks/*.sh
    [ "$status" -ne 0 ]
}

# ── Steps that can lock the admin out are never run ──────────────────────────

@test "remediate: reboot, firewall, kill and SSH login changes become MANUAL comments" {
    fail "reboot needed";  remedy "reboot"
    fail "selinux off";    remedy "sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config && reboot"
    fail "ufw inactive";   remedy "ufw allow 22/tcp && ufw enable  # the allow rule keeps SSH reachable"
    fail "iptables open";  remedy "iptables -A INPUT -p tcp --dport 22 -j ACCEPT && iptables -P INPUT DROP"
    fail "firewalld off";  remedy "systemctl enable --now firewalld"
    fail "miner";          remedy "kill 4242  # then find the cron job"
    fail "ssh port";       remedy "sed -i 's/^#*Port.*/Port 2222/' /etc/ssh/sshd_config && sshd -t"
    fail "ssh passwords";  remedy "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sshd -t"
    fail "ssh allowusers"; remedy "sed -i '1i AllowUsers admin' /etc/ssh/sshd_config && sshd -t"
    fail "harmless";       remedy "echo harmless-ran"
    generate_remediate_script "$REMEDIATE_OUT" >/dev/null
    bash -n "$REMEDIATE_OUT"
    # Every risky command is stubbed to leave a mark: none may be called
    run bash -c "
        mark() { echo \"RAN \$*\" >> '$BATS_TEST_TMPDIR/ran'; }
        for c in reboot ufw iptables systemctl kill sed sshd; do eval \"\$c() { mark \$c \\\"\\\$@\\\"; }\"; export -f \$c; done
        export -f mark
        bash '$REMEDIATE_OUT'"
    [ "$status" -eq 0 ]
    [ ! -e "$BATS_TEST_TMPDIR/ran" ]
    [[ "$output" == *harmless-ran* ]]
    [[ "$output" == *"9 step(s) marked MANUAL were not run"* ]]
    [ "$(grep -c '^# MANUAL: ' "$REMEDIATE_OUT")" -eq 9 ]
}

@test "remediate: ordinary commands are not held back as MANUAL" {
    fail "a"; remedy "chmod 600 /etc/ssh/ssh_host_rsa_key"
    fail "b"; remedy "sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config && sshd -t"
    fail "c"; remedy "sysctl -w net.ipv4.tcp_syncookies=1 && echo 'net.ipv4.tcp_syncookies=1' >> /etc/sysctl.d/99-anzen-hardening.conf"
    fail "d"; remedy "ls -l /proc/1/exe  # inspect, then kill 1 and reboot"
    fail "e"; remedy "apt-get upgrade -y"
    generate_remediate_script "$REMEDIATE_OUT" >/dev/null
    run grep -c '^# MANUAL' "$REMEDIATE_OUT"
    [ "$output" = "0" ]
}

@test "remediate: no remedy in the checks breaks the syntax of the script" {
    # Every literal remedy line of every check, with variables left as text
    local n=0 line
    while IFS= read -r line; do
        fail "finding $n"; remedy "$line"; n=$((n + 1))
    done < <(grep -rhoE 'remedy "[^"$]+"' "$ANZEN_DIR"/lib/checks "$ANZEN_DIR"/plugins \
             | sed -e 's/^remedy "//' -e 's/"$//')
    [ "$n" -gt 20 ]
    generate_remediate_script "$REMEDIATE_OUT" >/dev/null
    bash -n "$REMEDIATE_OUT"
}

@test "remediate: an edited /etc file is copied aside first" {
    fail "x"; remedy "sed -i 's/a/b/' /etc/anzen-test.conf && echo edited"
    generate_remediate_script "$REMEDIATE_OUT" >/dev/null
    grep -qx '_anzen_bak /etc/anzen-test.conf' "$REMEDIATE_OUT"
    # _anzen_bak keeps the path under the backup directory, once
    local fn
    fn=$(sed -n '/^_anzen_bak() {/,/^}/p' "$REMEDIATE_OUT")
    printf 'old\n' > "$BATS_TEST_TMPDIR/f.conf"
    run bash -c "_bak_dir='$BATS_TEST_TMPDIR/bak'; $fn
        _anzen_bak '$BATS_TEST_TMPDIR/f.conf'; echo new > '$BATS_TEST_TMPDIR/f.conf'
        _anzen_bak '$BATS_TEST_TMPDIR/f.conf'; cat '$BATS_TEST_TMPDIR/bak$BATS_TEST_TMPDIR/f.conf'"
    [ "$status" -eq 0 ]
    [ "$output" = "old" ]
}

@test "remediate: sshd_config that sshd rejects is put back from the copy" {
    fail "x"; remedy "sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config"
    generate_remediate_script "$REMEDIATE_OUT" >/dev/null
    grep -qx '_anzen_sshd_check' "$REMEDIATE_OUT"
    local fn
    fn=$(sed -n '/^_anzen_sshd_check() {/,/^}/p' "$REMEDIATE_OUT")
    mkdir -p "$BATS_TEST_TMPDIR/bak/etc/ssh"
    echo good > "$BATS_TEST_TMPDIR/bak/etc/ssh/sshd_config"
    run bash -c "_bak_dir='$BATS_TEST_TMPDIR/bak'; sshd() { return 1; }
        cp() { echo \"cp \$*\"; }; $fn
        _anzen_sshd_check"
    [[ "$output" == *"cp -p $BATS_TEST_TMPDIR/bak/etc/ssh/sshd_config /etc/ssh/sshd_config"* ]]
    [[ "$output" == *"backup restored"* ]]
}

@test "remediate: the script is readable by its owner only" {
    fail "issue"; remedy "echo fix"
    generate_remediate_script "$REMEDIATE_OUT" >/dev/null
    [ "$(stat -c %a "$REMEDIATE_OUT")" = "700" ]
}

@test "remediate: a newline in a value cannot start a new command" {
    # A file name can hold a newline; in a "# note" it would end the comment
    local name=$'/etc/ssl/x.pem\ntouch '"$BATS_TEST_TMPDIR/pwned"
    fail "cert expires"; remedy "echo renew  # expires soon: $name"
    [ "$(wc -l < "$FINDINGS_FILE")" -eq 1 ]
    generate_remediate_script "$REMEDIATE_OUT" >/dev/null
    run bash "$REMEDIATE_OUT"
    [ "$status" -eq 0 ]
    [ ! -e "$BATS_TEST_TMPDIR/pwned" ]
}

@test "remediate: every value a check puts into a command goes through _q" {
    # A variable may stand after the "  # " note, inside $(_q ...), or be one
    # of the names below, which the check itself sets from fixed values
    run python3 - "$ANZEN_DIR" <<'PY'
import glob, re, sys
known = r'\$\{?(expected|rt|ssh_port|port|svc|_SYSCTL_CONF|key|fix|bl_cmd|upg|_qd|qlibs|rport|_u|_suite|found_dev|found_recon|d|pid)\b[^ "]*|\$\((_sshd_reload|printf )[^)]*\)'
bad = []
files = glob.glob(sys.argv[1] + '/lib/checks/**/*.sh', recursive=True) + glob.glob(sys.argv[1] + '/plugins/*.sh')
for f in files:
    for n, line in enumerate(open(f), 1):
        m = re.search(r'remedy "([^#].*)"', line)
        if not m:
            continue
        cmd = m.group(1).split('  # ')[0]
        cmd = re.sub(r'\$\(_q "[^"]*"\)', '', cmd)
        cmd = re.sub(known, '', cmd)
        if '$' in cmd:
            bad.append('%s:%d: %s' % (f, n, cmd.strip()))
print('\n'.join(bad))
sys.exit(1 if bad else 0)
PY
    echo "$output"
    [ "$status" -eq 0 ]
}
