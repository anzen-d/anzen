#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# checks/drift.sh — What changed since the last full run (persistence)
#
# An attacker who gets in leaves something behind: an SSH key, a cron job, a
# systemd unit, a SUID binary, an account, a listening port. Hardening checks
# do not notice those; comparing with the previous run does. The state is a
# TSV, "CATEGORY<TAB>KEY<TAB>VALUE", in DRIFT_STATE_DIR (root only, mode 600).
# Partial (--check) runs compare but do not update it, like history.
#
# Limitation: root on this host can also edit the state. Fleet mode keeps
# each host's state on that host; copy it off-host if that matters.

_drift_sha() { sha256sum 2>/dev/null | cut -c1-16; }

# _drift_collect — print the current state, sorted
_drift_collect() {
    local f u uid shell home line

    # Accounts that can log in, and every UID 0 account
    while IFS=: read -r u _ uid _ _ home shell; do
        [ "$uid" = 0 ] && printf 'uid0\t%s\t-\n' "$u"
        case "$shell" in */nologin|*/false|"") continue ;; esac
        printf 'user\t%s\t%s\n' "$u" "$uid:$shell"
        # SSH keys: one entry per key line (options or key changed = new entry)
        for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
            [ -f "$f" ] || continue
            while IFS= read -r line; do
                case "$line" in ""|\#*) continue ;; esac
                # Shown as "type comment"; options and the key itself are hashed
                printf 'authkey\t%s %s\t%s\n' "$u" "$(printf '%s' "$line" | _drift_sha)" \
                    "$(awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^(ssh-|ecdsa-|sk-)/) { print $i, $(i + 2); exit } }' <<< "$line")"
            done < "$f"
        done
    done < /etc/passwd

    # Files whose content matters: cron, sudoers, ld.so.preload, systemd units
    # in /etc (packages install theirs under /usr/lib)
    for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* \
             /etc/cron.monthly/* /var/spool/cron/crontabs/* /var/spool/cron/*; do
        [ -f "$f" ] && printf 'cron\t%s\t%s\n' "$f" "$(_drift_sha < "$f")"
    done
    for f in /etc/sudoers /etc/sudoers.d/*; do
        [ -f "$f" ] && printf 'sudoers\t%s\t%s\n' "$f" "$(_drift_sha < "$f")"
    done
    [ -f /etc/ld.so.preload ] && printf 'preload\t/etc/ld.so.preload\t%s\n' "$(_drift_sha < /etc/ld.so.preload)"
    while IFS= read -r f; do
        # An enabled unit is a symlink: its target is what changes
        if [ -L "$f" ]; then printf 'unit\t%s\t-> %s\n' "$f" "$(readlink "$f")"
        else printf 'unit\t%s\t%s\n' "$f" "$(_drift_sha < "$f")"; fi
    done < <(find /etc/systemd/system /root/.config/systemd/user /home/*/.config/systemd/user \
                 \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' \) \
                 \( -type f -o -type l \) 2>/dev/null)

    # SUID/SGID binaries in the system and temp dirs (not data trees: the
    # files module walks everything; this stays fast)
    while IFS= read -r f; do
        printf 'suid\t%s\t%s\n' "$f" "$(_drift_sha < "$f")"
    done < <(find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /usr/lib /usr/libexec \
                 /tmp /var/tmp /dev/shm -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)

    # Listening sockets, keyed by scope rather than address: a daemon bound
    # to every interface IP (nmbd) would change with each Docker network.
    # Ephemeral ports on loopback and in UDP belong to local helpers/clients
    if command -v ss &>/dev/null; then
        ss -Hltunp 2>/dev/null | awk '{
            n = split($5, a, ":"); port = a[n]; addr = substr($5, 1, length($5) - length(port) - 1)
            if (addr ~ /^(\*|0\.0\.0\.0|\[::\])$/) scope = "all"
            else if (addr ~ /^(127\.|\[::1\]|\[::ffff:127\.)/) scope = "local"
            else scope = "ip"
            if (port >= 32768 && ($1 == "udp" || scope == "local")) next
            proc = "?"; if (match($0, /users:\(\("[^"]+"/)) proc = substr($0, RSTART + 9, RLENGTH - 10)
            printf "port\t%s %s:%s\t%s\n", $1, scope, port, proc }' \
            | sort -u | awk -F'\t' '
                # One line per port; several processes can share one (mDNS)
                $2 == k { v = v "," $3; next }
                { if (k != "") print "port\t" k "\t" v; k = $2; v = $3 }
                END { if (k != "") print "port\t" k "\t" v }'
    fi
}

# _drift_compare OLD NEW — findings for what is new or changed in NEW
_drift_compare() {
    local old=$1 new=$2 cat key val prev n=0 removed ku
    local -A before=()
    while IFS=$'\t' read -r cat key val; do before["$cat"$'\t'"$key"]=$val; done < "$old"
    while IFS=$'\t' read -r cat key val; do
        prev=${before["$cat"$'\t'"$key"]-}
        if [ -z "${before["$cat"$'\t'"$key"]+x}" ]; then
            n=$((n + 1))
            case $cat in
                uid0)    fail "New UID 0 account: $key"
                         remedy "grep -n $(_q "^$key:") /etc/passwd  # remove it unless you created it" ;;
                user)    warn "New login account: $key (uid:shell $val)"
                         remedy "lastlog -u $(_q "$key")  # who created it? check the auth log" ;;
                authkey) ku=${key%% *}
                         if [ "$ku" = root ]; then fail "New SSH key for root: $val"; else warn "New SSH key for $ku: $val"; fi
                         remedy "grep -n -- $(_q "${val##* }") ~$(_q "$ku")/.ssh/authorized_keys*  # remove it unless you added it" ;;
                cron)    warn "New cron file: $key"; remedy "cat $(_q "$key")" ;;
                sudoers) warn "New sudoers file: $key"; remedy "cat $(_q "$key")" ;;
                preload) fail "/etc/ld.so.preload created — every program now loads: $(grep -v '^#' /etc/ld.so.preload 2>/dev/null | tr '\n' ' ')"
                         remedy "cat /etc/ld.so.preload  # a rootkit technique; remove the file unless you know why it exists" ;;
                unit)    warn "New systemd unit: $key"; remedy "systemctl cat $(_q "${key##*/}")" ;;
                suid)    case $key in
                             /tmp/*|/var/tmp/*|/dev/shm/*) fail "New SUID/SGID binary in a temp dir: $key" ;;
                             *) warn "New SUID/SGID binary: $key" ;;
                         esac
                         remedy "ls -l $(_q "$key"); dpkg -S $(_q "$key") || rpm -qf $(_q "$key")" ;;
                port)    warn "New listening port: $key ($val)"; remedy "ss -ltnup | grep ':${key##*:} '" ;;
            esac
        elif [ "$prev" != "$val" ]; then
            n=$((n + 1))
            case $cat in
                cron|sudoers|unit) warn "Changed since last run: $key"; remedy "cat $(_q "$key")" ;;
                preload)           fail "/etc/ld.so.preload changed"; remedy "cat /etc/ld.so.preload" ;;
                user)              warn "Account changed: $key (now uid:shell $val)" ;;
                # Package updates replace SUID binaries routinely
                suid)              info "SUID/SGID binary updated: $key" ;;
            esac
        fi
    done < "$new"
    removed=$(awk -F'\t' 'NR == FNR { k[$1 FS $2]; next } !(($1 FS $2) in k)' "$new" "$old" | wc -l)
    [ "$removed" -gt 0 ] && info "$removed item(s) removed since last run (accounts, keys, units, ports…)"
    _DRIFT_CHANGES=$n
}

run_drift_check() {
    section "Changes Since Last Run"
    if [ "$EUID" -ne 0 ]; then
        info "Needs root (other users' SSH keys and crontabs) — skipped"
        return 0
    fi
    local dir="${DRIFT_STATE_DIR:-/var/lib/anzen/state}" state new when
    state="$dir/drift.tsv"
    new=$(umask 077; mktemp)
    _drift_collect | sort -u > "$new"

    if [ ! -s "$state" ]; then
        info "Baseline recorded: $(wc -l < "$new") accounts, keys, units, SUID binaries and ports — changes are reported from the next run"
    else
        when=$(date -r "$state" '+%F %H:%M' 2>/dev/null)
        _DRIFT_CHANGES=0
        _drift_compare "$state" "$new"
        [ "$_DRIFT_CHANGES" -eq 0 ] && \
            ok "No new accounts, SSH keys, cron jobs, units, SUID binaries or listening ports since $when"
    fi

    # Partial runs compare only, so a manual --check=drift does not swallow the
    # changes the next full run should report (a first baseline is saved anyway)
    if [ ! -s "$state" ] || ! ${PARTIAL_RUN:-false}; then
        (umask 077; mkdir -p "$dir") && mv "$new" "$state" && chmod 600 "$state"
    fi
    rm -f "$new"
}
