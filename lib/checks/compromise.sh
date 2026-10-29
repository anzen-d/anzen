#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# checks/compromise.sh — Indicators of compromise
#
# Hardening checks ask "could someone get in?"; these ask "is someone in?".
# Few, high-signal checks: a preloaded library, programs running from temp
# dirs or memory, cryptominers, kernel modules with no file on disk.

# Typical cryptominer process names and mining-pool ports
_IOC_MINERS='^(xmrig|xmr-stak|kdevtmpfsi|kinsing|minerd|cpuminer|nbminer|t-rex|lolminer|phoenixminer|ethminer|xmrig-notls)$'
_IOC_POOL_PORTS=' 3333 4444 5555 7777 14433 14444 45560 45700 '

run_compromise_check() {
    section "Indicators of Compromise"
    # Overridable for tests
    local preload="${ANZEN_LD_SO_PRELOAD:-/etc/ld.so.preload}" proc="${ANZEN_PROC:-/proc}"

    # 1. /etc/ld.so.preload: every program loads these libraries first
    local libs
    libs=$(grep -vE '^[[:space:]]*(#|$)' "$preload" 2>/dev/null | tr '\n' ' ')
    if [ -n "$libs" ]; then
        fail "$preload preloads into every program: $libs— a common rootkit technique"
        remedy "ls -l $libs; dpkg -S $libs || rpm -qf $libs  # remove $preload unless you know why it exists"
    else
        ok "No libraries preloaded via $preload"
    fi

    if [ "$EUID" -ne 0 ] && [ -z "${ANZEN_PROC:-}" ]; then
        info "Process checks need root — skipped"
        return 0
    fi

    # 2. Processes running from temp dirs or from memory (fileless)
    local d pid exe comm tmp_hits=0 restart=() miners=0
    for d in "$proc"/[0-9]*; do
        pid=${d##*/}
        exe=$(readlink "$d/exe" 2>/dev/null) || continue
        comm=$(cat "$d/comm" 2>/dev/null)
        case $exe in
            /tmp/*|/var/tmp/*|/dev/shm/*)
                fail "Process running from a temp dir: $comm (pid $pid) $exe"
                remedy "ls -l $d/exe; cat $d/cmdline | tr '\\0' ' '  # inspect, then kill $pid and find how it got there"
                tmp_hits=$((tmp_hits + 1)) ;;
            /memfd:*)
                # runc re-executes itself from a memfd while starting containers
                case $exe in /memfd:runc*) ;; *)
                    warn "Process running from memory (no file on disk): $comm (pid $pid) $exe"
                    remedy "cat $d/cmdline | tr '\\0' ' '; ls -l $d/fd  # fileless malware runs this way"
                    tmp_hits=$((tmp_hits + 1)) ;;
                esac ;;
            *" (deleted)")
                # Usually an update replaced the binary of a running program
                restart+=("$comm") ;;
        esac
        if [[ "$comm" =~ $_IOC_MINERS ]]; then
            fail "Cryptominer process: $comm (pid $pid) $exe"
            remedy "kill $pid; then find the cron job, unit or container that starts it"
            miners=$((miners + 1))
        fi
    done
    [ "$tmp_hits" -eq 0 ] && ok "No processes running from temp dirs or memory"
    if [ "${#restart[@]}" -gt 0 ]; then
        info "${#restart[@]} process(es) still run a binary an update replaced — restart them: $(printf '%s\n' "${restart[@]}" | sort -u | head -10 | tr '\n' ' ')"
    fi

    # 3. Established connections to typical mining-pool ports
    if command -v ss &>/dev/null && [ -z "${ANZEN_PROC:-}" ]; then
        # "state established" output: Recv-Q Send-Q Local Peer Process
        local line peer rport
        while IFS= read -r line; do
            peer=$(awk '{ print $4 }' <<< "$line"); rport=${peer##*:}
            [[ "$_IOC_POOL_PORTS" == *" $rport "* ]] || continue
            # A local service on one of these ports is not a pool
            case $peer in 127.*|"[::1]"*|"[::ffff:127."*) continue ;; esac
            warn "Outbound connection to a typical mining-pool port: $peer $(grep -o 'users:(("[^"]*"' <<< "$line" | cut -d'"' -f2)"
            remedy "ss -tnp state established | grep ':$rport'  # check what this process is and why it connects there"
            miners=$((miners + 1))
        done < <(ss -Htnp state established 2>/dev/null)
    fi
    [ "$miners" -eq 0 ] && ok "No cryptominer processes or mining-pool connections"

    # 4. Kernel modules loaded without a module file (a rootkit loads its
    # module and deletes the file). Not inside containers: they see the host's
    # modules but not its /lib/modules
    if command -v modinfo &>/dev/null && [ -r "$proc/modules" ] \
       && [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
        local m missing=()
        while read -r m _; do
            modinfo -F filename "$m" &>/dev/null || missing+=("$m")
        done < "$proc/modules"
        if [ "${#missing[@]}" -gt 0 ]; then
            warn "Loaded kernel module(s) with no file on disk: ${missing[*]} — rootkit, or a module whose file was removed"
            remedy "cat /sys/module/${missing[0]}/taint 2>/dev/null; dmesg | grep -i ${missing[0]}  # verify where it came from"
        else
            ok "Every loaded kernel module has a file on disk"
        fi
    fi
}
