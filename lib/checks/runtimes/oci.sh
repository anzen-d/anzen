#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# runtimes/oci.sh — Checks for OCI-compatible runtimes: Docker, Podman, nerdctl

_oci_daemon_checks() {
    local rt=$1
    case "$rt" in
    docker)
        if [ -S /var/run/docker.sock ]; then
            local sm sg
            sm=$(stat -c "%a" /var/run/docker.sock 2>/dev/null)
            sg=$(stat -c "%G" /var/run/docker.sock 2>/dev/null)
            [ $((8#${sm:-0} & 8#002)) -ne 0 ] \
                && { fail "Docker socket world-writable  [CIS 1.2.1]"
                     remedy "chmod 660 /var/run/docker.sock"; } \
                || ok "Docker socket permissions OK ($sm, group: $sg)"
        fi

        local dj="/etc/docker/daemon.json"
        if [ -f "$dj" ]; then
            grep -q '"no-new-privileges".*true' "$dj" 2>/dev/null \
                && ok "Docker: no-new-privileges=true  [CIS 2.18]" \
                || { warn "Docker: no-new-privileges not set globally  [CIS 2.18]"
                     remedy "# Add to $dj: \"no-new-privileges\": true"; }
            grep -q '"userns-remap"' "$dj" 2>/dev/null \
                && ok "Docker: user namespace remapping configured  [CIS 2.8]" \
                || { warn "Docker: userns-remap not configured  [CIS 2.8]"
                     remedy "# Add to $dj: \"userns-remap\": \"default\""; }
            grep -q '"live-restore".*true' "$dj" 2>/dev/null \
                && ok "Docker: live-restore enabled" \
                || { warn "Docker: live-restore not enabled"
                     remedy "# Add to $dj: \"live-restore\": true"; }
        else
            info "No /etc/docker/daemon.json found"
        fi

        [ "${DOCKER_CONTENT_TRUST:-0}" = "1" ] \
            && ok "DOCKER_CONTENT_TRUST=1  [CIS 4.5]" \
            || { warn "DOCKER_CONTENT_TRUST not set  [CIS 4.5]"
                 remedy "export DOCKER_CONTENT_TRUST=1  # add to /etc/environment"; }
        ;;

    podman)
        local uid; uid=$(id -u 2>/dev/null)
        [ "$uid" -eq 0 ] \
            && { warn "Podman running as root — consider rootless mode"
                 remedy "# Run Podman as a non-root user for better isolation"; } \
            || ok "Podman running rootless (uid=$uid)"

        local sock="/run/user/${uid}/podman/podman.sock"
        if [ -S "$sock" ]; then
            local sm; sm=$(stat -c "%a" "$sock" 2>/dev/null)
            [ $((8#${sm:-0} & 8#002)) -ne 0 ] \
                && { fail "Podman socket world-writable: $sock"
                     remedy "chmod 660 '$sock'"; } \
                || ok "Podman socket permissions OK"
        fi
        ;;

    nerdctl)
        local sock="/run/containerd/containerd.sock"
        if [ -S "$sock" ]; then
            local sm; sm=$(stat -c "%a" "$sock" 2>/dev/null)
            [ $((8#${sm:-0} & 8#002)) -ne 0 ] \
                && { fail "containerd socket world-writable"
                     remedy "chmod 660 $sock"; } \
                || ok "containerd socket permissions OK"
        fi
        local cfg="/etc/containerd/config.toml"
        [ -f "$cfg" ] && grep -q 'SystemdCgroup.*=.*true' "$cfg" 2>/dev/null \
            && ok "containerd: SystemdCgroup enabled" \
            || info "containerd: SystemdCgroup not confirmed in $cfg"
        ;;
    esac
}

_oci_container_checks() {
    local rt=$1
    local containers
    containers=$("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null) || return
    [ -z "$containers" ] && { info "[$rt] No running containers"; return; }

    local priv=0 root=0 hostnet=0 mounts=0 caps=0 ns=0 envsec=0

    # Docker publishes ports with its own iptables rules, ahead of ufw and
    # firewalld: "ufw deny 8080" does not stop a published 8080. Rules in the
    # DOCKER-USER chain are the supported way to filter them
    local fw="" docker_user=false
    if [ "$rt" = "docker" ]; then
        ufw status 2>/dev/null | grep -q '^Status: active' && fw=ufw
        [ -z "$fw" ] && systemctl is-active --quiet firewalld 2>/dev/null && fw=firewalld
        [ "$(iptables -S DOCKER-USER 2>/dev/null | grep -cv -- '-N DOCKER-USER\|-j RETURN$')" -gt 0 ] && docker_user=true
    fi

    while IFS=' ' read -r cid cname; do
        [ -z "$cid" ] && continue

        local is_priv
        is_priv=$("$rt" inspect "$cid" --format '{{.HostConfig.Privileged}}' 2>/dev/null)
        [ "$is_priv" = "true" ] && {
            fail "[$rt] Privileged container: $cname  [CIS 5.4]"
            remedy "# Remove --privileged from $cname; use --cap-add for specific caps"
            priv=$((priv+1)); }

        local cuser
        cuser=$("$rt" inspect "$cid" --format '{{.Config.User}}' 2>/dev/null)
        { [ -z "$cuser" ] || [ "$cuser" = "root" ] || [ "$cuser" = "0" ]; } && {
            warn "[$rt] Running as root: $cname  [CIS 5.1]"
            remedy "# Add USER <nonroot> in the Dockerfile for $cname"
            root=$((root+1)); }

        local netmode
        netmode=$("$rt" inspect "$cid" --format '{{.HostConfig.NetworkMode}}' 2>/dev/null)
        [ "$netmode" = "host" ] && {
            fail "[$rt] --network=host: $cname  [CIS 5.9]"
            remedy "# Use a bridge network instead of --network=host in $cname"
            hostnet=$((hostnet+1)); }

        local vols
        vols=$("$rt" inspect "$cid" --format '{{range .Mounts}}{{.Source}}|{{end}}' 2>/dev/null)
        IFS='|' read -ra volarr <<< "$vols"
        for vol in "${volarr[@]}"; do
            vol="${vol%/}"
            case "$vol" in
                ""|/) ;;
                /etc|/proc|/sys|/var/run/docker.sock|/run/docker.sock|/run/podman|/root)
                    fail "[$rt] $cname mounts sensitive path: $vol  [CIS 5.5]"
                    remedy "# Remove or restrict the $vol mount in $cname"
                    mounts=$((mounts+1)) ;;
            esac
        done

        # One inspect for the rest: capabilities, namespaces, security options,
        # environment and published ports, one "key=value" per line
        local cfg line cap bad_caps="" warn_caps="" sec_env="" pubs=""
        cfg=$("$rt" inspect "$cid" --format '{{range .HostConfig.CapAdd}}cap={{.}}{{println}}{{end}}pid={{.HostConfig.PidMode}}{{println}}ipc={{.HostConfig.IpcMode}}{{println}}{{range .HostConfig.SecurityOpt}}sec={{.}}{{println}}{{end}}{{range .Config.Env}}env={{.}}{{println}}{{end}}{{range $p, $b := .NetworkSettings.Ports}}{{range $b}}port={{.HostIp}} {{$p}}{{println}}{{end}}{{end}}' 2>/dev/null)
        while IFS= read -r line; do
            case $line in
                cap=*)
                    cap=${line#cap=}; cap=${cap#CAP_}
                    case $cap in
                        ALL|SYS_ADMIN|SYS_MODULE|SYS_RAWIO|SYS_PTRACE|DAC_READ_SEARCH) bad_caps+=" $cap" ;;
                        NET_ADMIN|NET_RAW|SYS_TIME|BPF|PERFMON|SYS_BOOT) warn_caps+=" $cap" ;;
                    esac ;;
                pid=host)
                    fail "[$rt] $cname shares the host PID namespace (pid: host)  [CIS 5.15]"
                    remedy "# Remove pid: host from $cname"; ns=$((ns+1)) ;;
                ipc=host)
                    warn "[$rt] $cname shares the host IPC namespace (ipc: host)  [CIS 5.16]"
                    remedy "# Remove ipc: host from $cname"; ns=$((ns+1)) ;;
                sec=*seccomp*unconfined*)
                    warn "[$rt] $cname runs without a seccomp profile  [CIS 5.21]"
                    remedy "# Remove security_opt seccomp=unconfined from $cname"; ns=$((ns+1)) ;;
                sec=*apparmor*unconfined*)
                    warn "[$rt] $cname runs without AppArmor confinement  [CIS 5.1]"
                    remedy "# Remove security_opt apparmor=unconfined from $cname"; ns=$((ns+1)) ;;
                env=*)
                    # Names only, never values. *_FILE variables point at secrets
                    # files, which is the right way
                    line=${line#env=}
                    # Whole name segments: TOKEN, not TOKENIZERS_PARALLELISM
                    [[ "${line%%=*}" =~ (^|_)(PASSWORD|PASSWD|PASS|SECRET|TOKEN|APIKEY|API_KEY|PRIVATE_KEY|ACCESS_KEY|SECRET_KEY)(_|$) ]] || continue
                    [[ "${line%%=*}" == *_FILE ]] && continue
                    [ -n "${line#*=}" ] && sec_env+=" ${line%%=*}" ;;
                port=*)
                    line=${line#port=}
                    case ${line%% *} in ""|0.0.0.0|::) pubs+=" ${line#* }" ;; esac ;;
            esac
        done <<< "$cfg"
        if [ -n "$bad_caps" ]; then
            fail "[$rt] $cname adds capabilities that allow escaping to the host:$bad_caps  [CIS 5.3]"
            remedy "# Remove cap_add$bad_caps from $cname unless it truly needs them"; caps=$((caps+1))
        elif [ -n "$warn_caps" ]; then
            warn "[$rt] $cname adds powerful capabilities:$warn_caps  [CIS 5.3]"
            remedy "# Keep only the capabilities $cname needs (VPN containers need NET_ADMIN)"; caps=$((caps+1))
        fi
        if [ -n "$sec_env" ]; then
            warn "[$rt] Secrets in environment variables of $cname:$sec_env (readable via docker inspect)"
            remedy "# Use secrets files (*_FILE variables, docker secrets) for $cname"; envsec=$((envsec+1))
        fi
        if [ -n "$pubs" ]; then
            pubs=$(tr ' ' '\n' <<< "$pubs" | sort -u | grep . | tr '\n' ' ')
            if [ -n "$fw" ] && ! $docker_user; then
                warn "[$rt] $cname publishes ${pubs% } on all interfaces — Docker's rules bypass $fw"
                remedy "# Bind to 127.0.0.1 (\"127.0.0.1:PORT:PORT\") if only a local proxy uses it, or filter in the DOCKER-USER chain"
            else
                info "[$rt] $cname publishes ${pubs% } on all interfaces"
            fi
        fi

        if [ "$rt" = "docker" ] || [ "$rt" = "nerdctl" ]; then
            local memlimit
            memlimit=$("$rt" inspect "$cid" --format '{{.HostConfig.Memory}}' 2>/dev/null)
            [ "${memlimit:-0}" -eq 0 ] && {
                warn "[$rt] No memory limit: $cname  [CIS 5.10]"
                remedy "# Add --memory=256m (or appropriate) to $cname"; }
        fi

    done <<< "$containers"

    [ "$priv"    -eq 0 ] && ok "[$rt] No privileged containers"
    [ "$root"    -eq 0 ] && ok "[$rt] No containers running as root"
    [ "$hostnet" -eq 0 ] && ok "[$rt] No containers on host network"
    [ "$mounts"  -eq 0 ] && ok "[$rt] No sensitive host paths mounted"
    [ "$caps"    -eq 0 ] && ok "[$rt] No containers with added dangerous capabilities"
    [ "$ns"      -eq 0 ] && ok "[$rt] No host PID/IPC namespaces, seccomp and AppArmor active"
    [ "$envsec"  -eq 0 ] && ok "[$rt] No secrets in container environment variables"
    [ -n "$fw" ] && $docker_user && info "[$rt] DOCKER-USER chain has rules — make sure they cover the published ports"
    return 0
}
