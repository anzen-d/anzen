#!/bin/bash
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

    local priv=0 root=0 hostnet=0 mounts=0

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
                /etc|/proc|/sys|/var/run/docker.sock|/run/podman|/root)
                    fail "[$rt] $cname mounts sensitive path: $vol  [CIS 5.5]"
                    remedy "# Remove or restrict the $vol mount in $cname"
                    mounts=$((mounts+1)) ;;
            esac
        done

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
}
