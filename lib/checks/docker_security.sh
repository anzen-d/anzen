#!/bin/bash
# checks/docker_security.sh — Container runtime security dispatcher
# Sources runtime-specific checks from lib/checks/runtimes/

run_docker_security_check() {
    section "Container Security"

    # Source all runtime check files
    local rt_dir="$ANZEN_DIR/lib/checks/runtimes"
    for rt_file in "$rt_dir"/*.sh; do
        # shellcheck source=/dev/null
        [ -f "$rt_file" ] && source "$rt_file"
    done

    local found_any=false

    # ── OCI-compatible runtimes (docker/podman/nerdctl share same CLI) ─────────
    for rt in docker podman nerdctl; do
        command -v "$rt" &>/dev/null || continue
        "$rt" info &>/dev/null 2>&1  || continue
        found_any=true
        info "Runtime detected: $rt"
        _oci_daemon_checks  "$rt"
        _oci_container_checks "$rt"
    done

    # ── LXD ───────────────────────────────────────────────────────────────────
    if command -v lxc &>/dev/null && lxc list &>/dev/null 2>&1; then
        found_any=true
        info "Runtime detected: LXD"
        _lxd_checks
    elif command -v lxc-ls &>/dev/null; then
        found_any=true
        info "Runtime detected: LXC"
        _lxc_checks
    fi

    # ── Kubernetes ────────────────────────────────────────────────────────────
    if command -v kubectl &>/dev/null && kubectl cluster-info &>/dev/null 2>&1; then
        found_any=true
        info "Runtime detected: Kubernetes"
        _k8s_checks
    fi

    # ── Low-level runtimes (informational only) ───────────────────────────────
    for rt in ctr runc kata-runtime; do
        command -v "$rt" &>/dev/null && info "Low-level runtime present: $rt"
    done

    [ "$found_any" = "false" ] && info "No container runtime found — skipping"
}
