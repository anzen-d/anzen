#!/bin/bash
# checks/systemd_hardening.sh — Per-service systemd hardening options

run_systemd_hardening_check() {
    section "Systemd Hardening"

    if ! command -v systemctl &>/dev/null; then
        info "systemd not available — skipping"
        return
    fi

    local hardening_opts=(
        NoNewPrivileges
        PrivateTmp
        ProtectSystem
        ProtectHome
        RestrictAddressFamilies
        CapabilityBoundingSet
    )

    # Get running non-trivial services
    local services
    services=$(systemctl list-units --type=service --state=running --no-legend 2>/dev/null \
        | awk '{print $1}' \
        | grep -vE '^(getty|user@|systemd-|dbus|snapd|polkit|NetworkManager|ModemManager|accounts|avahi|bluetooth|colord|cups|fwupd|gdm|lightdm|rtkit|thermald|udisks2|upower|packagekit|apt-daily|unattended-upgrades)' \
        | head -20)

    if [ -z "$services" ]; then
        info "No applicable running services found"
        return
    fi

    local unprotected=0
    while IFS= read -r svc; do
        [ -z "$svc" ] && continue
        local missing=()
        for opt in "${hardening_opts[@]}"; do
            val=$(systemctl show "$svc" --property="$opt" 2>/dev/null | cut -d= -f2-)
            # NoNewPrivileges=yes, PrivateTmp=yes, ProtectSystem=full/strict, ProtectHome=yes/read-only
            case "$opt" in
                NoNewPrivileges)   [ "$val" != "yes" ] && missing+=("$opt") ;;
                PrivateTmp)        [ "$val" != "yes" ] && missing+=("$opt") ;;
                ProtectSystem)     [[ "$val" =~ ^(full|strict)$ ]] || missing+=("$opt") ;;
                ProtectHome)       [[ "$val" =~ ^(yes|read-only)$ ]] || missing+=("$opt") ;;
                RestrictAddressFamilies) [ -z "$val" ] || [ "$val" = "RestrictAddressFamilies=" ] && missing+=("$opt") ;;
                CapabilityBoundingSet) [ -z "$val" ] || [ "$val" = "CapabilityBoundingSet=" ] && missing+=("$opt") ;;
            esac
        done
        if [ "${#missing[@]}" -gt 2 ]; then
            warn "$svc missing hardening: ${missing[*]}"
            remedy "systemctl edit $svc  # add [Service] NoNewPrivileges=yes PrivateTmp=yes ProtectSystem=strict ProtectHome=yes"
            unprotected=$((unprotected+1))
        fi
    done <<< "$services"

    [ "$unprotected" -eq 0 ] && ok "All checked services have adequate systemd hardening"

    # Check if systemd-analyze security is available
    if systemctl --version 2>/dev/null | grep -q "systemd 2[4-9][0-9]"; then
        info "Tip: run 'systemd-analyze security' for detailed per-service scores"
    fi

    # Check for services running as root that shouldn't need to
    local root_services
    root_services=$(systemctl list-units --type=service --state=running --no-legend 2>/dev/null \
        | awk '{print $1}' \
        | while read -r s; do
            user=$(systemctl show "$s" --property=User 2>/dev/null | cut -d= -f2-)
            [ -z "$user" ] || [ "$user" = "root" ] && echo "$s"
        done \
        | grep -vE '^(systemd-|getty|NetworkManager|wpa_supplicant|chronyd|ntpd|rsyslog|sshd|docker|containerd|cron|dbus|polkit|udevd|journald|logind|resolved|networkd|timesyncd)' \
        | head -10)

    if [ -n "$root_services" ]; then
        while IFS= read -r svc; do
            warn "Service running as root (consider DynamicUser=yes): $svc"
            remedy "systemctl edit $svc  # add [Service] DynamicUser=yes"
        done <<< "$root_services"
    fi
}
