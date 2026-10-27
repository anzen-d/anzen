#!/bin/bash
# checks/compiler.sh — Development tools and attack-enabler detection

run_compiler_check() {
    section "Compilers & Dev Tools"

    # Compilers / build tools (unexpected on production)
    local dev_tools=(gcc g++ cc make cmake clang rustc go)
    local found_dev=()
    for tool in "${dev_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            found_dev+=("$tool")
        fi
    done

    if [ "${#found_dev[@]}" -gt 0 ]; then
        warn "Compiler/build tools found: ${found_dev[*]}"
        if [ "$OS_FAMILY" = "debian" ]; then
            remedy "apt-get remove --purge ${found_dev[*]}"
        elif [ "$OS_FAMILY" = "rhel" ]; then
            remedy "dnf remove ${found_dev[*]}"
        else
            remedy "# Remove compilers if not needed in production: ${found_dev[*]}"
        fi
    else
        ok "No compilers found"
    fi

    # Network recon / exploitation tools
    local recon_tools=(nmap masscan nikto sqlmap metasploit msfconsole hydra john hashcat aircrack-ng)
    local found_recon=()
    for tool in "${recon_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            found_recon+=("$tool")
        fi
    done

    if [ "${#found_recon[@]}" -gt 0 ]; then
        fail "Offensive security tools found: ${found_recon[*]}"
        if [ "$OS_FAMILY" = "debian" ]; then
            remedy "apt-get remove --purge ${found_recon[*]}"
        elif [ "$OS_FAMILY" = "rhel" ]; then
            remedy "dnf remove ${found_recon[*]}"
        else
            remedy "# Remove offensive tools: ${found_recon[*]}"
        fi
    else
        ok "No offensive security tools found"
    fi

    # Packet capture tools (may be legitimate but worth noting)
    local capture_tools=(tcpdump tshark wireshark)
    local found_capture=()
    for tool in "${capture_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            found_capture+=("$tool")
        fi
    done

    if [ "${#found_capture[@]}" -gt 0 ]; then
        warn "Packet capture tools installed: ${found_capture[*]}"
        remedy "# Remove if not needed: apt-get remove --purge ${found_capture[*]}"
    else
        ok "No packet capture tools found"
    fi

    # Check for world-executable interpreters in unusual locations
    local suspicious_interp=0
    while IFS= read -r f; do
        warn "Interpreter in unusual location: $f"
        suspicious_interp=$((suspicious_interp+1))
    done < <(find /tmp /var/tmp /dev/shm -type f \
        \( -name "python*" -o -name "perl*" -o -name "ruby*" -o -name "php*" -o -name "nc" -o -name "ncat" \) \
        2>/dev/null | head -5)

    [ "$suspicious_interp" -eq 0 ] && ok "No suspicious interpreters in temp locations"

    # Check for setuid on developer tools
    local suid_devtools=0
    while IFS= read -r f; do
        fail "SUID bit on dev tool: $f"
        remedy "chmod u-s '$f'"
        suid_devtools=$((suid_devtools+1))
    done < <(find /usr/bin /usr/local/bin -type f \
        \( -name "gcc*" -o -name "g++*" -o -name "cc*" -o -name "nmap" -o -name "tcpdump" \) \
        -perm -4000 2>/dev/null)

    [ "$suid_devtools" -eq 0 ] && ok "No SUID bits on compiler/dev tools"
}
