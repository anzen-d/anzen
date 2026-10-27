#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# lib/os_detect.sh — Detect OS family and package manager

OS_ID=""
OS_VERSION=""
OS_PRETTY=""
OS_FAMILY=""   # debian | rhel | arch | alpine | suse | other
PKG_MGR=""     # apt | dnf | yum | pacman | apk | zypper
INIT_SYS=""    # systemd | openrc | sysv | unknown

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-}"
        OS_PRETTY="${PRETTY_NAME:-$ID}"
    elif [ -f /etc/redhat-release ]; then
        OS_PRETTY=$(cat /etc/redhat-release)
        OS_ID="rhel"
    else
        OS_PRETTY="Unknown Linux"
        OS_ID="unknown"
    fi

    case "$OS_ID" in
        ubuntu|debian|linuxmint|pop|kali|raspbian)
            OS_FAMILY="debian" ; PKG_MGR="apt" ;;
        rhel|centos|fedora|rocky|almalinux|ol|amzn)
            OS_FAMILY="rhel"
            command -v dnf &>/dev/null && PKG_MGR="dnf" || PKG_MGR="yum" ;;
        arch|manjaro|endeavouros)
            OS_FAMILY="arch" ; PKG_MGR="pacman" ;;
        alpine)
            OS_FAMILY="alpine" ; PKG_MGR="apk" ;;
        opensuse*|sles)
            OS_FAMILY="suse" ; PKG_MGR="zypper" ;;
        *)
            OS_FAMILY="other"
            for m in apt dnf yum pacman apk zypper; do
                command -v $m &>/dev/null && PKG_MGR=$m && break
            done
            ;;
    esac

    if pidof systemd &>/dev/null || [ -d /run/systemd/system ]; then
        INIT_SYS="systemd"
    elif [ -f /sbin/openrc ]; then
        INIT_SYS="openrc"
    elif [ -f /sbin/init ]; then
        INIT_SYS="sysv"
    else
        INIT_SYS="unknown"
    fi

    export OS_ID OS_VERSION OS_PRETTY OS_FAMILY PKG_MGR INIT_SYS
}

detect_os
