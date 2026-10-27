#!/bin/bash
# bash completion for anzen

_anzen_complete() {
    local cur prev words cword
    _init_completion || return

    local modules="system users ssh network network2 packages files secrets
                   systemd_hardening tls compiler path_check modules
                   services docker_security images logins kernel auditd cve
                   pentest pentest_external"

    case "$prev" in
        --check)
            COMPREPLY=( $(compgen -W "$modules" -- "$cur") )
            return ;;
        --output|--config|--history|--dashboard)
            _filedir
            return ;;
        --remote)
            _known_hosts_real "$cur"
            return ;;
        --schedule)
            COMPREPLY=( $(compgen -W "daily weekly monthly" -- "$cur") )
            return ;;
    esac

    if [[ "$cur" == --check=* ]]; then
        COMPREPLY=( $(compgen -W "$modules" -- "${cur#--check=}") )
        COMPREPLY=( "${COMPREPLY[@]/#/--check=}" )
        return
    fi

    if [[ "$cur" == --schedule=* ]]; then
        COMPREPLY=( $(compgen -W "daily weekly monthly" -- "${cur#--schedule=}") )
        COMPREPLY=( "${COMPREPLY[@]/#/--schedule=}" )
        return
    fi

    local opts="--html --txt --json --remediate --parallel -p
                --baseline --diff --quiet -q --no-color
                --version -v --help -h
                --output= --config= --check= --remote= --schedule=
                --sarif --strict --wan --target= --resolve-to= --remote-pentest=
                --history= --dashboard="

    COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
}

complete -F _anzen_complete anzen anzen.sh
