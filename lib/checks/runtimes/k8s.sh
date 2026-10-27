#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# runtimes/k8s.sh — Kubernetes cluster security checks

_k8s_checks() {
    # All kubectl calls degrade gracefully if RBAC denies access

    # ── API server access ─────────────────────────────────────────────────────
    # Anonymous auth — if this returns 200 without credentials, anon auth is on
    local anon_check
    anon_check=$(kubectl get --raw /api 2>&1)
    if echo "$anon_check" | grep -q '"versions"'; then
        warn "[k8s] API server responds to unauthenticated requests"
        remedy "# Set --anonymous-auth=false in kube-apiserver manifest"
    else
        ok "[k8s] API server requires authentication"
    fi

    # ── RBAC: cluster-admin bindings outside kube-system ─────────────────────
    local admin_bindings
    admin_bindings=$(kubectl get clusterrolebindings \
        -o jsonpath='{range .items[?(@.roleRef.name=="cluster-admin")]}{.metadata.name}{"\t"}{range .subjects[*]}{.kind}/{.name}{" "}{end}{"\n"}{end}' \
        2>/dev/null || true)

    if [ -n "$admin_bindings" ]; then
        while IFS=$'\t' read -r binding subjects; do
            [ -z "$binding" ] && continue
            # Ignore built-in system bindings
            case "$binding" in
                cluster-admin|system:masters|kubeadm:cluster-admins) continue ;;
            esac
            warn "[k8s] cluster-admin binding: $binding ($subjects)"
            remedy "kubectl delete clusterrolebinding '$binding'  # review first"
        done <<< "$admin_bindings"
    else
        ok "[k8s] No unexpected cluster-admin bindings"
    fi

    # ── Privileged / host-network pods ────────────────────────────────────────
    local priv_pods hostnet_pods hostpid_pods

    priv_pods=$(kubectl get pods --all-namespaces \
        -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\t"}{range .spec.containers[*]}{.securityContext.privileged}{" "}{end}{"\n"}{end}' \
        2>/dev/null | grep -v "^kube-system/" | grep "true" || true)

    if [ -n "$priv_pods" ]; then
        while IFS=$'\t' read -r pod _; do
            [ -z "$pod" ] && continue
            fail "[k8s] Privileged pod: $pod  [CIS 5.2.1]"
            remedy "# Remove securityContext.privileged: true from $pod"
        done <<< "$priv_pods"
    else
        ok "[k8s] No privileged pods (outside kube-system)"
    fi

    hostnet_pods=$(kubectl get pods --all-namespaces \
        -o jsonpath='{range .items[?(@.spec.hostNetwork==true)]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}' \
        2>/dev/null | grep -v "^kube-system/" || true)

    if [ -n "$hostnet_pods" ]; then
        while IFS= read -r pod; do
            [ -z "$pod" ] && continue
            fail "[k8s] Pod uses hostNetwork: $pod  [CIS 5.2.4]"
            remedy "# Remove hostNetwork: true from $pod spec"
        done <<< "$hostnet_pods"
    else
        ok "[k8s] No pods using hostNetwork (outside kube-system)"
    fi

    hostpid_pods=$(kubectl get pods --all-namespaces \
        -o jsonpath='{range .items[?(@.spec.hostPID==true)]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}' \
        2>/dev/null | grep -v "^kube-system/" || true)

    if [ -n "$hostpid_pods" ]; then
        while IFS= read -r pod; do
            [ -z "$pod" ] && continue
            fail "[k8s] Pod uses hostPID: $pod  [CIS 5.2.2]"
            remedy "# Remove hostPID: true from $pod spec"
        done <<< "$hostpid_pods"
    else
        ok "[k8s] No pods using hostPID (outside kube-system)"
    fi

    # ── Secrets mounted as env vars ───────────────────────────────────────────
    local env_secrets
    env_secrets=$(kubectl get pods --all-namespaces \
        -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\t"}{range .spec.containers[*]}{range .env[*]}{.valueFrom.secretKeyRef.name}{" "}{end}{end}{"\n"}{end}' \
        2>/dev/null | grep -v $'\t$' | grep -v "^kube-system/" || true)

    if [ -n "$env_secrets" ]; then
        while IFS=$'\t' read -r pod secrets; do
            [ -z "$pod" ] && continue
            warn "[k8s] Secrets as env vars in $pod: $secrets  [CIS 5.4.1]"
            remedy "# Mount secrets as volumes instead of env vars in $pod"
        done <<< "$env_secrets"
    else
        ok "[k8s] No secrets exposed as environment variables"
    fi

    # ── Default service account token automount ───────────────────────────────
    local automount_ns
    automount_ns=$(kubectl get serviceaccount default --all-namespaces \
        -o jsonpath='{range .items[?(@.automountServiceAccountToken!=false)]}{.metadata.namespace}{"\n"}{end}' \
        2>/dev/null | grep -v "^kube-system$" || true)

    if [ -n "$automount_ns" ]; then
        while IFS= read -r ns; do
            [ -z "$ns" ] && continue
            warn "[k8s] Default SA token automount enabled in namespace: $ns  [CIS 5.1.6]"
            remedy "kubectl patch serviceaccount default -n $ns -p '{\"automountServiceAccountToken\": false}'"
        done <<< "$automount_ns"
    else
        ok "[k8s] Default SA token automount disabled in all namespaces"
    fi

    # ── Network policies ──────────────────────────────────────────────────────
    local namespaces_no_netpol
    namespaces_no_netpol=$(
        for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
            case "$ns" in kube-system|kube-public|kube-node-lease) continue ;; esac
            count=$(kubectl get networkpolicies -n "$ns" --no-headers 2>/dev/null | wc -l)
            [ "${count:-0}" -eq 0 ] && echo "$ns"
        done
    )

    if [ -n "$namespaces_no_netpol" ]; then
        while IFS= read -r ns; do
            [ -z "$ns" ] && continue
            warn "[k8s] No NetworkPolicy in namespace: $ns  [CIS 5.3.2]"
            remedy "# Add a default-deny NetworkPolicy to namespace $ns"
        done <<< "$namespaces_no_netpol"
    else
        ok "[k8s] All namespaces have NetworkPolicy defined"
    fi

    # ── Pod Security Standards (PSA) ──────────────────────────────────────────
    local no_pss_ns
    no_pss_ns=$(kubectl get namespaces \
        -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.labels}{"\n"}{end}' \
        2>/dev/null \
        | grep -v "kube-system\|kube-public\|kube-node-lease" \
        | grep -v "pod-security.kubernetes.io" || true)

    if [ -n "$no_pss_ns" ]; then
        while IFS=$'\t' read -r ns _; do
            [ -z "$ns" ] && continue
            warn "[k8s] No Pod Security Standard label on namespace: $ns  [CIS 5.2]"
            remedy "kubectl label namespace $ns pod-security.kubernetes.io/enforce=baseline"
        done <<< "$no_pss_ns"
    else
        ok "[k8s] All namespaces have Pod Security Standard labels"
    fi

    # ── etcd encryption ───────────────────────────────────────────────────────
    local etcd_enc
    etcd_enc=$(kubectl get apiserver -o jsonpath='{.items[0].spec.encryption}' 2>/dev/null \
        || kubectl get pod -n kube-system -l component=kube-apiserver \
            -o jsonpath='{.items[0].spec.containers[0].command}' 2>/dev/null \
            | grep -c "encryption-provider-config" || echo "0")

    if [ "${etcd_enc:-0}" = "0" ]; then
        warn "[k8s] etcd encryption at rest not confirmed  [CIS 1.2.31]"
        remedy "# Configure --encryption-provider-config in kube-apiserver"
    else
        ok "[k8s] etcd encryption provider configured"
    fi
}
