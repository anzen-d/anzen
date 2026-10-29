#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# checks/images.sh — Container image freshness
# Per running image: age, unpinned tags, containers left on an older image
# after a pull, and (optionally) a newer digest published upstream (registry
# HEAD requests via curl — no pulls, no Docker Hub rate-limit cost).

# _image_runtime — docker or podman when its daemon/socket answers
_image_runtime() {
    if command -v docker &>/dev/null && docker info &>/dev/null; then echo docker
    elif command -v podman &>/dev/null && podman info &>/dev/null; then echo podman
    fi
}

# _image_ref_parts REF — "registry repository tag" (Docker Hub defaults applied)
_image_ref_parts() {
    local ref=$1 reg repo tag=latest
    repo=$ref
    if [[ "${ref##*/}" == *:* ]]; then tag=${ref##*:}; repo=${ref%:*}; fi
    reg=${repo%%/*}
    if [[ "$repo" == */* && ( "$reg" == *.* || "$reg" == *:* || "$reg" == localhost ) ]]; then
        repo=${repo#*/}
    else
        reg=registry-1.docker.io
        [[ "$repo" == */* ]] || repo="library/$repo"
    fi
    echo "$reg $repo $tag"
}

# _image_remote_digest REF — registry digest of REF, empty when unknown (private,
# rate-limited, offline). Uses HEAD requests with an anonymous token: Docker Hub
# does not count HEADs against the pull limit, unlike GETs (docker pull/inspect)
_image_remote_digest() {
    local reg repo tag hdr www realm svc tok
    read -r reg repo tag <<< "$(_image_ref_parts "$1")"
    local accept="application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json"
    local url="https://$reg/v2/$repo/manifests/$tag"
    hdr=$(curl -sI -m 10 -H "Accept: $accept" "$url" 2>/dev/null | tr -d '\r')
    www=$(grep -i '^www-authenticate: bearer' <<< "$hdr")
    if [ -n "$www" ]; then
        realm=$(sed -nE 's/.*realm="([^"]+)".*/\1/p' <<< "$www")
        svc=$(sed -nE 's/.*service="([^"]+)".*/\1/p' <<< "$www")
        tok=$(curl -s -m 10 "$realm?service=$svc&scope=repository:$repo:pull" 2>/dev/null \
              | sed -nE 's/.*"(access_)?token" *: *"([^"]+)".*/\2/p' | head -1)
        [ -n "$tok" ] || return 0
        hdr=$(curl -sI -m 10 -H "Accept: $accept" -H "Authorization: Bearer $tok" "$url" 2>/dev/null | tr -d '\r')
    fi
    sed -nE 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: *(sha256:[0-9a-f]+).*/\1/p' <<< "$hdr" | head -1
}

run_images_check() {
    section "Container Images"

    local rt; rt=$(_image_runtime)
    if [ -z "$rt" ]; then
        info "No running Docker/Podman — skipping"
        return 0
    fi

    local max_age="${IMAGE_MAX_AGE_DAYS:-180}" now; now=$(date +%s)
    local check_updates="${IMAGE_CHECK_UPDATES:-true}"
    if [ "$check_updates" = "true" ] && [ "${OFFLINE:-false}" = "true" ]; then
        info "Upstream update check skipped (--offline)"
        check_updates=false
    elif [ "$check_updates" = "true" ] && ! command -v curl &>/dev/null; then
        info "Upstream update check needs curl — skipped"
        check_updates=false
    fi

    local ids; ids=$("$rt" ps -q --no-trunc 2>/dev/null)
    [ -z "$ids" ] && { info "No running containers"; return 0; }

    # ref<TAB>container image ID<TAB>container names — one line per (ref, image ID)
    local ref running names cur_id created age digests remote stale=0 old=0 unpinned=0 newer=0 total=0
    # shellcheck disable=SC2086  # container IDs: hex, word-splitting is intended
    while IFS=$'\t' read -r ref running names; do
        total=$((total + 1))

        # Unpinned: :latest or no tag (a digest pin counts as pinned)
        if [[ "$ref" != *@sha256:* ]] && { [[ "$ref" == *:latest ]] || [[ "${ref##*/}" != *:* ]]; }; then
            if [ "${IMAGE_WARN_LATEST:-true}" = "true" ]; then
                warn "Unpinned image tag: $ref [$names]"
                remedy "# pin $ref to a version tag (or @sha256 digest) in the compose file"
            fi
            unpinned=$((unpinned + 1))
        fi

        # Pulled but not recreated: the tag now points at a different image
        cur_id=$("$rt" image inspect --format '{{.Id}}' "$ref" 2>/dev/null)
        if [ -n "$cur_id" ] && [ "$cur_id" != "$running" ]; then
            warn "Containers run an older image than the pulled $ref [$names]"
            remedy "$rt compose up -d  # or recreate: $names"
            stale=$((stale + 1))
        fi

        # Age of the image the containers actually run
        created=$("$rt" image inspect --format '{{.Created}}' "$running" 2>/dev/null)
        created=$(date -d "$created" +%s 2>/dev/null || echo 0)
        # Reproducible builds stamp 1970/1980: no usable build date
        if [ "$created" -gt 946684800 ]; then
            age=$(( (now - created) / 86400 ))
            if [ "$age" -gt "$max_age" ]; then
                warn "Image $ref is $age days old (limit $max_age) [$names]"
                remedy "$rt pull $ref && recreate $names  # or move to a maintained tag"
                old=$((old + 1))
            fi
        fi

        # Newer digest upstream than the one the containers run
        if [ "$check_updates" = "true" ] && [[ "$ref" != *@sha256:* ]]; then
            digests=$("$rt" image inspect --format '{{join .RepoDigests " "}}' "$running" 2>/dev/null)
            remote=$(_image_remote_digest "$ref")
            if [ -n "$remote" ] && [ -n "$digests" ] && [[ " $digests " != *"@$remote "* ]]; then
                warn "Newer image published for $ref [$names]"
                remedy "$rt pull $ref && recreate $names"
                newer=$((newer + 1))
            fi
        fi
    # Config.Image, not "ps" .Image: once a pull moves the tag, ps shows the
    # bare image ID instead of the ref the container was started from
    done < <("$rt" inspect --format '{{.Config.Image}}{{"\t"}}{{.Image}}{{"\t"}}{{.Name}}' $ids 2>/dev/null \
             | sed 's/\t\//\t/' \
             | awk -F'\t' '{ k = $1 "\t" $2; if (!(k in n)) o[++c] = k; n[k] = (n[k] ? n[k] "," : "") $3 }
                           END { for (i = 1; i <= c; i++) print o[i] "\t" n[o[i]] }')

    if [ "$total" -gt 0 ] && [ $((stale + old + unpinned + newer)) -eq 0 ]; then
        ok "$total running image(s): pinned, current and newer than $max_age days"
    else
        info "$total running image(s): $unpinned unpinned, $stale not recreated after pull, $old older than $max_age days, $newer with a newer upstream digest"
    fi
}
