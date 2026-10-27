#!/usr/bin/env bats
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# tests/test_checks_images.bats — Tests for lib/checks/images.sh

setup() {
    ANZEN_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    FINDINGS_FILE="$(mktemp)"
    NO_COLOR=true QUIET=true
    export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/output.sh"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/images.sh"
}

teardown() { rm -f "$FINDINGS_FILE" "${FINDINGS_FILE}.tmp"; }

# Fake runtime: two containers on one image, started from :latest, image
# built 400 days ago; the tag now points at a newer image (pulled, not recreated)
fake_runtime() {
    _image_runtime() { echo fakert; }
    fakert() {
        case "$1 $2" in
            "ps -q") printf 'c1\nc2\n' ;;
            "inspect --format") printf 'app:latest\tsha256:old\t/web1\napp:latest\tsha256:old\t/web2\n' ;;
            "image inspect")
                # fakert image inspect --format FORMAT REF
                case "$4 $5" in
                    "{{.Id}} app:latest")      echo sha256:new ;;
                    "{{.Created}} sha256:old") date -u -d '400 days ago' +%Y-%m-%dT%H:%M:%SZ ;;
                esac ;;
        esac
    }
    IMAGE_CHECK_UPDATES=false
}

@test "images: no runtime is INFO, not an error" {
    _image_runtime() { :; }
    run_images_check
    grep -q $'^INFO\t.*No running Docker/Podman' "$FINDINGS_FILE"
}

@test "images: containers on one image are reported once, with all names" {
    fake_runtime
    run_images_check
    [ "$(grep -c 'Unpinned image tag: app:latest \[web1,web2\]' "$FINDINGS_FILE")" -eq 1 ]
}

@test "images: pulled-but-not-recreated and old images are WARN" {
    fake_runtime
    run_images_check
    grep -q 'Containers run an older image than the pulled app:latest' "$FINDINGS_FILE"
    grep -qE 'Image app:latest is (399|400) days old' "$FINDINGS_FILE"
}

@test "images: IMAGE_WARN_LATEST=false silences unpinned tags" {
    fake_runtime
    IMAGE_WARN_LATEST=false run_images_check
    ! grep -q 'Unpinned' "$FINDINGS_FILE"
}

@test "_image_ref_parts() applies Docker Hub defaults and keeps other registries" {
    [ "$(_image_ref_parts nginx)" = "registry-1.docker.io library/nginx latest" ]
    [ "$(_image_ref_parts linuxserver/radarr)" = "registry-1.docker.io linuxserver/radarr latest" ]
    [ "$(_image_ref_parts ghcr.io/home-assistant/home-assistant:stable)" = "ghcr.io home-assistant/home-assistant stable" ]
    [ "$(_image_ref_parts localhost:5000/app:1.2)" = "localhost:5000 app 1.2" ]
}
