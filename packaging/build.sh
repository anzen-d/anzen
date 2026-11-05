#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# packaging/build.sh VERSION OUTDIR — build anzen_VERSION_all.deb and
# anzen-VERSION-1.noarch.rpm (Linux edition) from this checkout.
#
# Layout: /usr/lib/anzen (anzen.sh, lib/, plugins/), /usr/bin/anzen,
# bash/zsh completions, and reports in /var/lib/anzen/reports (anzen writes
# reports next to anzen.sh, so /usr/lib/anzen/reports is a symlink there).
# Needs dpkg-deb for the .deb and rpmbuild for the .rpm; a missing tool skips
# that package.
set -euo pipefail

VERSION=${1:?usage: packaging/build.sh VERSION OUTDIR}
OUT=$(mkdir -p "${2:?usage: packaging/build.sh VERSION OUTDIR}" && cd "$2" && pwd)
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "ERROR: bad version '$VERSION'" >&2; exit 1; }
MAINT="Anzen contributors <91915181+anzen-d@users.noreply.github.com>"
DESC="Security audit for Linux hosts, containers and fleets"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

# stage ROOT ZSH_DIR — the installed file tree under ROOT
stage() {
    local root=$1 zsh=$2
    install -d "$root/usr/lib/anzen" "$root/usr/bin" "$root/var/lib/anzen/reports" \
        "$root/usr/share/bash-completion/completions" "$root$zsh" "$root/usr/share/doc/anzen"
    cp -r "$SRC/lib" "$SRC/plugins" "$root/usr/lib/anzen/"
    install -m 755 "$SRC/anzen.sh" "$root/usr/lib/anzen/anzen.sh"
    install -m 644 "$SRC/anzen.conf.example" "$SRC/anzen.accept.example" "$root/usr/lib/anzen/"
    ln -s /var/lib/anzen/reports "$root/usr/lib/anzen/reports"
    printf '#!/bin/bash\nexec bash /usr/lib/anzen/anzen.sh "$@"\n' > "$root/usr/bin/anzen"
    chmod 755 "$root/usr/bin/anzen"
    chmod 700 "$root/var/lib/anzen/reports"
    install -m 644 "$SRC/completions/anzen.bash" "$root/usr/share/bash-completion/completions/anzen"
    install -m 644 "$SRC/completions/anzen.zsh" "$root$zsh/_anzen"
    install -m 644 "$SRC/README.md" "$SRC/CHANGELOG.md" "$SRC/LICENSE" "$root/usr/share/doc/anzen/"
    find "$root/usr/lib/anzen" -type f -name '*.sh' -exec chmod 755 {} +
    find "$root/usr/lib/anzen" -type f ! -name '*.sh' -exec chmod 644 {} +
    find "$root" -type d -exec chmod go-w {} +
}

if command -v dpkg-deb >/dev/null 2>&1; then
    d="$WORK/deb"
    stage "$d" /usr/share/zsh/vendor-completions
    install -d "$d/DEBIAN"
    cat > "$d/DEBIAN/control" <<CONTROL
Package: anzen
Version: $VERSION
Architecture: all
Maintainer: $MAINT
Depends: bash (>= 4.2), coreutils, findutils, gawk | mawk, grep, sed, iproute2, procps
Recommends: curl, openssl, sudo
Suggests: trivy, whiptail
Section: admin
Priority: optional
Homepage: https://github.com/anzen-d/anzen
Description: $DESC
 One self-hosted tool that audits hardening, exposed services, TLS, containers
 and known CVEs, with HTML/JSON/SARIF/CSV reports, history and a dashboard.
CONTROL
    dpkg-deb --root-owner-group --build "$d" "$OUT/anzen_${VERSION}_all.deb" >/dev/null
    echo "$OUT/anzen_${VERSION}_all.deb"
fi

if command -v rpmbuild >/dev/null 2>&1; then
    r="$WORK/rpm"
    stage "$r/root" /usr/share/zsh/site-functions
    install -d "$r/build/SPECS" "$r/build/RPMS"
    cat > "$r/build/SPECS/anzen.spec" <<SPEC
Name:      anzen
Version:   $VERSION
Release:   1
Summary:   $DESC
License:   AGPL-3.0-or-later
URL:       https://github.com/anzen-d/anzen
BuildArch: noarch
Requires:  bash >= 4.2, coreutils, findutils, gawk, grep, sed, iproute, procps-ng
Recommends: curl, openssl, sudo

%description
One self-hosted tool that audits hardening, exposed services, TLS, containers
and known CVEs, with HTML/JSON/SARIF/CSV reports, history and a dashboard.

%install
cp -a $r/root/. %{buildroot}/

%files
%license /usr/share/doc/anzen/LICENSE
%doc /usr/share/doc/anzen/README.md
%doc /usr/share/doc/anzen/CHANGELOG.md
/usr/lib/anzen
/usr/bin/anzen
/usr/share/bash-completion/completions/anzen
/usr/share/zsh/site-functions/_anzen
%dir %attr(0700, root, root) /var/lib/anzen/reports
%dir /var/lib/anzen
SPEC
    rpmbuild -bb --quiet --define "_topdir $r/build" --define "_rpmdir $OUT" \
        --define "_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm" \
        "$r/build/SPECS/anzen.spec" >/dev/null
    echo "$OUT/anzen-${VERSION}-1.noarch.rpm"
fi
