#!/usr/bin/env bash
# Build an RPM for wda-agent from an already-compiled release binary.
# Requires `rpmbuild` (from rpm-build) on a Fedora/RHEL-family host.
#
# Usage:
#   BIN=target/release/wda-agent packaging/rpm/build-rpm.sh
#
# Output: dist/wda-agent-<version>-1.<arch>.rpm
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${BIN:-$ROOT/target/release/wda-agent}"
VERSION="${VERSION:-$(grep -E '^version' "$ROOT/Cargo.toml" | head -n1 | cut -d'"' -f2)}"
OUT_DIR="${OUT_DIR:-$ROOT/dist}"
SPEC="$ROOT/packaging/rpm/wda-agent.spec"

if [ ! -x "$BIN" ]; then
    echo "error: binary not found at $BIN" >&2
    exit 1
fi

if ! command -v rpmbuild >/dev/null 2>&1; then
    echo "error: rpmbuild not available on this host" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

TARBALL_DIR="$WORK/wda-agent-$VERSION"
mkdir -p "$TARBALL_DIR"
cp "$BIN"                                        "$TARBALL_DIR/wda-agent"
cp "$ROOT/packaging/config/config.yaml"          "$TARBALL_DIR/config.yaml"
cp "$ROOT/packaging/systemd/wda-agent.service"   "$TARBALL_DIR/wda-agent.service"
tar -C "$WORK" -czf "$WORK/wda-agent-$VERSION.tar.gz" "wda-agent-$VERSION"

TOP="$WORK/rpmbuild"
mkdir -p "$TOP"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
cp "$WORK/wda-agent-$VERSION.tar.gz" "$TOP/SOURCES/"
cp "$SPEC" "$TOP/SPECS/"

rpmbuild \
    --define "_topdir $TOP" \
    --define "version $VERSION" \
    -bb "$TOP/SPECS/wda-agent.spec"

find "$TOP/RPMS" -name '*.rpm' -exec cp {} "$OUT_DIR/" \;
echo "built RPMs in $OUT_DIR"
