#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright 2026 Johannes Dahl
#
# Download Lenovo's OLED panel driver package for the ThinkPad X1 Yoga, check it against
# its known SHA-256 and generate intel_legacy_panel_data.bin from it with
# extract_panel_prop.py. Needs curl or wget, sha256sum, innoextract and python3.
#
# Usage: download_panel_prop.sh [-o OUTPUT] [PACKAGE]
# PACKAGE is n1ndp03w (2nd gen, the default) or n1fdl04w (1st gen). Both contain the same
# PanelDriver.sys and PanelDriver.inf, so either works on both generations.
set -eu

out=intel_legacy_panel_data.bin
if [ "${1:-}" = -o ]; then
	[ $# -ge 2 ] || { echo "-o needs a file name" >&2; exit 2; }
	out=$2
	shift 2
fi
pkg=${1:-n1ndp03w}

case $pkg in
n1ndp03w) sum=fdf69a0708e50704f20098f95625834b23fa473e5406bfb3ce8b7e62ef44b8ce ;;
n1fdl04w) sum=dd1439fadbf24faf792f6dfa00c8dcbc1e0418469d0bc56f9e68e32f7d3e1fc3 ;;
*) echo "unknown package $pkg: n1ndp03w or n1fdl04w" >&2; exit 2 ;;
esac
url=https://download.lenovo.com/pccbbs/mobiles/$pkg.exe

for t in sha256sum innoextract python3; do
	command -v "$t" >/dev/null || { echo "$t is needed" >&2; exit 1; }
done

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $url" >&2
if command -v curl >/dev/null; then
	curl -fsSL --retry 3 -o "$tmp/$pkg.exe" "$url"
elif command -v wget >/dev/null; then
	wget -q -O "$tmp/$pkg.exe" "$url"
else
	echo "curl or wget is needed" >&2
	exit 1
fi

echo "$sum  $tmp/$pkg.exe" | sha256sum -c --quiet - || {
	echo "$pkg.exe does not have the expected SHA-256; not using it" >&2
	exit 1
}

python3 -I "$here/extract_panel_prop.py" -o "$out" "$tmp/$pkg.exe"
