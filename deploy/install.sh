#!/bin/sh
# Installs tarn from a signed release. It verifies the signature and checksum
# before installing anything, and never changes your tailnet.
set -eu

repo=https://github.com/elliotnorth/Tarn/releases
if [ -n "${TARN_VERSION:-}" ]; then
	base="$repo/download/$TARN_VERSION"
else
	base="$repo/latest/download"
fi
base="${TARN_BASE_URL:-$base}"
root="${TARN_ROOT:-}" # install under another directory, for testing

die() {
	echo "tarn install: $*" >&2
	exit 1
}

[ "${TARN_OS:-$(uname -s)}" = Linux ] || die "tarn runs on Linux only"
case "${TARN_ARCH:-$(uname -m)}" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
armv7l | armv7) arch=armv7 ;;
*) die "no release for $(uname -m)" ;;
esac
[ -n "$root" ] || [ "$(id -u)" = 0 ] || die "run this as root (sudo)"
for tool in curl openssl sha256sum install; do
	command -v "$tool" >/dev/null || die "$tool is missing. On Debian: apt install curl openssl coreutils"
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

bin="tarn-linux-$arch"
for file in SHA256SUMS SHA256SUMS.sig "$bin" tarn.service; do
	curl -fsSL "$base/$file" -o "$tmp/$file" || die "can't download $file from $base"
done

cat >"$tmp/release.pub" <<'KEY'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGcLRDrrIz+J9GUuag/7bLY9IltJNrhj0ELXMy8NQWvg=
-----END PUBLIC KEY-----
KEY

openssl pkeyutl -verify -pubin -inkey "$tmp/release.pub" -rawin \
	-in "$tmp/SHA256SUMS" -sigfile "$tmp/SHA256SUMS.sig" >/dev/null 2>&1 ||
	die "the release signature is wrong. Nothing was installed"
(
	cd "$tmp"
	grep -E "[ *]($bin|tarn\.service)\$" SHA256SUMS | sha256sum -c --quiet -
) >/dev/null 2>&1 || die "a checksum is wrong. Nothing was installed"

install -d "$root/usr/local/bin" "$root/etc/systemd/system"
install -m 755 "$tmp/$bin" "$root/usr/local/bin/tarn"
unit="$root/etc/systemd/system/tarn.service"
if [ -e "$unit" ]; then
	echo "Keeping your existing $unit"
else
	install -m 644 "$tmp/tarn.service" "$unit"
fi
[ -n "$root" ] || systemctl daemon-reload

echo "Installed $("$root/usr/local/bin/tarn" -version 2>/dev/null || echo tarn)."
echo "Check this machine with: tarn doctor"
