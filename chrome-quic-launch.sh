#!/usr/bin/env bash
#
# chrome-quic-launch.sh -- launch Chromium in a throw-away profile
# configured to reach the HTTP/3 origin of the RFC9218 demo with a
# self-signed certificate.
#
# Chrome refuses QUIC to origins whose TLS cert isn't fully trusted.
# The older --ignore-certificate-errors flag now shows an "unsupported
# flag" warning and is ignored for QUIC (ERR_QUIC_PROTOCOL_ERROR).
# The supported way is --ignore-certificate-errors-spki-list, which
# pins acceptance to a specific certificate's SubjectPublicKeyInfo
# SHA-256 hash (base64-encoded).
#
# We combine that with --origin-to-force-quic-on so Chrome skips the
# Alt-Svc racing and connects directly over QUIC, and with a private
# --user-data-dir so these flags never touch your real profile.
#
# Usage:
#     ./chrome-quic-launch.sh [cert.pem] [https://localhost:8444/]
#
# Cert resolution order:
#   1. Positional $1
#   2. $DEMO_CERT
#   3. ssl_certificate directive parsed from nginx.conf next to this script
#   4. ./cert.pem (README Quick Setup default)

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# Discover ssl_certificate from a sibling nginx.conf, if present
discover_cert_from_nginx_conf() {
    local conf="$SCRIPT_DIR/nginx.conf"
    [ -f "$conf" ] || return 1
    # First ssl_certificate line that isn't the _key variant
    awk '
        /^[[:space:]]*ssl_certificate[[:space:]]+[^_]/ {
            for (i = 1; i <= NF; i++) if ($i == "ssl_certificate") { print $(i+1); exit }
        }
    ' "$conf" | sed 's/;$//'
}

CERT="${1:-${DEMO_CERT:-}}"
if [ -z "$CERT" ]; then
    CERT="$(discover_cert_from_nginx_conf || true)"
fi
if [ -z "$CERT" ]; then
    CERT="$SCRIPT_DIR/cert.pem"
fi

URL="${2:-https://localhost:8444/}"
PROFILE="${CHROME_PROFILE_DIR:-/tmp/chrome-quic-demo}"

if [ ! -f "$CERT" ]; then
    echo "error: cert not found at $CERT" >&2
    echo "usage: $0 [path/to/cert.pem] [url]" >&2
    exit 1
fi

# Locate a chromium binary
CHROME=""
for c in chromium chromium-browser google-chrome google-chrome-stable chrome; do
    if command -v "$c" >/dev/null 2>&1; then
        CHROME="$c"
        break
    fi
done
if [ -z "$CHROME" ]; then
    echo "error: no chromium/chrome binary found in PATH" >&2
    exit 1
fi

SPKI=$(openssl x509 -in "$CERT" -pubkey -noout \
        | openssl pkey -pubin -outform der \
        | openssl dgst -sha256 -binary \
        | openssl base64)

# Derive host:port for the --origin-to-force-quic-on flag from URL
HOSTPORT=$(printf '%s\n' "$URL" \
    | sed -E 's,^https?://,,; s,/.*$,,')

echo "chromium binary : $CHROME"
echo "cert           : $CERT"
echo "SPKI hash       : $SPKI"
echo "force QUIC on   : $HOSTPORT"
echo "profile dir     : $PROFILE"
echo "opening         : $URL"
echo
echo "NOTE: Chromium will display a yellow bar saying"
echo "  \"--ignore-certificate-errors-spki-list is an unsupported flag\""
echo "This is cosmetic - the flag IS honoured and QUIC will connect."
echo

exec "$CHROME" \
    --user-data-dir="$PROFILE" \
    --origin-to-force-quic-on="$HOSTPORT" \
    --ignore-certificate-errors-spki-list="$SPKI" \
    "$URL"
