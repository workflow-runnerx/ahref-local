#!/usr/bin/env bash
# Container entrypoint: virtual display + dummy audio + trusted fingerprint-proxy
# CA, then exec the checker (or any command via PROBE=1 / explicit "--" args).
#
#   docker run ... ahref-local --domains-file domains/sample-200.txt --modes authority
#   docker run ... -e PROBE=1 ahref-local            # runs tools/probe_fingerprint.py
#   docker run ... ahref-local -- bash               # anything after "--" is exec'd as-is
set -euo pipefail
cd /app

# ── 1. virtual display (headed Chromium; headless is a known bot signal) ──────
export DISPLAY="${DISPLAY:-:99}"
Xvfb "$DISPLAY" -screen 0 "${SCREEN:-1920x1080x24}" -nolisten tcp -ac +extension RANDR \
    >/tmp/xvfb.log 2>&1 &
for _ in $(seq 1 100); do
    xdpyinfo -display "$DISPLAY" >/dev/null 2>&1 && break
    sleep 0.1
done
xdpyinfo -display "$DISPLAY" >/dev/null 2>&1 || { echo "❌ Xvfb failed:"; cat /tmp/xvfb.log; exit 1; }

# ── 2. dummy audio device (no sound card == another "server" signal) ─────────
if command -v pulseaudio >/dev/null 2>&1; then
    pulseaudio --start --exit-idle-time=-1 --daemonize=yes >/dev/null 2>&1 || true
    pactl load-module module-null-sink sink_name=dummy sink_properties=device.description=Dummy \
        >/dev/null 2>&1 || true
fi

# ── 3. trust the fingerprint-proxy CA so pages are not "Not Secure" ──────────
CA_PEM="$(.venv/bin/python -c 'from fingerprint_proxy import get_ca; print(get_ca().ca_pem)')"
NSSDB="$HOME/.pki/nssdb"
# Opt-in only: with the CA trusted (real cert validation + TLS session reuse)
# Chromium dropped ~18% of same-origin responses from the proxy in testing
# (2026-10-10, Chromium 149 / Rosetta) and the Ahrefs app never hydrated.
# --ignore-certificate-errors (the default) was as reliable as no proxy.
if [[ "${AHREF_FP_TRUST_CA:-0}" != "1" ]]; then
    echo "[entrypoint] CA not installed (AHREF_FP_TRUST_CA=1 to trust it); browser uses --ignore-certificate-errors"
elif command -v certutil >/dev/null 2>&1 && [[ -f "$CA_PEM" ]]; then
    mkdir -p "$NSSDB"
    [[ -f "$NSSDB/cert9.db" ]] || certutil -d "sql:$NSSDB" -N --empty-password
    certutil -d "sql:$NSSDB" -D -n ahref-fp-proxy >/dev/null 2>&1 || true
    if certutil -d "sql:$NSSDB" -A -t "C,," -n ahref-fp-proxy -i "$CA_PEM"; then
        export AHREF_FP_CA_TRUSTED=1
        echo "[entrypoint] fingerprint-proxy CA trusted in $NSSDB"
    fi
fi

PROXY_INFO="none"; [[ -n "${AHREF_PROXY:-}" ]] && PROXY_INFO="set (${AHREF_PROXY%%:*})"
echo "[entrypoint] TZ=$TZ LANG=$LANG DISPLAY=$DISPLAY screen=${SCREEN:-1920x1080x24} proxy=$PROXY_INFO"

# ── 4. run ───────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--" ]]; then
    shift
    exec "$@"
fi
if [[ "${PROBE:-}" == "1" ]]; then
    exec .venv/bin/python tools/probe_fingerprint.py "$@"
fi
exec .venv/bin/python ahrefs_checker.py "$@"
