#!/usr/bin/env bash
# One-time setup: download + extract ungoogled-chromium and clone the
# cf-autoclick extension into ahref-local/vendor/. Idempotent — re-running
# is safe and fast (skips work that's already done).
#
# Why this exists:
#   ahrefs_checker.py needs (a) a Chromium binary and (b) an unpacked
#   cf-autoclick extension folder. Rather than depend on whatever Chrome
#   the host happens to have, we vendor a known-good ungoogled-chromium
#   build alongside the extension. ahrefs_checker.py auto-discovers both
#   from vendor/ at runtime.
#
# Usage:
#   bash tools/setup_vendor.sh
#
# After this, you can run:
#   .venv/bin/python ahrefs_checker.py --workers 1 --no-proxy --headless
#
# To upgrade the vendored chromium later:
#   1. Update CHROMIUM_VERSION below
#   2. Delete vendor/ungoogled-chromium/ and vendor/ungoogled-chromium.tar.xz
#   3. Re-run this script
#
# Linux builds are fetched per architecture (x86_64 / arm64) and cached as
# vendor/ungoogled-chromium-<arch>.tar.xz; the unpacked dir ships chromedriver
# too, which ahrefs_checker.py uses on Linux (Google publishes no arm64 one).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AHREF_DIR="$(dirname "${SCRIPT_DIR}")"
VENDOR_DIR="${AHREF_DIR}/vendor"

# ─── Pinned versions ────────────────────────────────────────────────────────
# Bump this and re-run to upgrade. The portable Linux build is preferred
# over the AppImage because it doesn't need FUSE and unpacks to plain files.
# arm64 portable builds exist from 154.0.8037.57-1 on (153 and older are
# x86_64 only); the Docker image is linux/arm64 so it runs natively on
# Apple Silicon instead of under Rosetta (see DOCUMENTATION.md, Docker).
CHROMIUM_VERSION="155.0.8059.39-1"
case "$(uname -m)" in
  aarch64|arm64) CHROMIUM_ARCH="arm64" ;;
  x86_64|amd64)  CHROMIUM_ARCH="x86_64" ;;
  *) echo "❌ unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
CHROMIUM_TARBALL_URL="https://github.com/ungoogled-software/ungoogled-chromium-portablelinux/releases/download/${CHROMIUM_VERSION}/ungoogled-chromium-${CHROMIUM_VERSION}-${CHROMIUM_ARCH}_linux.tar.xz"
# Cached per architecture so an x86_64 tarball is never unpacked on arm64.
CHROMIUM_TARBALL="${VENDOR_DIR}/ungoogled-chromium-${CHROMIUM_ARCH}.tar.xz"
CHROMIUM_DIR="${VENDOR_DIR}/ungoogled-chromium"
CHROMIUM_INNER="${VENDOR_DIR}/ungoogled-chromium-${CHROMIUM_VERSION}-${CHROMIUM_ARCH}_linux"

EXTENSION_URL="https://github.com/tenacious6/cf-autoclick.git"
EXTENSION_DIR="${VENDOR_DIR}/cf-autoclick"

mkdir -p "${VENDOR_DIR}"

# ─── macOS: use the Homebrew cask instead of the Linux tarball ─────────────
# The portable tarball above is a Linux x86_64 ELF build and cannot run on
# macOS. On a Mac we install ungoogled-chromium via Homebrew (arm64/x86_64
# native .app) and ahrefs_checker.py's find_chrome_binary() picks it up from
# /Applications/Chromium.app. The cf-autoclick clone below is shared.
if [[ "$(uname -s)" == "Darwin" ]]; then
  if [[ -x "/Applications/Chromium.app/Contents/MacOS/Chromium" ]]; then
    echo "[*] Chromium.app already present in /Applications — skipping"
  else
    if ! command -v brew >/dev/null 2>&1; then
      echo "❌ Homebrew not found. Install it from https://brew.sh then re-run." >&2
      exit 1
    fi
    echo "[*] Installing ungoogled-chromium via Homebrew cask..."
    brew install --cask ungoogled-chromium
  fi
  echo "[*] Verifying binary..."
  "/Applications/Chromium.app/Contents/MacOS/Chromium" --version
  echo "✅ Chromium ready at /Applications/Chromium.app"
  CHROMIUM_DIR="/Applications/Chromium.app"
fi

# ─── 1. ungoogled-chromium binary (Linux) ───────────────────────────────────
if [[ "$(uname -s)" == "Darwin" ]]; then
  : # handled above
elif [[ -x "${CHROMIUM_DIR}/chrome" ]] && "${CHROMIUM_DIR}/chrome" --version >/dev/null 2>&1; then
  echo "[*] ungoogled-chromium already present at ${CHROMIUM_DIR}/chrome — skipping"
elif [[ -d "${CHROMIUM_DIR}" ]]; then
  echo "❌ ${CHROMIUM_DIR} exists but does not run on this machine ($(uname -m))." >&2
  echo "   It was probably unpacked for another architecture — delete it and re-run." >&2
  exit 1
else
  if [[ ! -f "${CHROMIUM_TARBALL}" ]]; then
    echo "[*] Downloading ungoogled-chromium ${CHROMIUM_VERSION}..."
    curl -fL --progress-bar -o "${CHROMIUM_TARBALL}" "${CHROMIUM_TARBALL_URL}"
  else
    echo "[*] Tarball already cached at ${CHROMIUM_TARBALL}"
  fi

  echo "[*] Extracting tarball to ${VENDOR_DIR}..."
  tar -xJf "${CHROMIUM_TARBALL}" -C "${VENDOR_DIR}"

  if [[ ! -d "${CHROMIUM_INNER}" ]]; then
    echo "❌ Expected extracted dir ${CHROMIUM_INNER} not found." >&2
    echo "   The tarball layout may have changed. Check the contents:" >&2
    echo "     tar -tJf ${CHROMIUM_TARBALL} | head" >&2
    exit 1
  fi

  mv "${CHROMIUM_INNER}" "${CHROMIUM_DIR}"
  chmod +x "${CHROMIUM_DIR}/chrome" "${CHROMIUM_DIR}/chromedriver" 2>/dev/null || true

  echo "[*] Verifying binary..."
  if ! "${CHROMIUM_DIR}/chrome" --version; then
    echo "❌ vendor/ungoogled-chromium/chrome failed to run --version." >&2
    echo "   You may be missing system libraries. On Ubuntu try:" >&2
    echo "     sudo apt install -y libnss3 libatk-bridge2.0-0 libxkbcommon0 \\" >&2
    echo "                         libxcomposite1 libxdamage1 libxrandr2 libgbm1 \\" >&2
    echo "                         libpango-1.0-0 libcairo2 libasound2t64" >&2
    exit 1
  fi
  echo "✅ Chromium ready at ${CHROMIUM_DIR}/chrome"
fi

# ─── 2. cf-autoclick extension ──────────────────────────────────────────────
if [[ -f "${EXTENSION_DIR}/manifest.json" ]]; then
  echo "[*] cf-autoclick already present at ${EXTENSION_DIR} — skipping"
else
  echo "[*] Cloning cf-autoclick from ${EXTENSION_URL}..."
  git clone --depth 1 "${EXTENSION_URL}" "${EXTENSION_DIR}"

  if [[ ! -f "${EXTENSION_DIR}/manifest.json" ]]; then
    echo "❌ Cloned extension missing manifest.json: ${EXTENSION_DIR}" >&2
    exit 1
  fi
  echo "✅ Extension ready at ${EXTENSION_DIR}"
fi

# ─── Done ───────────────────────────────────────────────────────────────────
cat <<EOF

╔══════════════════════════════════════════════════════════════╗
║                  ✅  VENDOR SETUP COMPLETE                   ║
╚══════════════════════════════════════════════════════════════╝

  Chromium:  ${CHROMIUM_DIR}
  Extension: ${EXTENSION_DIR}

ahrefs_checker.py will auto-discover both at runtime. Try:

  cd ${AHREF_DIR}
  python -m venv .venv && .venv/bin/pip install -r requirements.txt
  .venv/bin/python ahrefs_checker.py --workers 1 --no-proxy --headless

EOF
