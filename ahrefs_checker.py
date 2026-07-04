"""
Ahrefs Pull-based Checker — auto-routes between authority and traffic queues.

Each worker gets its own per-run Chrome profile (replicated from a master
profile downloaded from a GitHub release on every start), runs a browser,
and pulls execution records from BOTH pull-based endpoints in round-robin:

  GET/POST /ahref-authority/   (authority queue)
  GET/POST /ahref-traffic/     (traffic queue)

Whichever endpoint returns a record dictates which JS / target URL /
extractor is used to scrape that one domain — the workflow doesn't have
to pick a mode upfront. Both queues feed the same browser; if only one
queue has work, the worker drains it and idles on the other.

The master profile is downloaded once per run from a GitHub release and
contains the cf-autoclick extension pre-installed. Every worker copies it
into a unique directory ``ahref_w{worker_id}_{uuid8}`` so concurrent
instances never collide on profile state. All per-worker profile dirs (and
the master cache) are cleaned up when the worker exits or the process is
killed.

Usage:
    python ahrefs_checker.py [--modes MODES] [--api-url URL] [--headless] [--workers 5]
                             [--chrome /path/to/chrome] [--extension /path/to/ext/folder]

    MODES is a comma-separated list (default: 'authority,traffic'). Set to
    a single value (e.g. 'traffic') to lock the worker to one queue.

    --extension: directly pass the extension folder path — skips GitHub
    profile download and Extensions/cf_autoclick/ folder structure entirely.
"""

import argparse
import atexit
import json
import os
import platform
import random
import shutil
import signal
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover
    from requests.packages.urllib3.util.retry import Retry  # type: ignore

WEBSHARE_API_KEY = os.environ.get("WEBSHARE_API_KEY", "9ulqjlekme1514dwfi7p6lwm9kmvygshn5brii5s")
WEBSHARE_PROXY_HOST = "p.webshare.io"
WEBSHARE_PROXY_PORT = "9999"

# Track authorized IP for cleanup
_WEBSHARE_AUTH_ID: Optional[int] = None

AHREFS_JSON_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ahrefs.json")
AHREFS_TRAFFIC_JSON_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "ahrefs-traffic-checker.json"
)
PROXIES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxies.txt")
DEFAULT_API_URL = "https://b-domain.articleinnovator.com/domain-metrics-management-service/api/v1"

# --------------------------------------------------------------------------- #
# Master profile (downloaded from GitHub release on every run)
# --------------------------------------------------------------------------- #
PROFILE_RELEASE_URL = os.environ.get(
    "AHREF_PROFILE_RELEASE_URL",
    "https://github.com/sanket-sakariya/test-abc/releases/download/"
    "worker-profile-v1/ahrefs-worker-profile.zip",
)
PROFILE_PREEXTRACTED_DIR = os.environ.get("AHREF_MASTER_PROFILE_DIR", "").strip() or None

# All per-worker profile dirs created during this process — cleaned up on exit.
_CREATED_PROFILES: List[str] = []
_PROFILES_LOCK = threading.Lock()

# Master profile cache (populated by _download_master_profile on first call).
_MASTER_PROFILE_DIR: Optional[str] = None
_MASTER_PROFILE_LOCK = threading.Lock()


# ----------------------------------------------------------------------------
# Mode dispatch — authority vs traffic share most of the browser machinery
# but differ in which endpoint they pull from, which JS spec they inject,
# and how they extract the result.
# ----------------------------------------------------------------------------

class CheckerMode:
    """Per-mode configuration: endpoint, target URL, JS spec, result parser."""

    def __init__(
        self,
        name: str,
        endpoint: str,
        target_url: str,
        spec_path: str,
        extract_row: Callable[[Dict[str, Any], str], Dict[str, Any]],
    ):
        self.name = name
        self.endpoint = endpoint
        self.target_url = target_url
        self.spec_path = spec_path
        self.extract_row = extract_row

    def build_url(self, domain: str) -> str:
        """Build the per-domain target URL. The domain is passed via the
        ``?input=`` query param so Ahrefs auto-runs the check (no typing)."""
        from urllib.parse import quote

        return self.target_url.format(domain=quote(domain, safe=""))


def _extract_authority_row(parsed: Dict[str, Any], domain: str) -> Dict[str, Any]:
    """Authority-mode result extractor: DR / backlinks / linking websites."""
    row: Dict[str, Any] = {"domain_name": domain, "status": "error"}
    results = parsed.get("results")
    if results and isinstance(results, list):
        r = results[0]
        row["domain_name"] = r.get("domain_name", domain)
        row["dr"] = r.get("dr")
        row["backlinks"] = r.get("backlinks")
        row["linking_websites"] = r.get("linking_websites")
        row["backlinks_dofollow_percentage"] = r.get("backlinks_dofollow_percentage")
        row["linking_websites_dofollow_percentage"] = r.get("linking_websites_dofollow_percentage")
        # Only a real DR (or backlinks) means the modal actually rendered
        # metrics. Missing values => the check failed (modal never appeared,
        # "something went wrong", turnstile timeout, etc.) — mark it failed
        # instead of silently recording a null "completed".
        if r.get("dr") is not None or r.get("backlinks") is not None:
            row["status"] = "completed"
        elif r.get("error"):
            row["error"] = r.get("error")
    return row


def _extract_traffic_row(parsed: Dict[str, Any], domain: str) -> Dict[str, Any]:
    """Traffic-mode result extractor: organic_traffic / traffic_value / etc."""
    row: Dict[str, Any] = {"domain_name": domain, "status": "error"}
    results = parsed.get("results")
    if results and isinstance(results, list):
        r = results[0]
        row["domain_name"] = r.get("domain_name", domain)
        row["organic_traffic"] = r.get("organic_traffic")
        row["traffic_value"] = r.get("traffic_value")
        row["traffic_graph"] = r.get("traffic_graph") or {}
        row["top_countries"] = r.get("top_countries") or []
        row["top_keywords"] = r.get("top_keywords") or []
        row["top_pages"] = r.get("top_pages") or []
        row["turnstile_retries"] = r.get("turnstile_retries")
        if r.get("organic_traffic") is not None or r.get("traffic_value") is not None:
            row["status"] = "completed"
        elif r.get("error"):
            row["error"] = r.get("error")
    return row


MODES: Dict[str, CheckerMode] = {
    "authority": CheckerMode(
        name="authority",
        endpoint="/ahref-authority/",
        target_url="https://ahrefs.com/website-authority-checker/?input={domain}",
        spec_path=AHREFS_JSON_PATH,
        extract_row=_extract_authority_row,
    ),
    "traffic": CheckerMode(
        name="traffic",
        endpoint="/ahref-traffic/",
        target_url="https://ahrefs.com/traffic-checker/?input={domain}&mode=subdomains",
        spec_path=AHREFS_TRAFFIC_JSON_PATH,
        extract_row=_extract_traffic_row,
    ),
}


# ----------------------------------------------------------------------------
# HTTP resilience — retries on DNS / 5xx
# ----------------------------------------------------------------------------

def _make_resilient_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=5, connect=5, read=5, status=5,
        backoff_factor=1.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST", "PUT", "PATCH", "DELETE"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(pool_connections=10, pool_maxsize=20, max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


_HTTP = _make_resilient_session()


# ----------------------------------------------------------------------------
# Webshare IP Authorization
# ----------------------------------------------------------------------------

def webshare_get_my_ip() -> str:
    """Get the public IP of this machine."""
    resp = requests.get("https://api.ipify.org", timeout=10)
    resp.raise_for_status()
    return resp.text.strip()


def webshare_authorize_ip(ip: str) -> int:
    """Authorize IP with Webshare. Returns the authorization ID."""
    global _WEBSHARE_AUTH_ID
    resp = requests.post(
        "https://proxy.webshare.io/api/v2/proxy/ipauthorization/",
        json={"ip_address": ip},
        headers={"Authorization": f"Token {WEBSHARE_API_KEY}"},
        timeout=15,
    )
    if resp.status_code == 400 and "already" in resp.text.lower():
        # IP already authorized — find its ID
        list_resp = requests.get(
            "https://proxy.webshare.io/api/v2/proxy/ipauthorization/",
            headers={"Authorization": f"Token {WEBSHARE_API_KEY}"},
            timeout=15,
        )
        list_resp.raise_for_status()
        for entry in list_resp.json().get("results", []):
            if entry.get("ip_address") == ip:
                _WEBSHARE_AUTH_ID = entry["id"]
                print(f"✅ IP {ip} already authorized (id={_WEBSHARE_AUTH_ID})", flush=True)
                return _WEBSHARE_AUTH_ID
        # Fallback — can't find but it's authorized, set None so we don't delete
        print(f"⚠️  IP {ip} reportedly authorized but not found in list", flush=True)
        return 0
    resp.raise_for_status()
    data = resp.json()
    _WEBSHARE_AUTH_ID = data["id"]
    print(f"✅ Authorized IP {ip} with Webshare (id={_WEBSHARE_AUTH_ID})", flush=True)
    return _WEBSHARE_AUTH_ID


def webshare_deauthorize_ip() -> None:
    """Remove the authorized IP from Webshare."""
    global _WEBSHARE_AUTH_ID
    if not _WEBSHARE_AUTH_ID:
        return
    try:
        resp = requests.delete(
            f"https://proxy.webshare.io/api/v2/proxy/ipauthorization/{_WEBSHARE_AUTH_ID}/",
            headers={"Authorization": f"Token {WEBSHARE_API_KEY}"},
            timeout=15,
        )
        if resp.status_code == 204:
            print(f"✅ Deauthorized IP from Webshare (id={_WEBSHARE_AUTH_ID})", flush=True)
        else:
            print(f"⚠️  Webshare deauthorize returned {resp.status_code}", flush=True)
    except Exception as e:
        print(f"⚠️  Failed to deauthorize IP: {e}", flush=True)
    _WEBSHARE_AUTH_ID = None


# ----------------------------------------------------------------------------
# Master-profile bootstrap — download once per run from GitHub release.
# Only used when --extension is NOT passed.
# ----------------------------------------------------------------------------

def _download_master_profile() -> str:
    global _MASTER_PROFILE_DIR
    with _MASTER_PROFILE_LOCK:
        if _MASTER_PROFILE_DIR and os.path.isdir(_MASTER_PROFILE_DIR):
            return _MASTER_PROFILE_DIR

        if PROFILE_PREEXTRACTED_DIR and os.path.isdir(PROFILE_PREEXTRACTED_DIR):
            ext_manifest = os.path.join(
                PROFILE_PREEXTRACTED_DIR, "Extensions", "cf_autoclick", "manifest.json"
            )
            if os.path.isfile(ext_manifest):
                _MASTER_PROFILE_DIR = PROFILE_PREEXTRACTED_DIR
                print(
                    f"✅ Using pre-extracted master profile from "
                    f"AHREF_MASTER_PROFILE_DIR={PROFILE_PREEXTRACTED_DIR}",
                    flush=True,
                )
                return _MASTER_PROFILE_DIR
            print(
                f"[!] AHREF_MASTER_PROFILE_DIR={PROFILE_PREEXTRACTED_DIR} exists "
                f"but is missing Extensions/cf_autoclick/manifest.json — "
                f"falling back to download.",
                flush=True,
            )

        run_token = uuid.uuid4().hex[:8]
        download_path = os.path.join(tempfile.gettempdir(), f"ahref_master_{run_token}.zip")
        extract_root = os.path.join(tempfile.gettempdir(), f"ahref_master_{run_token}")

        print(f"[*] Downloading master profile from {PROFILE_RELEASE_URL}", flush=True)
        try:
            with _HTTP.get(PROFILE_RELEASE_URL, timeout=(15, 300), stream=True) as resp:
                resp.raise_for_status()
                with open(download_path, "wb") as fh:
                    for chunk in resp.iter_content(chunk_size=1024 * 1024):
                        if chunk:
                            fh.write(chunk)
        except Exception as e:
            raise RuntimeError(
                f"Failed to download master profile from {PROFILE_RELEASE_URL}: {e}. "
                "Make sure the release exists — run "
                "tools/upload_profile_release.sh to create it."
            ) from e

        size_mb = os.path.getsize(download_path) / (1024 * 1024)
        print(f"[*] Downloaded {size_mb:.1f} MB; extracting to {extract_root}", flush=True)

        os.makedirs(extract_root, exist_ok=True)
        try:
            with zipfile.ZipFile(download_path, "r") as zf:
                zf.extractall(extract_root)
        except Exception as e:
            raise RuntimeError(f"Failed to extract master profile zip: {e}") from e
        finally:
            try:
                os.remove(download_path)
            except OSError:
                pass

        candidates = [extract_root] + [
            os.path.join(extract_root, d) for d in os.listdir(extract_root)
            if os.path.isdir(os.path.join(extract_root, d))
        ]
        master = None
        for c in candidates:
            if os.path.isfile(os.path.join(c, "Extensions", "cf_autoclick", "manifest.json")):
                master = c
                break

        if master is None:
            raise RuntimeError(
                f"Downloaded master profile is malformed — no Extensions/cf_autoclick/"
                f"manifest.json found under {extract_root}. Rebuild the release with "
                "tools/upload_profile_release.sh from a profile that has the "
                "cf-autoclick extension installed."
            )

        _MASTER_PROFILE_DIR = master
        print(f"✅ Master profile ready at {master}", flush=True)
        return master


def _create_worker_profile(worker_id: int) -> str:
    """Copy the master profile into a fresh per-worker directory."""
    master = _download_master_profile()
    profile_id = f"ahref_w{worker_id}_{uuid.uuid4().hex[:8]}"
    dest = os.path.join(tempfile.gettempdir(), profile_id)
    if os.path.isdir(dest):
        shutil.rmtree(dest, ignore_errors=True)
    shutil.copytree(master, dest)

    ext_manifest = os.path.join(dest, "Extensions", "cf_autoclick", "manifest.json")
    if not os.path.isfile(ext_manifest):
        shutil.rmtree(dest, ignore_errors=True)
        raise RuntimeError(
            f"[W{worker_id}] Per-worker profile missing cf-autoclick after copy: "
            f"{ext_manifest}"
        )

    mac_files = [
        os.path.join(dest, "Local State"),
        os.path.join(dest, "Default", "Secure Preferences"),
        os.path.join(dest, "Default", "Preferences"),
    ]
    for f in mac_files:
        try:
            if os.path.isfile(f):
                os.remove(f)
        except OSError:
            pass

    with _PROFILES_LOCK:
        _CREATED_PROFILES.append(dest)

    return dest


def _create_plain_profile(worker_id: int) -> str:
    """Create a plain empty per-worker profile (used when --extension is passed directly)."""
    profile_id = f"ahref_w{worker_id}_{uuid.uuid4().hex[:8]}"
    dest = os.path.join(tempfile.gettempdir(), profile_id)
    os.makedirs(dest, exist_ok=True)
    with _PROFILES_LOCK:
        _CREATED_PROFILES.append(dest)
    return dest


def _remove_worker_profile(path: Optional[str]) -> None:
    """Remove a single per-worker profile dir and stop tracking it."""
    if not path:
        return
    try:
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass
    with _PROFILES_LOCK:
        try:
            _CREATED_PROFILES.remove(path)
        except ValueError:
            pass


def _global_profile_cleanup() -> None:
    """atexit + SIGTERM hook — wipe every per-worker dir and the master cache."""
    with _PROFILES_LOCK:
        paths = list(_CREATED_PROFILES)
        _CREATED_PROFILES.clear()
    for p in paths:
        try:
            shutil.rmtree(p, ignore_errors=True)
        except Exception:
            pass
    global _MASTER_PROFILE_DIR
    if _MASTER_PROFILE_DIR:
        is_preextracted = (
            PROFILE_PREEXTRACTED_DIR
            and os.path.abspath(_MASTER_PROFILE_DIR) == os.path.abspath(PROFILE_PREEXTRACTED_DIR)
        )
        if not is_preextracted:
            try:
                parent = os.path.dirname(_MASTER_PROFILE_DIR)
                if parent.startswith(tempfile.gettempdir()) and "ahref_master_" in parent:
                    shutil.rmtree(parent, ignore_errors=True)
                else:
                    shutil.rmtree(_MASTER_PROFILE_DIR, ignore_errors=True)
            except Exception:
                pass
        _MASTER_PROFILE_DIR = None


atexit.register(_global_profile_cleanup)


def _install_signal_handlers() -> None:
    def _handler(signum, _frame):
        try:
            webshare_deauthorize_ip()
            _global_profile_cleanup()
        finally:
            sys.exit(128 + signum)
    for sig in (signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError):
            pass


# ----------------------------------------------------------------------------
# Driver-build serialization
# ----------------------------------------------------------------------------

_DRIVER_BUILD_LOCK_PATH = "/tmp/uc_driver_build.lock"
_driver_build_lock = threading.Lock()

UC_CACHE_DIR = os.path.expanduser("~/.local/share/undetected_chromedriver")


def _acquire_driver_build_lock(timeout: float = 60.0) -> Optional[Any]:
    try:
        import fcntl
    except ImportError:
        return None
    deadline = time.time() + timeout
    fh = open(_DRIVER_BUILD_LOCK_PATH, "w")
    while time.time() < deadline:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fh
        except BlockingIOError:
            time.sleep(0.5)
    fh.close()
    return None


def _release_driver_build_lock(fh: Optional[Any]) -> None:
    if fh is None:
        return
    try:
        import fcntl
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    except Exception:
        pass
    try:
        fh.close()
    except Exception:
        pass


def load_mode_js(spec_path: str) -> str:
    with open(spec_path, "r", encoding="utf-8") as fh:
        spec = json.load(fh)
    action = next((a for a in spec.get("actions", []) if a.get("type") == "evaluate"), None)
    if not action or "script" not in action:
        raise RuntimeError(f"{spec_path} missing the 'evaluate' action / script")
    return action["script"]


def load_proxies() -> List[str]:
    if not os.path.exists(PROXIES_PATH):
        return []
    with open(PROXIES_PATH) as f:
        return [line.strip() for line in f if line.strip()]


def find_chrome_binary() -> Optional[str]:
    system = platform.system()
    candidates = []
    if system == "Linux":
        # Prefer the vendored ungoogled-chromium build shipped in vendor/
        # so the script Just Works after the one-time tools/setup_vendor.sh
        # extraction. Falls back to system installs if vendor/ is missing.
        script_dir = os.path.dirname(os.path.abspath(__file__))
        candidates = [
            os.path.join(script_dir, "vendor", "ungoogled-chromium", "chrome"),
            "/usr/bin/ungoogled-chromium",
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium",
            "/usr/bin/google-chrome-stable",
            "/usr/bin/google-chrome",
        ]
    elif system == "Darwin":
        candidates = ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]
    elif system == "Windows":
        for env in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
            base = os.environ.get(env, "")
            if base:
                candidates.append(os.path.join(base, "Google", "Chrome", "Application", "chrome.exe"))
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return None


def detect_chrome_major(chrome_binary: Optional[str]) -> Optional[int]:
    import subprocess, re
    if not chrome_binary:
        return None
    try:
        out = subprocess.check_output([chrome_binary, "--version"], text=True, timeout=5)
        m = re.search(r"(\d+)\.", out)
        return int(m.group(1)) if m else None
    except Exception:
        return None


def _free_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def build_driver(worker_id: int, headless: bool, chrome_binary: Optional[str],
                 version_main: Optional[int], proxy: Optional[str] = None,
                 extension_path: Optional[str] = None):
    """Build a uc.Chrome driver.

    If extension_path is provided (via --extension CLI arg), load the
    extension directly via --load-extension without needing a master profile
    or GitHub download. Otherwise falls back to the original master-profile
    flow.

    Returns (driver, profile_path).
    """
    import undetected_chromedriver as uc

    file_lock = _acquire_driver_build_lock(timeout=120.0)
    with _driver_build_lock:
        try:
            return _build_driver_locked(
                worker_id, headless=headless, chrome_binary=chrome_binary,
                version_main=version_main, proxy=proxy, uc=uc,
                extension_path=extension_path,
            )
        finally:
            _release_driver_build_lock(file_lock)


def _build_driver_locked(worker_id: int, headless: bool, chrome_binary: Optional[str],
                         version_main: Optional[int], proxy: Optional[str],
                         uc, extension_path: Optional[str] = None):
    opts = uc.ChromeOptions()
    opts.page_load_strategy = "eager"
    opts.add_argument("--no-first-run")
    opts.add_argument("--no-default-browser-check")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    opts.add_argument("--disable-infobars")
    opts.add_argument("--lang=en-US")
    opts.add_argument("--window-size=1280,900")
    opts.add_argument(f"--remote-debugging-port={_free_port()}")
    # Skip GNOME/KDE keyring + macOS Keychain prompts on Linux desktops —
    # otherwise Chromium blocks startup waiting for the user to unlock the
    # secret store. We don't store passwords in the worker profile, so the
    # plaintext "basic" backend is fine.
    opts.add_argument("--password-store=basic")
    opts.add_argument("--use-mock-keychain")

    # ── Extension + Profile loading ───────────────────────────────────────
    if extension_path and os.path.isdir(extension_path):
        # --extension passed directly via CLI — skip GitHub download and
        # master profile entirely. Just create a plain empty profile and
        # load the extension straight from the given path.
        ext_abs = os.path.abspath(extension_path)
        opts.add_argument(f"--load-extension={ext_abs}")
        opts.add_argument(f"--disable-extensions-except={ext_abs}")
        profile = _create_plain_profile(worker_id)
        print(f"  [worker-{worker_id}] Loading extension directly: {ext_abs}", flush=True)
        print(f"  [worker-{worker_id}] Profile: {profile}", flush=True)
    else:
        # Original flow — copy from master profile (GitHub download or
        # AHREF_MASTER_PROFILE_DIR env var).
        profile = _create_worker_profile(worker_id)
        print(f"  [worker-{worker_id}] Profile: {profile}", flush=True)
        ext_dest = os.path.join(profile, "Extensions", "cf_autoclick")
        if os.path.isdir(ext_dest):
            opts.add_argument(f"--load-extension={ext_dest}")
            opts.add_argument(f"--disable-extensions-except={ext_dest}")
            print(f"  [worker-{worker_id}] Loading extension from profile: {ext_dest}", flush=True)
        else:
            print(f"  [worker-{worker_id}] WARNING: extension dir missing at {ext_dest}",
                  flush=True)
    # ─────────────────────────────────────────────────────────────────────

    if chrome_binary:
        opts.binary_location = chrome_binary

    # Proxy auth extension if needed
    if proxy:
        parts = proxy.split(":")
        if len(parts) == 4:
            ip, port, user, passwd = parts
            ext_zip = os.path.join(tempfile.gettempdir(), f"proxy_ext_w{worker_id}.zip")
            with zipfile.ZipFile(ext_zip, 'w') as zp:
                zp.writestr("manifest.json", json.dumps({
                    "version": "1.0.0", "manifest_version": 2, "name": "Proxy Auth",
                    "permissions": ["proxy", "tabs", "unlimitedStorage", "storage",
                                    "<all_urls>", "webRequest", "webRequestBlocking"],
                    "background": {"scripts": ["background.js"]},
                    "minimum_chrome_version": "22.0.0"
                }))
                zp.writestr("background.js", f"""
                    var config = {{mode: "fixed_servers", rules: {{
                        singleProxy: {{scheme: "http", host: "{ip}", port: parseInt({port})}},
                        bypassList: ["localhost"]
                    }}}};
                    chrome.proxy.settings.set({{value: config, scope: "regular"}}, function(){{}});
                    chrome.webRequest.onAuthRequired.addListener(
                        function(details) {{ return {{authCredentials: {{username: "{user}", password: "{passwd}"}}}}; }},
                        {{urls: ["<all_urls>"]}}, ['blocking']
                    );
                """)
            opts.add_extension(ext_zip)
        elif len(parts) == 2:
            # IP-authorized proxy (no user/pass) — use Chrome's --proxy-server
            opts.add_argument(f"--proxy-server=http://{proxy}")

    _ensure_uc_binary_present()

    driver = uc.Chrome(options=opts, headless=headless, use_subprocess=True,
                       version_main=version_main, user_data_dir=profile)
    driver.set_page_load_timeout(15)
    driver.set_script_timeout(45)

    _snapshot_uc_binary()
    return driver, profile


# ----------------------------------------------------------------------------
# undetected_chromedriver binary cache management
# ----------------------------------------------------------------------------

_UC_BIN_BACKUP = "/tmp/uc_chromedriver.backup"


def _ensure_uc_binary_present() -> None:
    try:
        os.makedirs(UC_CACHE_DIR, exist_ok=True)
    except Exception:
        return
    canonical = os.path.join(UC_CACHE_DIR, "undetected_chromedriver")
    if os.path.exists(canonical):
        return
    if os.path.exists(_UC_BIN_BACKUP):
        try:
            shutil.copy2(_UC_BIN_BACKUP, canonical)
            os.chmod(canonical, 0o755)
            print(f"  [uc-cache] restored chromedriver from backup", flush=True)
        except Exception as e:
            print(f"  [uc-cache] restore failed: {e}", flush=True)


def _snapshot_uc_binary() -> None:
    canonical = os.path.join(UC_CACHE_DIR, "undetected_chromedriver")
    if not os.path.exists(canonical):
        return
    try:
        if os.path.exists(_UC_BIN_BACKUP):
            try:
                if os.path.getsize(canonical) == os.path.getsize(_UC_BIN_BACKUP):
                    return
            except Exception:
                pass
        shutil.copy2(canonical, _UC_BIN_BACKUP)
    except Exception:
        pass


def scrape_domain(driver, domain: str, mode: CheckerMode) -> Dict[str, Any]:
    """Process a single domain in the browser using the given mode."""
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.action_chains import ActionChains
    from selenium.common.exceptions import WebDriverException

    t0 = time.time()
    row: Dict[str, Any] = {"domain_name": domain, "status": "error"}

    try:
        try:
            driver.get(mode.build_url(domain))
        except Exception:
            pass

        # Domain is supplied via the URL (?input=<domain>), so Ahrefs auto-runs
        # the check — no input typing/submit. Let the page settle, then inject
        # the extract-only JS which waits for the result modal directly.
        time.sleep(2)

        js_template = load_mode_js(mode.spec_path)
        js_payload = js_template.replace("${domains}", domain)

        kickoff_js = f"""
            window.addEventListener('message', function(e){{
                if (e && e.data && e.data.type === 'TURNSTILE_FOCUS_REQUEST') {{
                    window.postMessage({{type:'TURNSTILE_FOCUS_RESPONSE',success:true,reason:'no_turnstile'}},'*');
                }}
            }});
            window.__ahrefsResult = undefined;
            window.__ahrefsError = undefined;
            (async function() {{
                try {{
                    var r = await (async function() {{ {js_payload} }})();
                    window.__ahrefsResult = r;
                }} catch (err) {{
                    window.__ahrefsError = JSON.stringify({{error:String(err&&err.message||err)}});
                }}
            }})();
        """
        driver.execute_script(kickoff_js)

        poll_deadline = time.time() + (120 if mode.name == "traffic" else 60)
        last_click = 0.0

        while time.time() < poll_deadline:
            try:
                done_raw = driver.execute_script(
                    "return JSON.stringify({r:window.__ahrefsResult,e:window.__ahrefsError})"
                )
                done_payload = json.loads(done_raw) if done_raw else {}
            except Exception:
                time.sleep(1)
                continue

            if done_payload.get("r") is not None:
                raw = done_payload["r"]
                parsed = json.loads(raw) if isinstance(raw, str) else raw
                if isinstance(parsed, dict) and "results" in parsed:
                    row = mode.extract_row(parsed, domain)
                break

            if done_payload.get("e") is not None:
                row["error"] = done_payload["e"]
                break

            now = time.time()
            if now - last_click > 4:
                try:
                    for f in driver.find_elements(By.TAG_NAME, "iframe"):
                        if "challenges.cloudflare.com" in (f.get_attribute("src") or ""):
                            ActionChains(driver, duration=100).move_to_element_with_offset(
                                f, random.randint(20, 35), random.randint(15, 25)
                            ).pause(0.15).click().perform()
                            last_click = now
                            break
                except (WebDriverException, Exception):
                    pass

            time.sleep(1.0)

    except Exception as e:
        row["error"] = f"{type(e).__name__}: {e}"
    finally:
        row["elapsed_seconds"] = round(time.time() - t0, 2)
        row["finished_at"] = datetime.now(timezone.utc).isoformat()
    return row


# Thread-safe print
_print_lock = threading.Lock()
def tprint(msg):
    with _print_lock:
        print(msg)


def pull_domain(api_url: str, mode: CheckerMode) -> Optional[Dict[str, Any]]:
    try:
        resp = _HTTP.get(f"{api_url}{mode.endpoint}", timeout=(10, 30))
        if resp.status_code == 204:
            return None
        resp.raise_for_status()
        data = resp.json()
        if data.get("success"):
            return data["data"]
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 204:
            return None
    except Exception as e:
        tprint(f"  [pull] error after retries: {e}")
    return None


def post_result(api_url: str, mode: CheckerMode, execution_record: Dict, result: Dict) -> bool:
    try:
        resp = _HTTP.post(
            f"{api_url}{mode.endpoint}",
            json={"execution_record": execution_record, "result": result},
            timeout=(10, 60),
        )
        resp.raise_for_status()
        ok = resp.json().get("success", False)
        if not ok:
            _buffer_ahref_failed_post(mode, execution_record, result)
        return ok
    except Exception as e:
        tprint(f"  [post] error after retries: {e}; buffering result for {result.get('domain_name')}")
        _buffer_ahref_failed_post(mode, execution_record, result)
        return False


# ----------------------------------------------------------------------------
# Persistent post buffer
# ----------------------------------------------------------------------------

def _ahref_post_buffer_path(mode: CheckerMode) -> str:
    return os.environ.get(
        f"AHREF_{mode.name.upper()}_POST_BUFFER",
        f"/tmp/ahref-local_pending_posts_{mode.name}.jsonl",
    )


_ahref_buffer_lock = threading.Lock()


def _buffer_ahref_failed_post(mode: CheckerMode, execution_record: Dict, result: Dict) -> None:
    try:
        with _ahref_buffer_lock:
            with open(_ahref_post_buffer_path(mode), "a", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "execution_record": execution_record,
                    "result": result,
                }) + "\n")
    except Exception as e:
        print(f"  [buffer] FATAL: cannot write ahref post buffer: {e}", flush=True)


def _flush_pending_ahref_posts(api_url: str, mode: CheckerMode, max_per_run: int = 50) -> int:
    buf_path = _ahref_post_buffer_path(mode)
    if not os.path.exists(buf_path):
        return 0
    flushed = 0
    remaining: List[str] = []
    with _ahref_buffer_lock:
        try:
            with open(buf_path, "r", encoding="utf-8") as fh:
                lines = fh.readlines()
        except Exception:
            return 0
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if flushed >= max_per_run:
                remaining.append(line)
                continue
            try:
                obj = json.loads(line)
                resp = _HTTP.post(
                    f"{api_url}{mode.endpoint}",
                    json={"execution_record": obj["execution_record"],
                          "result": obj["result"]},
                    timeout=(10, 60),
                )
                if resp.status_code < 400 and resp.json().get("success"):
                    flushed += 1
                    continue
            except Exception:
                pass
            remaining.append(line)
        try:
            with open(buf_path, "w", encoding="utf-8") as fh:
                for ln in remaining:
                    fh.write(ln + "\n")
        except Exception:
            pass
    return flushed


def _start_ahref_buffer_flusher(api_url: str, mode: CheckerMode) -> threading.Thread:
    def loop():
        while True:
            time.sleep(30)
            try:
                n = _flush_pending_ahref_posts(api_url, mode)
                if n:
                    tprint(f"  [flusher] re-sent {n} buffered {mode.name} posts")
            except Exception as e:
                tprint(f"  [flusher] error: {e}")
    t = threading.Thread(target=loop, daemon=True, name=f"ahref-{mode.name}-post-flusher")
    t.start()
    return t


# ----------------------------------------------------------------------------
# Browser healthcheck
# ----------------------------------------------------------------------------

def _is_driver_alive(driver) -> bool:
    if driver is None:
        return False
    try:
        return driver.execute_script("return 1") == 1
    except Exception:
        return False


def worker_loop(worker_id: int, proxy: Optional[str], api_url: str, headless: bool,
                chrome_bin: Optional[str], version_main: Optional[int],
                modes: List[CheckerMode], extension_path: Optional[str] = None):
    """Single worker: opens browser, pulls and processes domains forever."""
    proxy_short = proxy.split(":")[0] if proxy else "local"
    mode_names = ",".join(m.name for m in modes)
    tprint(f"  [W{worker_id}] Starting [modes={mode_names}] with proxy {proxy_short}...")

    driver = None
    profile_path: Optional[str] = None
    processed = 0
    rr_offset = worker_id % max(1, len(modes))

    def start_browser():
        nonlocal driver, profile_path
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
            time.sleep(2)
        old_profile = profile_path
        if old_profile:
            _remove_worker_profile(old_profile)
        profile_path = None

        last_err = None
        for attempt in range(10):
            try:
                driver, profile_path = build_driver(
                    worker_id, headless=headless, chrome_binary=chrome_bin,
                    version_main=version_main, proxy=proxy,
                    extension_path=extension_path,
                )
                if _is_driver_alive(driver):
                    break
                raise RuntimeError("driver built but is_alive() returned False")
            except Exception as e:
                last_err = e
                tprint(f"  [W{worker_id}] driver build attempt {attempt+1}/10 failed: {e}")
                try:
                    if driver:
                        driver.quit()
                except Exception:
                    pass
                driver = None
                if profile_path:
                    _remove_worker_profile(profile_path)
                    profile_path = None
                sleep_s = min(5 * (2 ** attempt), 60)
                time.sleep(sleep_s)
        if driver is None:
            raise RuntimeError(f"driver build failed after 10 attempts: {last_err}")
        try:
            driver.get("about:blank")
        except Exception:
            pass
        tprint(f"  [W{worker_id}] Browser ready (proxy: {proxy_short}, profile: {profile_path})")

    def _pull_any() -> Optional[tuple]:
        nonlocal rr_offset
        n = len(modes)
        for i in range(n):
            mode = modes[(rr_offset + i) % n]
            record = pull_domain(api_url, mode)
            if record is not None:
                rr_offset = (rr_offset + i + 1) % n
                return mode, record
        return None

    try:
        start_browser()
        last_healthcheck = time.time()

        while True:
            now = time.time()
            if now - last_healthcheck > 60:
                if not _is_driver_alive(driver):
                    tprint(f"  [W{worker_id}] healthcheck failed — rebuilding browser")
                    start_browser()
                last_healthcheck = now

            pull_result = _pull_any()

            if pull_result is None:
                time.sleep(3 + random.random() * 2)
                continue

            mode, record = pull_result
            domain = record.get("domain_name", "unknown")
            execution_id = record.get("execution_id", "?")[:8]
            tprint(f"  [W{worker_id}] Got [{mode.name}]: {domain} (exec: {execution_id})")

            try:
                result = scrape_domain(driver, domain, mode)
                mark = "OK" if result["status"] == "completed" else "FAIL"
                if mode.name == "authority":
                    tprint(f"  [W{worker_id}] [{mark}][{mode.name}] {domain} "
                           f"DR={result.get('dr', '-')} BL={result.get('backlinks', '-')} "
                           f"({result['elapsed_seconds']:.1f}s)")
                else:
                    tprint(f"  [W{worker_id}] [{mark}][{mode.name}] {domain} "
                           f"OT={result.get('organic_traffic', '-')} "
                           f"TV={result.get('traffic_value', '-')} "
                           f"({result['elapsed_seconds']:.1f}s)")
                try:
                    driver.get("about:blank")
                except Exception:
                    tprint(f"  [W{worker_id}] post-scrape navigation failed; rebuilding browser")
                    start_browser()
            except Exception as e:
                tprint(f"  [W{worker_id}] Error: {e.__class__.__name__}: {e}. Restarting browser...")
                try:
                    start_browser()
                except Exception as e2:
                    tprint(f"  [W{worker_id}] FATAL: cannot rebuild browser: {e2}")
                    raise
                result = {"domain_name": domain, "status": "error", "error": str(e)}

            post_result(api_url, mode, record, result)
            processed += 1

            if processed > 0 and processed % 50 == 0:
                tprint(f"  [W{worker_id}] processed {processed} — recycling browser")
                try:
                    start_browser()
                except Exception as e:
                    tprint(f"  [W{worker_id}] recycle failed (continuing): {e}")

    except KeyboardInterrupt:
        pass
    except Exception as e:
        tprint(f"  [W{worker_id}] FATAL: {e}")
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
        if profile_path:
            _remove_worker_profile(profile_path)
            tprint(f"  [W{worker_id}] Cleaned up profile {profile_path}")
        tprint(f"  [W{worker_id}] Stopped. Processed: {processed}")


def main():
    p = argparse.ArgumentParser(
        description="Ahrefs Checker — Parallel Pull Mode. By default the worker "
                    "polls BOTH /ahref-authority/ and /ahref-traffic/ in round-robin "
                    "and processes whichever queue has a message.",
    )
    p.add_argument("--api-url", default=DEFAULT_API_URL)
    p.add_argument("--modes", default="authority,traffic",
                   help="Comma-separated list of Ahrefs checks to pull (default: "
                        "'authority,traffic'). Set to 'authority' or 'traffic' to "
                        "lock the worker to one queue.")
    p.add_argument("--mode", choices=list(MODES.keys()),
                   help="DEPRECATED — use --modes.")
    p.add_argument("--headless", action="store_true")
    p.add_argument("--workers", type=int, default=5, help="Number of parallel browser instances")
    p.add_argument("--chrome", help="Path to chrome/chromium binary")
    p.add_argument("--extension", help="Direct path to unpacked extension folder "
                                       "(e.g. ~/Downloads/cf-autoclick-master). "
                                       "Skips GitHub profile download entirely.")
    p.add_argument("--proxies", default=PROXIES_PATH, help="Path to proxies file")
    p.add_argument("--no-proxy", action="store_true", help="Disable proxies")
    p.add_argument("--webshare-proxy", action="store_true",
                   help="Use Webshare rotating proxy (p.webshare.io:9999 with IP auth)")
    args = p.parse_args()

    # Resolve --modes / --mode
    raw_modes = args.modes if args.modes else (args.mode or "authority,traffic")
    requested = [m.strip().lower() for m in raw_modes.split(",") if m.strip()]
    unknown = [m for m in requested if m not in MODES]
    if unknown:
        print(f"[FATAL] Unknown mode(s): {unknown}. Valid: {list(MODES.keys())}",
              file=sys.stderr)
        sys.exit(2)
    if not requested:
        print(f"[FATAL] No modes given. Pass --modes authority,traffic.", file=sys.stderr)
        sys.exit(2)
    enabled_modes = [MODES[m] for m in requested]

    _install_signal_handlers()

    # Validate --extension path if provided
    extension_path: Optional[str] = None
    if args.extension:
        extension_path = os.path.abspath(os.path.expanduser(args.extension))
        if not os.path.isdir(extension_path):
            print(f"[FATAL] --extension path does not exist or is not a directory: {extension_path}",
                  file=sys.stderr)
            sys.exit(2)
        manifest = os.path.join(extension_path, "manifest.json")
        if not os.path.isfile(manifest):
            print(f"[FATAL] --extension folder has no manifest.json: {extension_path}",
                  file=sys.stderr)
            sys.exit(2)
        print(f"[*] Extension: {extension_path} (direct --load-extension, skipping GitHub profile)",
              flush=True)
    else:
        # Auto-discover the vendored cf-autoclick clone before falling back to
        # the GitHub master-profile download. This is what tools/setup_vendor.sh
        # populates — running ahrefs_checker.py with no flags should Just Work.
        script_dir = os.path.dirname(os.path.abspath(__file__))
        vendored_ext = os.path.join(script_dir, "vendor", "cf-autoclick")
        if os.path.isfile(os.path.join(vendored_ext, "manifest.json")):
            extension_path = vendored_ext
            print(f"[*] Extension: {extension_path} (auto-discovered from vendor/, "
                  f"skipping GitHub profile)", flush=True)
        else:
            # Only download master profile when --extension is NOT passed AND
            # vendor/cf-autoclick is missing.
            try:
                _download_master_profile()
            except Exception as e:
                print(f"[FATAL] Cannot bootstrap master profile: {e}", file=sys.stderr)
                sys.exit(2)

    proxies = [] if args.no_proxy else load_proxies()
    num_workers = args.workers

    # Webshare rotating proxy — authorize IP and override proxies list
    if args.webshare_proxy:
        my_ip = webshare_get_my_ip()
        print(f"[*] Public IP: {my_ip}", flush=True)
        webshare_authorize_ip(my_ip)
        atexit.register(webshare_deauthorize_ip)
        proxies = [f"{WEBSHARE_PROXY_HOST}:{WEBSHARE_PROXY_PORT}"]
        print(f"[*] Webshare proxy: {proxies[0]}", flush=True)
        # Give Webshare a moment to propagate the IP auth
        time.sleep(3)

    if not args.no_proxy and not args.webshare_proxy and not proxies:
        print("[WARN] No proxies found. Running all instances on local IP.")

    chrome_bin = args.chrome or find_chrome_binary()
    version_main = detect_chrome_major(chrome_bin)

    mode_summary = ", ".join(f"{m.name}->{m.endpoint}" for m in enabled_modes)
    print(f"[*] Ahrefs Checker - Parallel Pull Mode")
    print(f"[*] Modes: {mode_summary}")
    print(f"[*] API: {args.api_url}")
    print(f"[*] Chrome: {chrome_bin}")
    print(f"[*] Workers: {num_workers} | Proxy: {'disabled' if args.no_proxy or not proxies else f'{len(proxies)} loaded'}")
    print(f"[*] Launching {num_workers} browser instances...\n")

    for mode in enabled_modes:
        initial = _flush_pending_ahref_posts(args.api_url, mode, max_per_run=200)
        if initial:
            print(f"[*] Recovered {initial} buffered {mode.name} posts from previous run")
        _start_ahref_buffer_flusher(args.api_url, mode)

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = []
        for i in range(num_workers):
            proxy = proxies[i % len(proxies)] if proxies else None
            f = executor.submit(
                worker_loop, i, proxy, args.api_url, args.headless,
                chrome_bin, version_main, enabled_modes,
                extension_path,  # passed directly to each worker
            )
            futures.append(f)
            time.sleep(10)

        try:
            for f in futures:
                f.result()
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")


if __name__ == "__main__":
    main()
