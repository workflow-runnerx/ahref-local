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
                             [--proxy host:port[:user:pass]]

    Batch mode (no queue server — fixed list in, JSON out):
    python ahrefs_checker.py --domains-file domains.txt --out results.json \
                             --proxy brd.superproxy.io:44445:USER:PASS --modes authority
    Authority batches solve ONE Turnstile captcha in the browser and reuse its
    token over Ahrefs' own API for the rest of the list (see "Batch mode").

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
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

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
    """Remove a single per-worker profile dir and stop tracking it.

    Chromium keeps flushing its disk cache for a moment after driver.quit()
    returns, so a single rmtree races with the browser and leaves a stub
    (Default/Cache/...) behind. Retry a few times until the dir is gone."""
    if not path:
        return
    # Chromium is still shutting down when driver.quit() returns and re-creates
    # Default/Cache + "Network Persistent State" a second or two later, so a
    # single rmtree leaves a stub behind. Keep removing until the directory
    # has stayed absent for a few consecutive polls (or ~12 s have passed).
    deadline = time.time() + 12
    absent_polls = 0
    while time.time() < deadline:
        try:
            if os.path.isdir(path):
                absent_polls = 0
                shutil.rmtree(path, ignore_errors=True)
            else:
                absent_polls += 1
                if absent_polls >= 4:
                    break
        except Exception:
            pass
        time.sleep(0.5)
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
# Proxy handling
#
# Proxy specs are "host:port" (IP-authorised) or "host:port:user:pass".
# Chromium never talks to the upstream proxy itself: every browser gets a
# local fingerprint proxy (fingerprint_proxy.py) on 127.0.0.1:<port> that
# terminates TLS with a locally-signed leaf cert and re-issues each request
# through curl_cffi impersonating Chrome, optionally via the upstream proxy.
# Cloudflare therefore scores curl_cffi's Chrome TLS ClientHello / h2
# fingerprint instead of the vendored ungoogled-chromium's, while cookies,
# User-Agent and all other headers come from the real browser untouched.
# (The previous CONNECT auth forwarder only injected Proxy-Authorization and
# let the browser's own TLS pass through.)
#
# Bright Data: the ISP zone hands out a different exit IP on every connection
# unless the username carries a "-session-<id>" suffix. Cloudflare binds its
# cookies/Turnstile token to the exit IP, so every worker gets its own sticky
# session id (see make_sticky_proxy).
# ----------------------------------------------------------------------------

_FORWARDERS: Dict[str, Any] = {}          # upstream key -> FingerprintProxy
_FORWARDERS_LOCK = threading.Lock()

# Set AHREF_FP_DIRECT=1 to route the browser through the fingerprint proxy
# even with --no-proxy (no upstream; useful to verify the fingerprint locally).
FP_DIRECT = os.environ.get("AHREF_FP_DIRECT", "") not in ("", "0", "false")


def parse_proxy(spec: Optional[str]) -> Optional[Dict[str, Any]]:
    """Parse 'host:port' / 'host:port:user:pass' (also accepts scheme://user:pass@host:port)."""
    if not spec:
        return None
    spec = spec.strip()
    if "://" in spec:
        from urllib.parse import urlparse, unquote
        u = urlparse(spec)
        return {"host": u.hostname, "port": int(u.port or 80),
                "user": unquote(u.username) if u.username else None,
                "passwd": unquote(u.password) if u.password else None}
    parts = spec.split(":")
    if len(parts) == 2:
        return {"host": parts[0], "port": int(parts[1]), "user": None, "passwd": None}
    if len(parts) >= 4:
        # password may itself contain ':' — re-join the tail
        return {"host": parts[0], "port": int(parts[1]), "user": parts[2],
                "passwd": ":".join(parts[3:])}
    raise ValueError(f"Bad proxy spec {spec!r}; expected host:port or host:port:user:pass")


def format_proxy(p: Optional[Dict[str, Any]]) -> Optional[str]:
    if not p:
        return None
    if p.get("user"):
        return f"{p['host']}:{p['port']}:{p['user']}:{p['passwd']}"
    return f"{p['host']}:{p['port']}"


def make_sticky_proxy(spec: Optional[str], session_id: Optional[str] = None) -> Optional[str]:
    """Give Bright Data (brd.superproxy.io) proxies a sticky session so all
    connections of one worker share one exit IP. Other providers pass through."""
    p = parse_proxy(spec)
    if not p or not p.get("user"):
        return spec
    host = (p.get("host") or "").lower()
    if "superproxy.io" not in host and "brd-customer" not in p["user"]:
        return spec
    if "-session-" in p["user"]:
        return spec
    sid = session_id or uuid.uuid4().hex[:10]
    p["user"] = f"{p['user']}-session-{sid}"
    return format_proxy(p)


def proxy_for_requests(spec: Optional[str]) -> Optional[Dict[str, str]]:
    """requests-style proxies dict for the same proxy the browser uses."""
    p = parse_proxy(spec)
    if not p:
        return None
    from urllib.parse import quote
    if p.get("user"):
        url = f"http://{quote(p['user'], safe='')}:{quote(p['passwd'] or '', safe='')}@{p['host']}:{p['port']}"
    else:
        url = f"http://{p['host']}:{p['port']}"
    return {"http": url, "https": url}


def _start_fingerprint_proxy(host: Optional[str], port: Optional[int],
                             user: Optional[str], passwd: Optional[str]) -> int:
    """Start (once per upstream) the local TLS/h2 fingerprint proxy and
    return its port. host=None means no upstream (direct)."""
    from fingerprint_proxy import FingerprintProxy, upstream_url

    upstream = upstream_url(host, port, user, passwd) if host else None
    key = upstream or "direct"
    with _FORWARDERS_LOCK:
        fp = _FORWARDERS.get(key)
        if fp is not None:
            return fp.port
        fp = FingerprintProxy(upstream=upstream)
        lport = fp.start()
        _FORWARDERS[key] = fp
        who = f"{host}:{port} (user {user[:24]}{'…' if user and len(user) > 24 else ''})" if host else "direct"
        print(f"  [proxy] fingerprint proxy 127.0.0.1:{lport} -> {who} "
              f"[curl_cffi impersonate={fp.impersonate}]", flush=True)
        return lport


def _stop_fingerprint_proxies() -> None:
    with _FORWARDERS_LOCK:
        fps = list(_FORWARDERS.values())
        _FORWARDERS.clear()
    for fp in fps:
        try:
            fp.stop()
        except Exception:
            pass


atexit.register(_stop_fingerprint_proxies)


BURNED_IPS_PATH = os.environ.get(
    "AHREF_BURNED_IPS",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "burned_ips.txt"),
)
_BURNED_LOCK = threading.Lock()


def load_burned_ips(path: str = BURNED_IPS_PATH) -> Dict[str, str]:
    """burned_ips.txt: one line per IP — 'ip<TAB>when<TAB>reason'. Returns {ip: when}."""
    out: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                out[parts[0].strip()] = parts[1] if len(parts) > 1 else ""
    except FileNotFoundError:
        pass
    except Exception as e:
        tprint(f"  [burned] cannot read {path}: {e}")
    return out


def mark_ip_burned(ip: Optional[str], reason: str, path: str = BURNED_IPS_PATH) -> None:
    if not ip:
        return
    with _BURNED_LOCK:
        if ip in load_burned_ips(path):
            return
        try:
            new_file = not os.path.exists(path)
            with open(path, "a", encoding="utf-8") as fh:
                if new_file:
                    fh.write("# exit IPs that Ahrefs/Cloudflare rejected — never reused. ip<TAB>when(UTC)<TAB>reason\n")
                fh.write(f"{ip}\t{datetime.now(timezone.utc).isoformat(timespec='seconds')}\t{reason}\n")
            tprint(f"  [burned] {ip} added to {os.path.basename(path)} ({reason})")
        except Exception as e:
            tprint(f"  [burned] cannot write {path}: {e}")


def exit_ip_via_requests(spec: Optional[str], timeout: float = 15.0) -> Optional[str]:
    """Resolve the exit IP of a proxy spec with a plain HTTP request (no browser)."""
    try:
        r = requests.get("https://api.ipify.org", proxies=proxy_for_requests(spec), timeout=timeout)
        ip = r.text.strip()
        return ip if r.status_code == 200 and len(ip) <= 45 else None
    except Exception as e:
        tprint(f"  [proxy] exit IP lookup failed: {str(e)[:100]}")
        return None


def chrome_proxy_arg(spec: Optional[str]) -> Optional[str]:
    """Translate a proxy spec into a --proxy-server value Chromium can use.
    Always the local fingerprint proxy — IP-authorised proxies too, otherwise
    the browser's own TLS fingerprint would reach Cloudflare."""
    p = parse_proxy(spec)
    if not p:
        if FP_DIRECT:
            return f"http://127.0.0.1:{_start_fingerprint_proxy(None, None, None, None)}"
        return None
    lport = _start_fingerprint_proxy(p["host"], p["port"], p.get("user"), p.get("passwd") or "")
    return f"http://127.0.0.1:{lport}"


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
        # Prefer ungoogled-chromium (supports --load-extension, which branded
        # Google Chrome 137+ dropped). Order: vendored .app in vendor/, then the
        # `brew install --cask ungoogled-chromium` install, then plain Chromium,
        # and only then Google Chrome as a last resort.
        script_dir = os.path.dirname(os.path.abspath(__file__))
        home = os.path.expanduser("~")
        candidates = [
            os.path.join(script_dir, "vendor", "ungoogled-chromium", "Chromium.app",
                         "Contents", "MacOS", "Chromium"),
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            os.path.join(home, "Applications", "Chromium.app", "Contents", "MacOS", "Chromium"),
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        ]
    elif system == "Windows":
        for env in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
            base = os.environ.get(env, "")
            if base:
                candidates.append(os.path.join(base, "Google", "Chrome", "Application", "chrome.exe"))
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return None


def find_chromedriver_binary(chrome_binary: Optional[str]) -> Optional[str]:
    """chromedriver shipped next to the vendored Linux chrome binary, or
    AHREF_CHROMEDRIVER; None lets undetected-chromedriver download one."""
    env = os.environ.get("AHREF_CHROMEDRIVER")
    if env and os.path.isfile(env):
        return env
    if chrome_binary and platform.system() == "Linux":
        cand = os.path.join(os.path.dirname(os.path.abspath(chrome_binary)), "chromedriver")
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
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
                 extension_path: Optional[str] = None, perf_log: bool = False):
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
                extension_path=extension_path, perf_log=perf_log,
            )
        finally:
            _release_driver_build_lock(file_lock)


def _build_driver_locked(worker_id: int, headless: bool, chrome_binary: Optional[str],
                         version_main: Optional[int], proxy: Optional[str],
                         uc, extension_path: Optional[str] = None,
                         perf_log: bool = False):
    opts = uc.ChromeOptions()
    if perf_log:
        # Batch mode reads the Turnstile token out of the network log.
        opts.set_capability("goog:loggingPrefs", {"performance": "ALL", "browser": "ALL"})
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
    # Extra Chromium switches, space separated (e.g. software WebGL inside a
    # GPU-less container — see docker/Dockerfile for the default used there).
    for extra in (os.environ.get("AHREF_CHROME_ARGS") or "").split():
        opts.add_argument(extra)

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

    # Proxy: host:port goes straight to --proxy-server; host:port:user:pass is
    # routed through the in-process auth forwarder (MV2 auth extensions no
    # longer load in current Chromium builds — see chrome_proxy_arg()).
    proxy_arg = chrome_proxy_arg(proxy) if (proxy or FP_DIRECT) else None
    if proxy_arg:
        opts.add_argument(f"--proxy-server={proxy_arg}")
        # The fingerprint proxy terminates TLS with leaf certs from its own
        # local CA (~/.ahref-fp-proxy/ca.pem). Unless the CA has been trusted
        # in the browser's store (AHREF_FP_CA_TRUSTED=1, e.g. certutil into
        # ~/.pki/nssdb on Linux — see docker/entrypoint.sh), accept them.
        ca_trusted = os.environ.get("AHREF_FP_CA_TRUSTED", "") not in ("", "0", "false")
        if not ca_trusted:
            opts.add_argument("--ignore-certificate-errors")
        print(f"  [worker-{worker_id}] --proxy-server={proxy_arg} (fingerprint proxy, "
              f"{'CA trusted' if ca_trusted else '--ignore-certificate-errors'})", flush=True)

    _ensure_uc_binary_present()

    # Linux: the vendored ungoogled-chromium tarball ships a matching
    # chromedriver; use it instead of undetected-chromedriver's download
    # (Google publishes no linux-arm64 chromedriver at all). uc patches the
    # given binary in place on first use.
    driver_path = find_chromedriver_binary(chrome_binary)
    if driver_path:
        print(f"  [worker-{worker_id}] chromedriver: {driver_path} (vendored)", flush=True)

    driver = uc.Chrome(options=opts, headless=headless, use_subprocess=True,
                       version_main=version_main, user_data_dir=profile,
                       driver_executable_path=driver_path)
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
            print("  [uc-cache] restored chromedriver from backup", flush=True)
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


# ── Turnstile interactive checkbox ───────────────────────────────────────────
# When Cloudflare escalates from the invisible check to "Verify you are
# human", the widget is a ~300×65 <iframe> whose src is EMPTY (the challenge
# frame is navigated programmatically). Matching on src therefore finds
# nothing — that is why the old ActionChains fallback (and cf-autoclick's own
# lookup) never clicked it. Find it by its box instead and click through CDP.
TURNSTILE_MAX_CLICKS = int(os.environ.get("AHREF_TURNSTILE_CLICKS", "2"))  # 0 = never click (measure the invisible pass)
TURNSTILE_CLICK_GAP_S = 8.0       # a rejected click shows "Troubleshoot"; more clicks never help
TURNSTILE_CLICK_GRACE_S = 6.0     # managed mode shows "Verifying…" first; give it a chance before clicking

_TURNSTILE_WIDGET_JS = """
return (function(){
  var out=[], ifr=document.querySelectorAll('iframe');
  for (var i=0;i<ifr.length;i++){
    var f=ifr[i], r=f.getBoundingClientRect(), src=f.src||'', title=f.title||'';
    var bySrc=src.indexOf('challenges.cloudflare.com')!==-1, byTitle=/cloudflare/i.test(title);
    var byBox=r.width>=240&&r.width<=360&&r.height>=50&&r.height<=90;
    if (bySrc||byTitle||byBox) out.push({x:r.left,y:r.top,w:r.width,h:r.height,
        how:bySrc?'src':(byTitle?'title':'box'), html:(f.outerHTML||'').slice(0,600)});
  }
  return out;
})();
"""


def _find_turnstile_widget(driver) -> Optional[Dict[str, Any]]:
    """Viewport box of the Turnstile widget iframe, or None. Light DOM first,
    then a CDP pierce through shadow roots (some widget variants live there)."""
    try:
        found = driver.execute_script(_TURNSTILE_WIDGET_JS) or []
        found = [b for b in found if b.get("w", 0) > 0 and b.get("h", 0) > 0]
        if found:
            return found[0]
    except Exception:
        pass
    try:
        driver.execute_cdp_cmd("DOM.enable", {})
        nodes = driver.execute_cdp_cmd("DOM.getFlattenedDocument", {"depth": -1, "pierce": True})["nodes"]
        for n in nodes:
            if n.get("nodeName") != "IFRAME":
                continue
            try:
                m = driver.execute_cdp_cmd("DOM.getBoxModel", {"nodeId": n["nodeId"]})["model"]["content"]
            except Exception:
                continue
            w, h = m[4] - m[0], m[5] - m[1]
            if 240 <= w <= 360 and 50 <= h <= 90:
                attrs = n.get("attributes") or []
                html = "<iframe " + " ".join(f'{attrs[i]}="{attrs[i+1]}"' for i in range(0, len(attrs) - 1, 2)) + ">"
                return {"x": m[0], "y": m[1], "w": w, "h": h, "how": "cdp-box", "html": html[:600]}
    except Exception:
        pass
    return None


def _cdp_click_turnstile(driver, box: Dict[str, Any]) -> Optional[Tuple[int, int]]:
    """Trusted click on the checkbox (≈20 px from the widget's left edge, vertically
    centred) via Input.dispatchMouseEvent, with a short approach path first."""
    x = box["x"] + 20 + random.uniform(-3, 3)
    y = box["y"] + box["h"] / 2 + random.uniform(-3, 3)
    try:
        sx, sy = x - random.randint(120, 220), y + random.randint(80, 160)
        steps = 8
        for i in range(1, steps + 1):
            driver.execute_cdp_cmd("Input.dispatchMouseEvent", {
                "type": "mouseMoved", "x": sx + (x - sx) * i / steps, "y": sy + (y - sy) * i / steps, "button": "none"})
            time.sleep(random.uniform(0.02, 0.05))
        time.sleep(random.uniform(0.1, 0.25))
        driver.execute_cdp_cmd("Input.dispatchMouseEvent", {
            "type": "mousePressed", "x": x, "y": y, "button": "left", "buttons": 1, "clickCount": 1})
        time.sleep(random.uniform(0.03, 0.08))
        driver.execute_cdp_cmd("Input.dispatchMouseEvent", {
            "type": "mouseReleased", "x": x, "y": y, "button": "left", "buttons": 0, "clickCount": 1})
        return int(x), int(y)
    except Exception as e:
        tprint(f"  [turnstile] CDP click failed: {type(e).__name__}: {e}")
        return None


def _save_evidence(driver, domain: str, tag: str) -> Optional[str]:
    """Screenshot into AHREF_EVIDENCE_DIR (if set) when Turnstile escalates."""
    d = os.environ.get("AHREF_EVIDENCE_DIR")
    if not d:
        return None
    try:
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, f"turnstile-{domain}-{tag}-{int(time.time())}.png")
        driver.save_screenshot(path)
        return path
    except Exception:
        return None


def scrape_domain(driver, domain: str, mode: CheckerMode) -> Dict[str, Any]:
    """Process a single domain in the browser using the given mode."""
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

        poll_deadline = time.time() + 45
        last_click = 0.0
        clicks = 0
        widget_seen = 0.0

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
                    ts = {k: v for k, v in row.items() if k.startswith("turnstile_")}
                    row = mode.extract_row(parsed, domain)
                    row.update(ts)            # keep the checkbox evidence on the result row
                break

            if done_payload.get("e") is not None:
                row["error"] = done_payload["e"]
                break

            # Fast fail: Ahrefs shows "Something went wrong" within a few
            # seconds when Cloudflare rejected this IP's captcha. Don't sit
            # out the full modal timeout — flag it and leave immediately.
            if _page_says_something_went_wrong(driver):
                row["ip_blocked"] = True
                row["error"] = "IP blocked: Ahrefs shows 'Something went wrong'"
                break

            # Interactive checkbox fallback (cf-autoclick cannot find the
            # src-less widget iframe — see _find_turnstile_widget).
            now = time.time()
            if now - last_click > TURNSTILE_CLICK_GAP_S:
                box = _find_turnstile_widget(driver)
                if box and not widget_seen:
                    widget_seen = now
                    row["turnstile_widget"] = True
                    row["turnstile_widget_html"] = box.get("html")
                    shot = _save_evidence(driver, domain, "widget")
                    tprint(f"  [turnstile] {domain}: widget visible ({box['how']}, "
                           f"{int(box['w'])}x{int(box['h'])} at {int(box['x'])},{int(box['y'])})"
                           + (f" — {shot}" if shot else ""))
                if (box and clicks < TURNSTILE_MAX_CLICKS and now - widget_seen >= TURNSTILE_CLICK_GRACE_S):
                    # still there after the grace period: managed mode escalated to the checkbox
                    if clicks == 0:
                        row["turnstile_interactive"] = True
                        _save_evidence(driver, domain, "checkbox")
                    pt = _cdp_click_turnstile(driver, box)
                    if pt:
                        clicks += 1
                        last_click = now
                        tprint(f"  [turnstile] {domain}: click #{clicks} at {pt} "
                               f"({now - widget_seen:.0f}s after the widget appeared)")

            time.sleep(1.0)

        if row.get("turnstile_widget"):
            row["turnstile_clicks"] = clicks
            row["turnstile_widget_seconds"] = round(widget_seen - t0, 1)
        if row.get("turnstile_widget") and row.get("status") != "completed":
            shot = _save_evidence(driver, domain, "final")
            if shot:
                tprint(f"  [turnstile] {domain}: not solved after {clicks} click(s) — {shot}")

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


# ----------------------------------------------------------------------------
# Batch mode — one captcha, many domains.
#
# The authority checker page calls
#     POST https://ahrefs.com/v4/stGetFreeWebsiteOverview
#     {"url": "<domain>", "captcha": "<Cloudflare Turnstile token>"}
# and the token is NOT single-use: for roughly four minutes the same token
# answers for any domain, from plain HTTP, as long as the request carries the
# browser's cookies, User-Agent and comes from the same exit IP. So in batch
# mode we solve the captcha once in the real browser (which also yields the
# first result), lift the token from the network log, and fan the remaining
# domains out over the API at a moderate concurrency. When the token ages
# out or starts being rejected we mint a fresh one with the next domain.
#
# Measured: ~1.5 s per API call, 5 concurrent ≈ 200 domains/min, sporadic
# "InvalidCaptcha" / "InternalError" under load are transient and retried.
# The traffic checker has no equivalent endpoint, so traffic domains still go
# through the browser one by one.
# ----------------------------------------------------------------------------

AHREFS_OVERVIEW_API = "https://ahrefs.com/v4/stGetFreeWebsiteOverview"
TOKEN_MAX_AGE_S = 180          # tokens die at ~240 s; refresh before that
TOKEN_MINT_RETRIES = 3         # consecutive failed mints before giving up
API_MAX_ATTEMPTS = 4           # per-domain API attempts (across tokens)


class _TokenState:
    def __init__(self):
        self.token: Optional[str] = None
        self.minted_at: float = 0.0
        self.user_agent: str = ""
        self.cookies: Dict[str, str] = {}
        self.mints: int = 0

    @property
    def age(self) -> float:
        return time.time() - self.minted_at if self.token else 1e9


def _collect_turnstile_token(driver) -> Optional[str]:
    """Read the captcha token the page just sent, from Chrome's perf log."""
    token = None
    try:
        entries = driver.get_log("performance")
    except Exception as e:
        tprint(f"  [batch] cannot read performance log: {e}")
        return None
    for entry in entries:
        try:
            msg = json.loads(entry["message"])["message"]
            if msg.get("method") != "Network.requestWillBeSent":
                continue
            req = msg["params"]["request"]
            if "stGetFreeWebsiteOverview" not in req.get("url", ""):
                continue
            body = json.loads(req.get("postData") or "{}")
            if body.get("captcha"):
                token = body["captcha"]  # keep the latest
        except Exception:
            continue
    return token


def mint_token(driver, seed_domain: str, state: _TokenState) -> Dict[str, Any]:
    """Run one real browser check for `seed_domain`; on success the Turnstile
    token, cookies and UA are stored in `state`. Returns the seed's row."""
    try:
        driver.get_log("performance")  # drain old entries
    except Exception:
        pass
    row = scrape_domain(driver, seed_domain, MODES["authority"])
    token = _collect_turnstile_token(driver)
    if token and row.get("status") == "completed":
        state.token = token
        state.minted_at = time.time()
        state.mints += 1
        try:
            state.user_agent = driver.execute_script("return navigator.userAgent")
            state.cookies = {c["name"]: c["value"] for c in driver.get_cookies()}
        except Exception:
            pass
        tprint(f"  [batch] token #{state.mints} minted via {seed_domain} "
               f"(len {len(token)}, browser {row.get('elapsed_seconds')}s)")
    else:
        tprint(f"  [batch] token mint via {seed_domain} FAILED: "
               f"status={row.get('status')} token={'yes' if token else 'no'} "
               f"error={row.get('error')}")
        if row.get("ip_blocked") or _page_says_something_went_wrong(driver):
            # Ahrefs shows this when Cloudflare rejected the captcha for this
            # exit IP — i.e. the IP is already burned (shared proxy IPs often
            # are). Retrying on the same IP never recovers; the caller closes
            # this session and moves to a fresh IP.
            row["ip_blocked"] = True
            row["error"] = "IP blocked: Ahrefs shows 'Something went wrong'"
            tprint(f"  [batch] *** IP BLOCKED *** ('Something went wrong' for {seed_domain} "
                   f"after {row.get('elapsed_seconds')}s) — closing Chromium, next IP")
    row["source"] = "browser"
    return row


def _page_says_something_went_wrong(driver) -> bool:
    try:
        txt = driver.execute_script(
            "var m=document.querySelector('.ReactModalPortal [role=dialog]');"
            "return (m ? m.innerText : document.body.innerText) || '';")
        return "something went wrong" in (txt or "").lower()
    except Exception:
        return False


def _api_session(state: _TokenState, proxy: Optional[str], concurrency: int) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": state.user_agent or "Mozilla/5.0",
        "Origin": "https://ahrefs.com",
        "Referer": "https://ahrefs.com/website-authority-checker/",
        "Accept": "*/*",
    })
    s.cookies.update(state.cookies)
    pr = proxy_for_requests(proxy)
    if pr:
        s.proxies.update(pr)
    adapter = HTTPAdapter(pool_connections=concurrency, pool_maxsize=concurrency, max_retries=0)
    s.mount("https://", adapter)
    return s


def api_authority_check(sess: requests.Session, domain: str, token: str,
                        timeout: float = 60.0) -> Dict[str, Any]:
    """One API call. Row has status 'completed' or 'error' with `error_kind`
    in {'InvalidCaptcha', 'InternalError', 'http', 'exception', 'unknown'}."""
    t0 = time.time()
    row: Dict[str, Any] = {"domain_name": domain, "status": "error", "source": "api"}
    try:
        resp = sess.post(AHREFS_OVERVIEW_API,
                         data=json.dumps({"url": domain, "captcha": token}),
                         timeout=timeout)
        if resp.status_code != 200:
            row["error"] = f"HTTP {resp.status_code}"
            row["error_kind"] = "http"
        else:
            body = resp.json()
            if isinstance(body, list) and body and body[0] == "Ok" and isinstance(body[1], dict):
                d = body[1]
                row["dr"] = d.get("domainRating")
                row["backlinks"] = d.get("backlinks")
                row["linking_websites"] = d.get("refdomains")
                row["backlinks_dofollow_percentage"] = d.get("dofollowBacklinks")
                row["linking_websites_dofollow_percentage"] = d.get("dofollowRefdomains")
                if row["dr"] is None and row["backlinks"] is None:
                    row["error"] = "empty result"
                    row["error_kind"] = "unknown"
                elif (row["dr"] or 0) >= 1 and not row["backlinks"] and not row["linking_websites"]:
                    # Ahrefs sometimes answers with the DR but zeroed link
                    # counts when its backend is slow (seen on github.com,
                    # google.com … right after a token mint). A DR>=1 site with
                    # zero backlinks is impossible, so treat it as transient.
                    row["error"] = f"partial result: DR {row['dr']} but zero backlinks"
                    row["error_kind"] = "PartialResult"
                else:
                    row["status"] = "completed"
            else:
                detail = body[1] if isinstance(body, list) and len(body) > 1 else body
                flat = json.dumps(detail)
                row["error"] = flat[:200]
                if "InvalidCaptcha" in flat:
                    row["error_kind"] = "InvalidCaptcha"
                elif "InternalError" in flat:
                    row["error_kind"] = "InternalError"
                else:
                    row["error_kind"] = "unknown"
    except Exception as e:
        row["error"] = f"{type(e).__name__}: {str(e)[:150]}"
        row["error_kind"] = "exception"
    row["elapsed_seconds"] = round(time.time() - t0, 2)
    row["finished_at"] = datetime.now(timezone.utc).isoformat()
    return row


class _Browser:
    """Owns the single batch-mode browser so callers can restart it."""

    def __init__(self, proxy_base: Optional[str] = None, **build_kwargs):
        self.kw = build_kwargs
        self.proxy_base = proxy_base          # as given on the CLI (no session)
        self.proxy: Optional[str] = None      # current sticky session spec
        self.exit_ip: Optional[str] = None
        self.sessions = 0
        self.driver = None
        self.profile: Optional[str] = None
        self.rotate_ip()

    def rotate_ip(self, reason: Optional[str] = None) -> None:
        """Close the browser, optionally record the current IP as burned, and
        start a fresh browser on a NEW proxy session whose exit IP is not on
        the burned list. Burned IPs are skipped with a cheap HTTP lookup —
        Chromium is only opened once a clean IP is found."""
        if reason and self.exit_ip:
            mark_ip_burned(self.exit_ip, reason)
        self.close()
        if not self.proxy_base:
            self.sessions += 1
            self.proxy = None
            self.kw["proxy"] = None
            self.restart()
            return
        skipped = 0
        for attempt in range(40):
            self.sessions += 1
            spec = make_sticky_proxy(self.proxy_base, session_id=uuid.uuid4().hex[:10])
            ip = exit_ip_via_requests(spec)
            burned = load_burned_ips()
            if ip is None:
                tprint(f"  [batch] session #{self.sessions}: proxy did not answer — next session")
                continue
            if ip in burned:
                skipped += 1
                tprint(f"  [batch] session #{self.sessions}: exit IP {ip} is on the burned list "
                       f"(since {burned[ip][:19]}) — skipping, no browser opened")
                continue
            self.proxy = spec
            self.exit_ip = ip
            self.kw["proxy"] = spec
            tprint(f"  [batch] session #{self.sessions}: exit IP {ip} is clean"
                   + (f" ({skipped} burned IPs skipped)" if skipped else "") + " — opening Chromium")
            self.restart()
            return
        raise RuntimeError("could not find a proxy exit IP that is not on the burned list "
                           f"after 40 sessions ({skipped} burned); see {BURNED_IPS_PATH}")

    def is_alive(self) -> bool:
        if not _is_driver_alive(self.driver):
            return False
        try:
            return bool(self.driver.window_handles)
        except Exception:
            return False

    def ensure_alive(self) -> None:
        if not self.is_alive():
            tprint("  [batch] browser not responding — restarting it")
            self.restart()

    def restart(self) -> None:
        self.close()
        last_err = None
        for attempt in range(5):
            try:
                self.driver, self.profile = build_driver(0, perf_log=True, **self.kw)
                time.sleep(1)
                if self.is_alive():
                    return
                raise RuntimeError("browser window closed right after start")
            except Exception as e:
                last_err = e
                tprint(f"  [batch] browser start attempt {attempt+1}/5 failed: {e}")
                self.close()
                time.sleep(min(5 * (attempt + 1), 20))
        raise RuntimeError(f"cannot start browser: {last_err}")

    def close(self) -> None:
        if self.driver is not None:
            _quit_driver(self.driver)
            self.driver = None
        if self.profile:
            _remove_worker_profile(self.profile)
            self.profile = None


def run_authority_batch(browser: "_Browser", domains: List[str], proxy: Optional[str],
                        concurrency: int, pace: float,
                        on_row: Callable[[Dict[str, Any]], None]) -> None:
    """Resolve every domain in `domains` (authority mode) via token reuse."""
    from collections import deque

    state = _TokenState()
    pending = deque(dict.fromkeys(d for d in domains if d))  # de-dup, keep order
    attempts: Dict[str, int] = {}
    mint_failures = 0        # consecutive failed mints on the current IP
    rotations = 0            # consecutive IP rotations without a good mint
    MAX_ROTATIONS = int(os.environ.get("AHREF_MAX_ROTATIONS", "10"))  # 0 = never take a second IP
    total = len(pending)
    done = 0
    sess: Optional[requests.Session] = None

    def finish(row: Dict[str, Any]) -> None:
        nonlocal done
        done += 1
        row["mode"] = "authority"
        on_row(row)

    while pending:
        # ── (re)mint when needed ────────────────────────────────────────
        if state.token is None or state.age > TOKEN_MAX_AGE_S:
            seed = pending.popleft()
            browser.ensure_alive()
            row = mint_token(browser.driver, seed, state)
            minted = state.token is not None and state.age <= TOKEN_MAX_AGE_S
            if not minted:
                mint_failures += 1
                # Rule: "Something went wrong" == this exit IP is burned (shared
                # proxy IP used by someone else). Close Chromium, take a new
                # Bright Data session (new IP) and retry the SAME domain.
                # Any other mint failure gets one more try on this IP first.
                if row.get("ip_blocked") or mint_failures >= 2 or not browser.is_alive():
                    rotations += 1
                    if rotations > MAX_ROTATIONS:
                        tprint(f"  [batch] {rotations-1} IP rotations in a row without a working "
                               f"captcha — giving up on {len(pending)+1} domains")
                        finish(row)
                        while pending:
                            d = pending.popleft()
                            finish({"domain_name": d, "status": "error", "source": "none",
                                    "error": "no working proxy IP after repeated rotations"})
                        return
                    why = "IP blocked ('Something went wrong')" if row.get("ip_blocked") \
                        else f"{mint_failures} failed captcha checks"
                    tprint(f"  [batch] {why} on this IP — closing Chromium, new session")
                    pending.appendleft(seed)       # retry same domain on the new IP
                    mint_failures = 0
                    browser.rotate_ip(reason=why)
                    continue
                pending.appendleft(seed)
                time.sleep(3)
                continue
            mint_failures = 0
            rotations = 0
            finish(row)
            sess = _api_session(state, browser.proxy, concurrency)
            tprint(f"  [batch] progress {done}/{total}; firing API calls "
                   f"({concurrency} concurrent, token age budget {TOKEN_MAX_AGE_S}s)")

        # ── rolling pool over the current token ─────────────────────────
        # Keep `concurrency` calls in flight continuously. The old wave
        # barrier made every group of N wait for its slowest member (a
        # github.com-sized answer takes ~7 s, a small domain <1 s), which was
        # most of a 200-domain run. Stops submitting when the token ages out
        # or looks dead; the outer loop then re-mints.
        token = state.token
        in_flight: Dict[Any, str] = {}
        ok_n = err_n = invalid = partial = 0
        consecutive_invalid = 0
        token_dead = False
        last_log = time.time()
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            while pending or in_flight:
                while (pending and len(in_flight) < concurrency
                       and state.age <= TOKEN_MAX_AGE_S and not token_dead):
                    d = pending.popleft()
                    in_flight[ex.submit(api_authority_check, sess, d, token)] = d
                    if pace:
                        time.sleep(pace / concurrency)   # smooth the burst a little
                if not in_flight:
                    break                                # token aged out / dead → re-mint
                done_set, _ = wait(list(in_flight), timeout=5, return_when=FIRST_COMPLETED)
                for fut in done_set:
                    d = in_flight.pop(fut)
                    try:
                        row = fut.result()
                    except Exception as e:               # should not happen, api_authority_check catches
                        row = {"domain_name": d, "status": "error", "source": "api",
                               "error": f"{type(e).__name__}: {e}", "error_kind": "exception"}
                    if row["status"] == "completed":
                        finish(row)
                        ok_n += 1
                        consecutive_invalid = 0
                        continue
                    kind = row.get("error_kind")
                    if kind == "InvalidCaptcha":
                        invalid += 1
                        consecutive_invalid += 1
                    else:
                        consecutive_invalid = 0
                    if kind == "PartialResult":
                        partial += 1
                    err_n += 1
                    attempts[d] = attempts.get(d, 0) + 1
                    if attempts[d] < API_MAX_ATTEMPTS:
                        pending.append(d)                # retry later (maybe with a new token)
                    else:
                        finish(row)
                    if consecutive_invalid >= min(5, concurrency) and not token_dead:
                        # A run of rejections means the token is dead (expired or
                        # revoked), not a flaky call. Drain and force a fresh mint.
                        token_dead = True
                        tprint(f"  [batch] {consecutive_invalid} InvalidCaptcha in a row — token dead, re-minting")
                now = time.time()
                if now - last_log > 10 or not (pending or in_flight):
                    tprint(f"  [batch] api: {ok_n} ok, {err_n} to retry"
                           + (f" ({partial} partial, {invalid} InvalidCaptcha)" if partial or invalid else "")
                           + f", in flight {len(in_flight)}, token age {state.age:.0f}s, "
                           f"progress {done}/{total}, pending {len(pending)}")
                    last_log = now
        if token_dead:
            state.token = None


def run_batch(domains: List[str], modes: List["CheckerMode"], proxy: Optional[str],
              headless: bool, chrome_bin: Optional[str], version_main: Optional[int],
              extension_path: Optional[str], out_path: str, concurrency: int,
              pace: float, use_api: bool) -> Dict[str, Any]:
    """Local batch run (no queue server). Writes rows to `out_path` as it goes."""
    rows: List[Dict[str, Any]] = []
    rows_lock = threading.Lock()
    t_start = time.time()

    def on_row(row: Dict[str, Any]) -> None:
        with rows_lock:
            rows.append(row)
            snapshot = list(rows)
        mark = "OK " if row.get("status") == "completed" else "FAIL"
        if row.get("mode") == "authority":
            tprint(f"  [{mark}][authority/{row.get('source','browser')}] {row['domain_name']} "
                   f"DR={row.get('dr','-')} BL={row.get('backlinks','-')} "
                   f"LW={row.get('linking_websites','-')}"
                   + (f" err={row.get('error')}" if row.get("error") else ""))
        else:
            tprint(f"  [{mark}][traffic/browser] {row['domain_name']} "
                   f"OT={row.get('organic_traffic','-')} TV={row.get('traffic_value','-')}"
                   + (f" err={row.get('error')}" if row.get("error") else ""))
        try:
            tmp = out_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(snapshot, fh, indent=2)
            os.replace(tmp, out_path)
        except Exception as e:
            tprint(f"  [batch] cannot write {out_path}: {e}")

    proxy_short = parse_proxy(proxy)["host"] if proxy else "local IP"
    tprint(f"[*] Batch: {len(domains)} domains, modes={[m.name for m in modes]}, "
           f"proxy={proxy_short}, api={'on' if use_api else 'off'}, concurrency={concurrency}")

    browser = _Browser(proxy_base=proxy, headless=headless, chrome_binary=chrome_bin,
                       version_main=version_main, extension_path=extension_path)
    try:
        for mode in modes:
            if mode.name == "authority" and use_api:
                run_authority_batch(browser, domains, proxy, concurrency, pace, on_row)
            else:
                for i, d in enumerate(domains, 1):
                    browser.ensure_alive()
                    row = scrape_domain(browser.driver, d, mode)
                    row["mode"] = mode.name
                    row["source"] = "browser"
                    on_row(row)
                    if i % 50 == 0:
                        tprint(f"  [batch] {i} browser checks — recycling browser")
                        browser.restart()
    finally:
        browser.close()

    elapsed = time.time() - t_start
    summary: Dict[str, Any] = {"domains": len(domains), "elapsed_seconds": round(elapsed, 1),
                               "out": out_path, "modes": {}}
    for mode in modes:
        mrows = [r for r in rows if r.get("mode") == mode.name]
        ok = [r for r in mrows if r.get("status") == "completed"]
        summary["modes"][mode.name] = {
            "completed": len(ok), "failed": len(mrows) - len(ok),
            "via_api": sum(1 for r in ok if r.get("source") == "api"),
            "via_browser": sum(1 for r in ok if r.get("source") == "browser"),
        }
    tprint("\n[*] Batch summary: " + json.dumps(summary))
    return summary


def load_domains(path: Optional[str], inline: Optional[str]) -> List[str]:
    """Domains from a file (one per line, '#' comments) and/or a comma/space/
    newline separated inline string. Strips scheme/path, lowercases, de-dups."""
    import re
    raw: List[str] = []
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue          # whole-line comments
                raw += re.split(r"[\s,;]+", line.split("#", 1)[0])
    if inline:
        raw += re.split(r"[\s,;]+", inline)
    out: List[str] = []
    seen = set()
    for item in raw:
        item = item.strip()
        if not item:
            continue
        item = re.sub(r"^[a-z]+://", "", item, flags=re.I)
        item = item.split("/")[0].split("?")[0].strip().lower()
        if item.startswith("www."):
            item = item[4:]
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


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

def _quit_driver(driver, wait_s: float = 10.0) -> None:
    """driver.quit() only SIGTERMs Chromium; wait for the process to actually
    exit so the profile dir can be removed without racing its shutdown."""
    pid = getattr(driver, "browser_pid", None)
    try:
        driver.quit()
    except Exception:
        pass
    if not pid:
        return
    import subprocess
    deadline = time.time() + wait_s
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            return                      # gone
        # a reaped-but-zombie child still answers kill(0); check its state
        try:
            out = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)],
                                 capture_output=True, text=True, timeout=2).stdout.strip()
            if not out or out.startswith("Z"):
                return
        except Exception:
            pass
        time.sleep(0.25)


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
            _quit_driver(driver)
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
    p.add_argument("--proxy", default=os.environ.get("AHREF_PROXY") or None,
                   help="Single proxy for every worker: host:port or "
                        "host:port:user:pass (env AHREF_PROXY). Bright Data "
                        "proxies automatically get a per-worker sticky session.")
    # ── batch mode (no queue server) ───────────────────────────────────────
    b = p.add_argument_group("batch mode", "Check a fixed list of domains locally and "
                             "write a JSON file instead of pulling from the queue.")
    b.add_argument("--domains-file", help="File with one domain per line")
    b.add_argument("--domains", help="Inline comma/space separated domains")
    b.add_argument("--out", default="results.json", help="Output JSON (default results.json)")
    b.add_argument("--concurrency", type=int, default=int(os.environ.get("AHREF_CONCURRENCY", "30")),
                   help="API calls kept in flight per token in batch mode (default 30, or "
                        "AHREF_CONCURRENCY). Measured: 5 is clean, 10-20 see sporadic "
                        "InternalError/InvalidCaptcha that the retries absorb")
    b.add_argument("--pace", type=float, default=0.5,
                   help="Seconds of spacing spread over each batch of `concurrency` submissions (default 0.5)")
    b.add_argument("--no-api", action="store_true",
                   help="Batch mode: run every domain through the browser instead of "
                        "reusing one Turnstile token over the API")
    args = p.parse_args()

    batch_mode = bool(args.domains_file or args.domains)

    # Resolve --modes / --mode
    raw_modes = args.modes if args.modes else (args.mode or "authority,traffic")
    requested = [m.strip().lower() for m in raw_modes.split(",") if m.strip()]
    unknown = [m for m in requested if m not in MODES]
    if unknown:
        print(f"[FATAL] Unknown mode(s): {unknown}. Valid: {list(MODES.keys())}",
              file=sys.stderr)
        sys.exit(2)
    if not requested:
        print("[FATAL] No modes given. Pass --modes authority,traffic.", file=sys.stderr)
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

    if args.proxy and not args.no_proxy:
        try:
            parse_proxy(args.proxy)
        except ValueError as e:
            print(f"[FATAL] {e}", file=sys.stderr)
            sys.exit(2)
        proxies = [args.proxy]
        print(f"[*] Proxy: {parse_proxy(args.proxy)['host']}:{parse_proxy(args.proxy)['port']} "
              f"({'authenticated' if parse_proxy(args.proxy)['user'] else 'IP-authorised'})",
              flush=True)

    if not args.no_proxy and not args.webshare_proxy and not proxies:
        print("[WARN] No proxies found. Running all instances on local IP.")

    chrome_bin = args.chrome or find_chrome_binary()
    version_main = detect_chrome_major(chrome_bin)

    if batch_mode:
        try:
            domains = load_domains(args.domains_file, args.domains)
        except OSError as e:
            print(f"[FATAL] cannot read domains: {e}", file=sys.stderr)
            sys.exit(2)
        if not domains:
            print("[FATAL] no domains to check", file=sys.stderr)
            sys.exit(2)
        proxy = proxies[0] if proxies else None
        print("[*] Ahrefs Checker - Batch Mode")
        print(f"[*] Chrome: {chrome_bin} (major {version_main})")
        summary = run_batch(
            domains, enabled_modes, proxy, args.headless, chrome_bin, version_main,
            extension_path, args.out, max(1, args.concurrency), max(0.0, args.pace),
            use_api=not args.no_api,
        )
        completed = sum(m["completed"] for m in summary["modes"].values())
        sys.exit(0 if completed > 0 else 1)

    mode_summary = ", ".join(f"{m.name}->{m.endpoint}" for m in enabled_modes)
    print("[*] Ahrefs Checker - Parallel Pull Mode")
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
            proxy = make_sticky_proxy(proxy, session_id=f"w{i}{uuid.uuid4().hex[:6]}")
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
