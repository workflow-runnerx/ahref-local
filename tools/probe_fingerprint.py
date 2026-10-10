#!/usr/bin/env python3
"""
Browser-side fingerprint probe — what a page (Cloudflare's challenge JS,
Ahrefs) can see about the checker's browser, dumped to JSON so two
environments (Mac vs Docker vs CI) can be diffed.

Uses the exact browser setup the checker uses (undetected-chromedriver +
cf-autoclick + vendored Chromium + fingerprint proxy when AHREF_PROXY /
AHREF_FP_DIRECT is set).

Collected:
  * navigator.*      webdriver, UA, UA-CH brands, platform, languages,
                     hardwareConcurrency, deviceMemory, plugins, touch
  * screen/window    size, depth, DPR, inner/outer dims
  * WebGL            unmasked vendor + renderer (SwiftShader/llvmpipe == VM)
  * fonts            which common fonts resolve
  * audio            AudioContext sample rate/state
  * time             JS timezone + offset  vs  exit-IP geolocation
  * network          exit IP (via the browser), TLS/h2 fingerprint seen by
                     tls.peet.ws (goes through the fingerprint proxy if set)
  * bot.sannysoft.com screenshot (optional, --screenshot-dir)

Usage:
    .venv/bin/python tools/probe_fingerprint.py --out out/probe-mac.json --screenshot-dir out
    AHREF_FP_DIRECT=1 .venv/bin/python tools/probe_fingerprint.py --out out/probe-mac-fp.json
"""
import argparse
import json
import os
import platform
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import requests  # noqa: E402

import ahrefs_checker as ac  # noqa: E402

PROBE_JS = r"""
return (function () {
  const out = {};
  const n = navigator;
  out.navigator = {
    webdriver: n.webdriver, userAgent: n.userAgent, platform: n.platform,
    vendor: n.vendor, languages: n.languages, language: n.language,
    hardwareConcurrency: n.hardwareConcurrency, deviceMemory: n.deviceMemory,
    plugins: n.plugins ? n.plugins.length : null, mimeTypes: n.mimeTypes ? n.mimeTypes.length : null,
    maxTouchPoints: n.maxTouchPoints, pdfViewerEnabled: n.pdfViewerEnabled,
    cookieEnabled: n.cookieEnabled, doNotTrack: n.doNotTrack,
    uaBrands: n.userAgentData ? n.userAgentData.brands : null,
    uaMobile: n.userAgentData ? n.userAgentData.mobile : null,
    uaPlatform: n.userAgentData ? n.userAgentData.platform : null,
    connection: n.connection ? {type: n.connection.effectiveType, rtt: n.connection.rtt, downlink: n.connection.downlink} : null,
  };
  out.screen = {
    width: screen.width, height: screen.height, availWidth: screen.availWidth, availHeight: screen.availHeight,
    colorDepth: screen.colorDepth, pixelDepth: screen.pixelDepth, dpr: window.devicePixelRatio,
    innerWidth: innerWidth, innerHeight: innerHeight, outerWidth: outerWidth, outerHeight: outerHeight,
    orientation: screen.orientation ? screen.orientation.type : null,
  };
  out.time = {
    timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    offsetMinutes: new Date().getTimezoneOffset(),
    locale: Intl.DateTimeFormat().resolvedOptions().locale,
  };
  try {
    const c = document.createElement('canvas');
    const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
    if (gl) {
      const d = gl.getExtension('WEBGL_debug_renderer_info');
      out.webgl = {
        vendor: d ? gl.getParameter(d.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
        renderer: d ? gl.getParameter(d.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER),
        version: gl.getParameter(gl.VERSION), shadingLanguage: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
        extensions: (gl.getSupportedExtensions() || []).length,
      };
    } else out.webgl = null;
  } catch (e) { out.webgl = {error: String(e)}; }
  try {
    const c2 = document.createElement('canvas'); c2.width = 220; c2.height = 40;
    const ctx = c2.getContext('2d'); ctx.textBaseline = 'top'; ctx.font = '14px Arial';
    ctx.fillStyle = '#f60'; ctx.fillRect(100, 1, 62, 20); ctx.fillStyle = '#069';
    ctx.fillText('ahref-local probe \u{1F600}', 2, 15);
    const data = c2.toDataURL(); let h = 0;
    for (let i = 0; i < data.length; i++) { h = (h * 31 + data.charCodeAt(i)) | 0; }
    out.canvasHash = (h >>> 0).toString(16);
  } catch (e) { out.canvasHash = 'err:' + e; }
  const fonts = ['Arial','Helvetica','Times New Roman','Courier New','Verdana','Georgia','Tahoma','Trebuchet MS',
    'Impact','Comic Sans MS','Segoe UI','Calibri','Cambria','Roboto','Ubuntu','Liberation Sans','DejaVu Sans',
    'Noto Sans','Noto Color Emoji','Lucida Grande','Menlo','Monaco','Consolas','Fira Code','Open Sans','Lato'];
  out.fonts = {};
  try { for (const f of fonts) out.fonts[f] = document.fonts.check('12px "' + f + '"'); } catch (e) { out.fonts = {error: String(e)}; }
  try {
    const AC = window.AudioContext || window.webkitAudioContext;
    const ac = new AC(); out.audio = {sampleRate: ac.sampleRate, state: ac.state, channels: ac.destination.maxChannelCount}; ac.close();
  } catch (e) { out.audio = {error: String(e)}; }
  out.misc = {
    chrome: typeof window.chrome, chromeRuntime: !!(window.chrome && window.chrome.runtime),
    notificationPermission: (typeof Notification !== 'undefined') ? Notification.permission : null,
    secureContext: window.isSecureContext,
    cdc: Object.keys(window).filter(k => /^cdc_|\$cdc_|__webdriver|__selenium|__driver/.test(k)),
    documentKeys: Object.keys(document).filter(k => /\$cdc_|webdriver|selenium|driver/i.test(k)),
    mediaDevices: !!(n.mediaDevices && n.mediaDevices.enumerateDevices),
    speechVoices: (window.speechSynthesis && speechSynthesis.getVoices) ? speechSynthesis.getVoices().length : null,
    battery: typeof n.getBattery,
    permissionsQuery: typeof (n.permissions && n.permissions.query),
    webrtc: typeof RTCPeerConnection,
  };
  return out;
})();
"""


def main() -> int:
    p = argparse.ArgumentParser(description="Browser-side fingerprint probe")
    p.add_argument("--out", default="out/probe.json")
    p.add_argument("--screenshot-dir", default=None, help="save bot.sannysoft.com + peet screenshots here")
    p.add_argument("--headless", action="store_true")
    p.add_argument("--skip-sites", action="store_true", help="only the local JS probe (no network)")
    args = p.parse_args()

    proxy = os.environ.get("AHREF_PROXY") or None
    if proxy:
        proxy = ac.make_sticky_proxy(proxy, session_id="probe" + os.urandom(3).hex())
    chrome = ac.find_chrome_binary()
    vm = ac.detect_chrome_major(chrome)
    ext = os.path.join(ROOT, "vendor", "cf-autoclick")
    ac._install_signal_handlers()

    report = {
        "env": {
            "host_platform": platform.platform(), "machine": platform.machine(),
            "python": platform.python_version(), "chrome": chrome, "chrome_major": vm,
            "in_docker": os.path.exists("/.dockerenv"), "display": os.environ.get("DISPLAY"),
            "tz_env": os.environ.get("TZ"), "lang_env": os.environ.get("LANG"),
            "proxy": (ac.parse_proxy(proxy) or {}).get("host") if proxy else None,
            "fp_direct": ac.FP_DIRECT, "fp_impersonate": os.environ.get("AHREF_FP_IMPERSONATE", "chrome"),
            "cpu_count": os.cpu_count(),
        },
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    print("[*] " + json.dumps(report["env"]), flush=True)

    driver, profile = ac.build_driver(0, headless=args.headless, chrome_binary=chrome,
                                      version_main=vm, proxy=proxy, extension_path=ext)
    try:
        driver.get("about:blank")
        time.sleep(1)
        report["browser"] = driver.execute_script(PROBE_JS)

        if not args.skip_sites:
            # exit IP + geo as the *browser* sees it (through the proxies)
            report["exit_ip"] = {}
            try:
                driver.get("https://api.ipify.org/?format=json")
                time.sleep(2)
                report["exit_ip"]["ip"] = json.loads(driver.find_element("tag name", "pre").text)["ip"]
            except Exception as e:
                report["exit_ip"]["browser_error"] = f"{type(e).__name__}: {str(e)[:120]}"
                try:
                    r = requests.get("https://api.ipify.org", proxies=ac.proxy_for_requests(proxy), timeout=20)
                    report["exit_ip"]["ip"] = r.text.strip()
                except Exception:
                    pass
            ip = report["exit_ip"].get("ip")
            if ip:
                for url, keys in (
                    (f"https://ipapi.co/{ip}/json/", {"city": "city", "region": "region", "country": "country_name",
                                                      "timezone": "timezone", "org": "org", "asn": "asn"}),
                    (f"http://ip-api.com/json/{ip}?fields=city,regionName,country,timezone,isp,as",
                     {"city": "city", "region": "regionName", "country": "country", "timezone": "timezone",
                      "org": "isp", "asn": "as"}),
                ):
                    try:
                        g = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=20).json()
                        if g.get(keys["timezone"]):
                            report["exit_ip"].update({k: g.get(v) for k, v in keys.items()})
                            report["exit_ip"]["geo_source"] = url.split("/")[2]
                            break
                    except Exception as e:
                        report["exit_ip"]["geo_error"] = f"{type(e).__name__}: {str(e)[:80]}"
            # TLS / h2 fingerprint as seen by an origin (goes through the fp proxy if set)
            try:
                driver.get("https://tls.peet.ws/api/clean")
                time.sleep(2)
                d = json.loads(driver.find_element("tag name", "pre").text)
                report["tls_seen_by_origin"] = {k: d.get(k) for k in ("ja3_hash", "ja4", "akamai_hash", "peetprint_hash")}
            except Exception as e:
                report["tls_seen_by_origin"] = {"error": f"{type(e).__name__}: {str(e)[:120]}"}
            if args.screenshot_dir:
                os.makedirs(args.screenshot_dir, exist_ok=True)
                tag = "docker" if report["env"]["in_docker"] else platform.system().lower()
                try:
                    driver.get("https://bot.sannysoft.com/")
                    time.sleep(6)
                    driver.set_window_size(1280, 2400)
                    time.sleep(1)
                    path = os.path.join(args.screenshot_dir, f"sannysoft-{tag}.png")
                    driver.save_screenshot(path)
                    rows = driver.execute_script(
                        "return [].slice.call(document.querySelectorAll('tr')).map(function(tr){"
                        "var td=tr.querySelectorAll('td');return td.length>=2?[td[0].innerText.trim(),"
                        "td[1].innerText.trim().slice(0,80),td[1].className]:null}).filter(Boolean)")
                    report["sannysoft"] = {"screenshot": path,
                                           "failed": [r[0] for r in rows if "failed" in (r[2] or "")],
                                           "rows": rows[:60]}
                except Exception as e:
                    report["sannysoft"] = {"error": f"{type(e).__name__}: {str(e)[:120]}"}
    finally:
        ac._quit_driver(driver)
        ac._remove_worker_profile(profile)
        ac._stop_fingerprint_proxies()

    # ---- quick verdicts ---------------------------------------------------
    b = report.get("browser", {})
    gl = (b.get("webgl") or {})
    renderer = str(gl.get("renderer") or "")
    flags = []
    if b.get("navigator", {}).get("webdriver"):
        flags.append("navigator.webdriver is true")
    if any(s in renderer.lower() for s in ("swiftshader", "llvmpipe", "mesa", "software")):
        flags.append(f"software GPU renderer: {renderer}")
    if not gl or gl.get("error"):
        flags.append("no WebGL")
    ex_tz = (report.get("exit_ip") or {}).get("timezone")
    js_tz = b.get("time", {}).get("timeZone")
    if ex_tz and js_tz and ex_tz != js_tz:
        flags.append(f"timezone mismatch: browser {js_tz} vs exit IP {ex_tz}")
    fonts = b.get("fonts") or {}
    if isinstance(fonts, dict) and sum(1 for v in fonts.values() if v is True) < 8:
        flags.append(f"few fonts resolve ({sum(1 for v in fonts.values() if v is True)}/{len(fonts)})")
    if b.get("misc", {}).get("cdc"):
        flags.append(f"chromedriver globals present: {b['misc']['cdc']}")
    if (b.get("navigator", {}).get("hardwareConcurrency") or 0) <= 2:
        flags.append(f"hardwareConcurrency={b.get('navigator', {}).get('hardwareConcurrency')}")
    if b.get("screen", {}).get("colorDepth") not in (24, 30, 32):
        flags.append(f"unusual colorDepth {b.get('screen', {}).get('colorDepth')}")
    if report.get("sannysoft", {}).get("failed"):
        flags.append("sannysoft failed rows: " + ", ".join(report["sannysoft"]["failed"][:8]))
    report["flags"] = flags

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"\n[*] probe written to {args.out}")
    print("[*] webgl:", gl.get("vendor"), "/", renderer)
    print("[*] tz:", js_tz, "| exit:", json.dumps(report.get("exit_ip")))
    print("[*] tls seen by origin:", json.dumps(report.get("tls_seen_by_origin")))
    print("[*] flags:" if flags else "[*] flags: none", *("\n     - " + f for f in flags))
    return 0


if __name__ == "__main__":
    sys.exit(main())
