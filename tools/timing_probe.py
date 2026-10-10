#!/usr/bin/env python3
"""Timing + client-hint probe through the checker's own browser (same flags,
extension, fingerprint proxy). Prints JSON. Usage: python timing_probe.py out.json"""
import json, os, sys, time
ROOT = os.getcwd()
sys.path.insert(0, ROOT)
import ahrefs_checker as ac

JS = r"""
const done = arguments[0];
(async () => {
  const o = {};
  // performance.now() granularity
  let t0 = performance.now(), n = 0, last = t0;
  while (n < 2000) { const t = performance.now(); if (t !== last) { last = t; n++; } }
  o.perfNowGranularityUs = Math.round(((last - t0) / n) * 1e6) / 1e3;
  // CPU: tight JS loop
  t0 = performance.now(); let s = 0; for (let i = 0; i < 2e7; i++) s += i % 7;
  o.jsLoop20M_ms = Math.round((performance.now() - t0) * 100) / 100;
  // JSON + string work
  const big = JSON.stringify(Array.from({length: 20000}, (_, i) => ({i, s: 'x'.repeat(20)})));
  t0 = performance.now(); for (let i = 0; i < 20; i++) JSON.parse(big);
  o.jsonParse20x_ms = Math.round((performance.now() - t0) * 100) / 100;
  // canvas 2D
  const c = document.createElement('canvas'); c.width = 800; c.height = 600; const ctx = c.getContext('2d');
  t0 = performance.now();
  for (let i = 0; i < 300; i++) { ctx.fillStyle = `hsl(${i},50%,50%)`; ctx.fillRect(i, i, 200, 200); ctx.fillText('fp' + i, 10 + i, 50); }
  o.canvas300ops_ms = Math.round((performance.now() - t0) * 100) / 100;
  // WebGL draw loop
  try {
    const c2 = document.createElement('canvas'); c2.width = 256; c2.height = 256; const g = c2.getContext('webgl'); const dbg = g.getExtension('WEBGL_debug_renderer_info');
    o.webglRenderer = g.getParameter(dbg.UNMASKED_RENDERER_WEBGL); o.webglVendor = g.getParameter(dbg.UNMASKED_VENDOR_WEBGL);
    t0 = performance.now(); for (let i = 0; i < 200; i++) { g.clearColor(i/200, 0, 0, 1); g.clear(g.COLOR_BUFFER_BIT); g.finish(); }
    o.webgl200clears_ms = Math.round((performance.now() - t0) * 100) / 100;
  } catch (e) { o.webglError = String(e); }
  // rAF cadence
  const frames = []; let prev = null;
  await new Promise(res => { function f(t) { if (prev !== null) frames.push(t - prev); prev = t; if (frames.length < 30) requestAnimationFrame(f); else res(); } requestAnimationFrame(f); });
  frames.sort((a, b) => a - b);
  o.rafMedian_ms = Math.round(frames[15] * 100) / 100; o.rafP90_ms = Math.round(frames[27] * 100) / 100;
  // setTimeout(0) latency
  const lat = []; for (let i = 0; i < 20; i++) { const a = performance.now(); await new Promise(r => setTimeout(r, 0)); lat.push(performance.now() - a); }
  lat.sort((a, b) => a - b); o.setTimeout0Median_ms = Math.round(lat[10] * 100) / 100;
  // Date vs performance drift
  const d0 = Date.now(), p0 = performance.now(); await new Promise(r => setTimeout(r, 500));
  o.dateVsPerfDrift_ms = Math.round(((Date.now() - d0) - (performance.now() - p0)) * 100) / 100;
  o.timeOrigin = performance.timeOrigin; o.tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  // client hints
  const u = navigator.userAgentData;
  o.ua = navigator.userAgent; o.platform = navigator.platform; o.cores = navigator.hardwareConcurrency; o.mem = navigator.deviceMemory;
  if (u) {
    o.uaBrands = u.brands; o.uaMobile = u.mobile; o.uaPlatform = u.platform;
    try { o.uaHigh = await u.getHighEntropyValues(['architecture','bitness','model','platformVersion','uaFullVersion','fullVersionList','wow64','formFactors']); } catch (e) { o.uaHighErr = String(e); }
  }
  done(JSON.stringify(o));
})();
"""

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "out/timing.json"
    proxy = os.environ.get("AHREF_PROXY") or None
    chrome = ac.find_chrome_binary()
    ext = os.path.join(ROOT, "vendor", "cf-autoclick")
    driver, profile = ac.build_driver(0, headless=False, chrome_binary=chrome,
                                      version_main=ac.detect_chrome_major(chrome), proxy=proxy, extension_path=ext)
    try:
        driver.set_script_timeout(120)
        try:
            driver.get("https://ahrefs.com/website-authority-checker")
        except Exception as e:
            print("page load timed out (eager), continuing:", e)
        time.sleep(3)
        res = json.loads(driver.execute_async_script(JS))
        # Also capture the request headers the origin would see (sec-ch-ua etc.)
        try:
            try:
                driver.get("https://httpbin.org/headers")
            except Exception:
                pass
            time.sleep(2)
            txt = driver.execute_script("return document.body.innerText")
            res["requestHeaders"] = json.loads(txt).get("headers")
        except Exception as e:
            res["requestHeadersErr"] = str(e)
        res["collected_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
        with open(out, "w") as f: json.dump(res, f, indent=2, sort_keys=True)
        print(json.dumps(res, indent=2, sort_keys=True))
    finally:
        try: driver.quit()
        except Exception: pass

if __name__ == "__main__":
    main()
