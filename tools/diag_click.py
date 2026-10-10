#!/usr/bin/env python3
"""One-domain Turnstile click experiment (container diagnostics).

Opens the authority checker like the checker does, then every 2 s records:
  * DevTools targets (is the cf-autoclick service worker alive? challenge
    iframes?), the IFRAME nodes the extension's pierce lookup would see
    (src + box), modal / "Something went wrong" state, browser console.
If the interactive checkbox sits unclicked for --wait-click seconds, it sends
the same CDP Input.dispatchMouseEvent click the extension would, once, at the
checkbox, and keeps watching. Everything goes to --out-dir.

    docker compose -f docker/docker-compose.yml run --rm checker -- \
        .venv/bin/python tools/diag_click.py --domain botxbyte.com --out-dir out/diag-click
"""
import argparse, json, os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); os.chdir(ROOT)
import ahrefs_checker as ac  # noqa: E402

STATE_JS = """
return (function(){
  var modal=document.querySelector('.ReactModalPortal [role=dialog]')||document.querySelector('[class*="ReactModal__Content"]');
  var body=(document.body&&document.body.innerText)||'';
  return {ready:document.readyState, modal:!!modal, modalText:modal?modal.innerText.slice(0,160):null,
          wentWrong:body.toLowerCase().indexOf('something went wrong')!==-1,
          focus:document.hasFocus(), vis:document.visibilityState,
          r:(window.__ahrefsResult!==undefined), e:window.__ahrefsError||null,
          input:(document.querySelector('input[name=input],input[type=text]')||{}).value||null};
})();
"""

def attr(attrs, name):
    if not attrs: return None
    for i in range(0, len(attrs) - 1, 2):
        if attrs[i] == name: return attrs[i + 1]
    return None

def cf_iframes(driver):
    """What the extension sees: IFRAME nodes (pierce) whose src mentions challenges.cloudflare.com, with box."""
    out = []
    try:
        nodes = driver.execute_cdp_cmd("DOM.getFlattenedDocument", {"depth": -1, "pierce": True})["nodes"]
    except Exception as e:
        return [{"error": str(e)}]
    for n in nodes:
        if n.get("nodeName") != "IFRAME": continue
        src = attr(n.get("attributes"), "src") or ""
        box = None
        try:
            m = driver.execute_cdp_cmd("DOM.getBoxModel", {"nodeId": n["nodeId"]})["model"]["content"]
            box = [round(m[0]), round(m[1]), round(m[4] - m[0]), round(m[5] - m[1])]
        except Exception:
            pass
        title = attr(n.get("attributes"), "title") or ""
        # Turnstile's widget iframe is created without a src (the frame is navigated
        # programmatically), so match the way a human would see it: a ~300x65 box
        # or Cloudflare's accessibility title.
        looks = bool(box) and 240 <= box[2] <= 360 and 50 <= box[3] <= 90
        out.append({"src": src[:90], "title": title[:60], "box": box,
                    "cf": "challenges.cloudflare.com" in src or "cloudflare" in title.lower() or looks})
    return out

def targets(driver):
    try:
        t = driver.execute_cdp_cmd("Target.getTargets", {})["targetInfos"]
    except Exception as e:
        return [{"error": str(e)}]
    keep = []
    for x in t:
        u = x.get("url", "")
        if x.get("type") in ("service_worker", "worker", "iframe", "page", "other") and ("extension" in u or "cloudflare" in u or x.get("type") == "service_worker"):
            keep.append({"type": x.get("type"), "url": u[:100], "attached": x.get("attached")})
    return keep

def cdp_click(driver, x, y):
    # a short human-looking approach path before the press
    sx, sy = x - 180, y + 120
    for i in range(1, 9):
        driver.execute_cdp_cmd("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": sx + (x - sx) * i / 8, "y": sy + (y - sy) * i / 8, "button": "none"})
        time.sleep(0.03)
    time.sleep(0.15)
    driver.execute_cdp_cmd("Input.dispatchMouseEvent", {"type": "mousePressed", "x": x, "y": y, "button": "left", "buttons": 1, "clickCount": 1})
    time.sleep(0.04)
    driver.execute_cdp_cmd("Input.dispatchMouseEvent", {"type": "mouseReleased", "x": x, "y": y, "button": "left", "buttons": 0, "clickCount": 1})

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--domain", default="botxbyte.com")
    p.add_argument("--seconds", type=int, default=60)
    p.add_argument("--wait-click", type=int, default=20, help="seconds the checkbox may sit unclicked before we click it; -1 = never")
    p.add_argument("--out-dir", default="out/diag-click")
    a = p.parse_args()
    os.makedirs(a.out_dir, exist_ok=True)

    proxy_base = os.environ.get("AHREF_PROXY") or None
    proxy = ac.make_sticky_proxy(proxy_base, session_id="dc" + os.urandom(3).hex()) if proxy_base else None
    exit_ip = ac.exit_ip_via_requests(proxy) if proxy else None
    burned = ac.load_burned_ips()
    print(f"[click] exit IP {exit_ip} burned={exit_ip in burned}", flush=True)
    if exit_ip in burned:
        print("[click] burned IP — aborting (no retry on this IP)"); return 2

    chrome = ac.find_chrome_binary(); vm = ac.detect_chrome_major(chrome)
    driver, _ = ac.build_driver(0, headless=False, chrome_binary=chrome, version_main=vm,
                                proxy=proxy, extension_path=os.path.join(ROOT, "vendor", "cf-autoclick"), perf_log=True)
    log = {"domain": a.domain, "exit_ip": exit_ip, "timeline": [], "console": [], "clicked_at": None}
    for dom in ("DOM.enable", "Page.enable"):
        try: driver.execute_cdp_cmd(dom, {})
        except Exception as e: print(f"[click] {dom}: {e}")
    t0 = time.time()
    try:
        try: driver.get(ac.MODES["authority"].build_url(a.domain))
        except Exception as e: print(f"[click] get(): {e}")
        first_seen = None; clicked = False; last_shot = 0; reloaded = False
        while time.time() - t0 < a.seconds:
            t = round(time.time() - t0, 1)
            try: st = driver.execute_script(STATE_JS)
            except Exception as e: st = {"err": str(e)}
            fr = cf_iframes(driver); tg = targets(driver)
            cf = [f for f in fr if f.get("cf") and f.get("box") and f["box"][2] > 0]
            entry = {"t": t, **st, "cf_iframes": cf, "iframes": fr, "targets": tg}
            log["timeline"].append(entry)
            print(f"[click] t={t:5.1f} modal={st.get('modal')} wrong={st.get('wentWrong')} focus={st.get('focus')} "
                  f"input={st.get('input')} cf_iframes={[f['box'] for f in cf]} sw={[x['url'][:60] for x in tg if x['type']=='service_worker']}", flush=True)
            if cf and first_seen is None: first_seen = time.time(); print("[click] interactive widget visible", flush=True)
            if (not reloaded and not cf and not st.get('input') and t > 35):
                reloaded = True; print('[click] app did not hydrate in 35 s (no input, no widget) — reloading once', flush=True)
                try: driver.get(ac.MODES['authority'].build_url(a.domain))
                except Exception as e: print(f'[click] reload get(): {e}')
                continue
            if st.get("modal") or st.get("wentWrong") or st.get("r"):
                print(f"[click] DONE modal={st.get('modal')} wrong={st.get('wentWrong')} text={st.get('modalText')!r}", flush=True)
                driver.save_screenshot(os.path.join(a.out_dir, "final.png")); break
            if (cf and not clicked and a.wait_click >= 0 and first_seen and time.time() - first_seen >= a.wait_click):
                x0, y0, w, h = cf[0]["box"]
                x, y = x0 + 20, y0 + h / 2   # checkbox centre sits ~20 px from the widget's left edge
                driver.save_screenshot(os.path.join(a.out_dir, "before-click.png"))
                cdp_click(driver, x, y); clicked = True; log["clicked_at"] = t
                print(f"[click] CDP click at ({x:.0f},{y:.0f}) after {a.wait_click}s unclicked", flush=True)
                time.sleep(1.5); driver.save_screenshot(os.path.join(a.out_dir, "after-click.png"))
            if clicked and time.time() - t0 - log['clicked_at'] > 30:
                print('[click] 30 s after the click and still no modal — stopping (outcome is known)', flush=True)
                driver.save_screenshot(os.path.join(a.out_dir, 'final.png')); break
            if time.time() - last_shot > 15:
                driver.save_screenshot(os.path.join(a.out_dir, f"t{int(t):03d}.png")); last_shot = time.time()
            time.sleep(2)
        try:
            for e in driver.get_log("browser"):
                log["console"].append(f"{e.get('level')}: {e.get('message','')[:300]}")
        except Exception as e:
            log["console"].append(f"get_log failed: {e}")
        if _wrong(driver):
            ac.mark_ip_burned(exit_ip, "IP blocked ('Something went wrong') [diag_click]")
    finally:
        with open(os.path.join(a.out_dir, "diag-click.json"), "w") as f: json.dump(log, f, indent=1)
        try: driver.quit()
        except Exception: pass
    print("[click] console lines:", len(log["console"]))
    for c in log["console"]:
        if any(k in c for k in ("CDP", "CONTENT SCRIPT", "debugger", "extension", "Turnstile", "turnstile")): print("   ", c[:220])
    return 0

def _wrong(driver):
    try: return ac._page_says_something_went_wrong(driver)
    except Exception: return False

if __name__ == "__main__":
    sys.exit(main())
