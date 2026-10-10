#!/usr/bin/env python3
"""
Diagnose why an Ahrefs check does not produce a result modal in some
environment (container, CI …): open the authority checker exactly like the
checker does, then every few seconds record what the page shows — Turnstile
iframe present?, modal present?, "Something went wrong"?, page title — and
save screenshots. Nothing is extracted; this is for eyes only.

    AHREF_PROXY=… .venv/bin/python tools/diag_ahrefs.py --domain botxbyte.com --seconds 90 --out-dir out
    docker compose -f docker/docker-compose.yml run --rm probe -- .venv/bin/python tools/diag_ahrefs.py --out-dir out
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import ahrefs_checker as ac  # noqa: E402

STATE_JS = """
return (function(){
  var ifr=[].slice.call(document.querySelectorAll('iframe')).map(function(f){return (f.src||'').slice(0,80)});
  // the Turnstile widget iframe has an EMPTY src — recognise it by its ~300x65 box
  var widget=[].slice.call(document.querySelectorAll('iframe')).some(function(f){var r=f.getBoundingClientRect();return r.width>=240&&r.width<=360&&r.height>=50&&r.height<=90;});
  var modal=document.querySelector('.ReactModalPortal [role=dialog]')||document.querySelector('[class*="ReactModal__Content"]');
  var body=(document.body&&document.body.innerText)||'';
  return {title:document.title.slice(0,80), ready:document.readyState, iframes:ifr,
          turnstile:widget||ifr.some(function(s){return s.indexOf('challenges.cloudflare.com')!==-1}),
          modal:!!modal, modalText:modal?modal.innerText.slice(0,200):null,
          wentWrong:body.toLowerCase().indexOf('something went wrong')!==-1,
          hasDR:body.indexOf('Domain Rating')!==-1, bodyLen:body.length,
          input:(document.querySelector('input[name=input],input[type=text]')||{}).value||null};
})();
"""


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--domain", default="botxbyte.com")
    p.add_argument("--mode", default="authority", choices=list(ac.MODES))
    p.add_argument("--seconds", type=int, default=90)
    p.add_argument("--out-dir", default="out")
    p.add_argument("--headless", action="store_true")
    args = p.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)
    tag = "docker" if os.path.exists("/.dockerenv") else "host"

    proxy = os.environ.get("AHREF_PROXY") or None
    if proxy:
        proxy = ac.make_sticky_proxy(proxy, session_id="diag" + os.urandom(3).hex())
    chrome = ac.find_chrome_binary()
    vm = ac.detect_chrome_major(chrome)
    ext = os.path.join(ROOT, "vendor", "cf-autoclick")
    ac._install_signal_handlers()
    mode = ac.MODES[args.mode]

    t_build = time.time()
    driver, profile = ac.build_driver(0, headless=args.headless, chrome_binary=chrome,
                                      version_main=vm, proxy=proxy, extension_path=ext,
                                      perf_log=True)
    print(f"[diag] browser up in {time.time() - t_build:.1f}s ({tag}, chrome {vm}, proxy={'yes' if proxy else 'no'})", flush=True)
    timeline = []
    try:
        t0 = time.time()
        try:
            driver.get(mode.build_url(args.domain))
        except Exception as e:
            print(f"[diag] driver.get raised {type(e).__name__}: {str(e)[:100]}")
        print(f"[diag] navigation returned after {time.time() - t0:.1f}s", flush=True)
        last_shot = 0
        while time.time() - t0 < args.seconds:
            try:
                st = driver.execute_script(STATE_JS)
            except Exception as e:
                st = {"error": f"{type(e).__name__}: {str(e)[:80]}"}
            st["t"] = round(time.time() - t0, 1)
            timeline.append(st)
            print(f"[diag] t={st['t']:5.1f}s ready={st.get('ready')} turnstile={st.get('turnstile')} "
                  f"modal={st.get('modal')} DR={st.get('hasDR')} wrong={st.get('wentWrong')} "
                  f"title={st.get('title')!r}", flush=True)
            if time.time() - last_shot >= 15 or st.get("modal") or st.get("wentWrong"):
                path = os.path.join(args.out_dir, f"diag-{tag}-{int(st['t']):03d}s.png")
                try:
                    driver.save_screenshot(path)
                except Exception as e:
                    print(f"[diag] screenshot failed: {e}")
                last_shot = time.time()
            if st.get("hasDR") and st.get("modal"):
                print("[diag] result modal rendered — done", flush=True)
                break
            if st.get("wentWrong"):
                print("[diag] 'Something went wrong' — IP rejected", flush=True)
                break
            time.sleep(3)
        # console errors + resources that failed / were blocked
        console = []
        try:
            for e in driver.get_log("browser"):
                if e.get("level") in ("SEVERE", "WARNING"):
                    console.append(f"{e.get('level')}: {str(e.get('message'))[:300]}")
        except Exception as e:
            console.append(f"(no browser log: {type(e).__name__})")
        for line in console[:40]:
            print("[diag][console]", line, flush=True)
        try:
            res = driver.execute_script(
                "return performance.getEntriesByType('resource').map(function(r){return {n:r.name.slice(0,120),"
                "s:r.responseStatus,t:r.transferSize,d:Math.round(r.duration)}})")
            bad = [r for r in res if (r.get("s") or 0) >= 400 or (r.get("s") == 0 and r.get("t") == 0)]
            print(f"[diag] resources: {len(res)} total, {len(bad)} failed/blocked", flush=True)
            for r in bad[:25]:
                print(f"[diag][resource] status={r.get('s')} size={r.get('t')} {r['n']}", flush=True)
        except Exception as e:
            res, bad = [], []
            print(f"[diag] resource timing failed: {e}")
        try:
            html_path = os.path.join(args.out_dir, f"diag-{tag}-final.html")
            with open(html_path, "w", encoding="utf-8") as fh:
                fh.write(driver.page_source)
        except Exception:
            pass
    finally:
        ac._quit_driver(driver)
        ac._remove_worker_profile(profile)
        ac._stop_fingerprint_proxies()
    with open(os.path.join(args.out_dir, f"diag-{tag}.json"), "w", encoding="utf-8") as fh:
        json.dump({"domain": args.domain, "mode": args.mode, "timeline": timeline,
                   "console": console, "resources": res}, fh, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
