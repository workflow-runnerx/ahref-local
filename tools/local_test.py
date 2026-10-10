#!/usr/bin/env python3
"""
Local smoke test for ahrefs_checker.py — scrapes domains straight from a
file instead of pulling from the server queue, and writes results.json.

Reuses the exact same browser setup (undetected-chromedriver + cf-autoclick
extension + auto-discovered Chromium) and the same scrape_domain() path as
the production worker, so a green run here means the real worker will work.

Usage (from the repo root):
    .venv/bin/python tools/local_test.py                      # authority, test_domains.txt
    .venv/bin/python tools/local_test.py --modes authority,traffic
    .venv/bin/python tools/local_test.py --domains example.com github.com
    .venv/bin/python tools/local_test.py --domains-file my.txt --out out.json
    .venv/bin/python tools/local_test.py --headless
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import ahrefs_checker as ac  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description="Local Ahrefs scrape smoke test (no server)")
    p.add_argument("--modes", default="authority",
                   help="Comma-separated: authority,traffic (default: authority)")
    p.add_argument("--domains", nargs="*", help="Domains to check (overrides --domains-file)")
    p.add_argument("--domains-file", default=os.path.join(ROOT, "test_domains.txt"))
    p.add_argument("--out", default=os.path.join(ROOT, "results.json"))
    p.add_argument("--headless", action="store_true")
    p.add_argument("--chrome", help="Path to chrome/chromium binary (default: auto-discover)")
    p.add_argument("--extension", help="Unpacked extension dir (default: vendor/cf-autoclick)")
    p.add_argument("--keep-open", action="store_true",
                   help="Leave the browser open after the run (press Enter to quit)")
    args = p.parse_args()

    modes = []
    for m in [x.strip().lower() for x in args.modes.split(",") if x.strip()]:
        if m not in ac.MODES:
            print(f"[FATAL] unknown mode {m!r}; valid: {list(ac.MODES)}", file=sys.stderr)
            return 2
        modes.append(ac.MODES[m])

    if args.domains:
        domains = args.domains
    else:
        with open(args.domains_file) as fh:
            domains = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    if not domains:
        print("[FATAL] no domains to test", file=sys.stderr)
        return 2

    ext = args.extension or os.path.join(ROOT, "vendor", "cf-autoclick")
    ext = os.path.abspath(os.path.expanduser(ext))
    if not os.path.isfile(os.path.join(ext, "manifest.json")):
        print(f"[FATAL] extension manifest.json not found under {ext}\n"
              f"        run: bash tools/setup_vendor.sh", file=sys.stderr)
        return 2

    chrome_bin = args.chrome or ac.find_chrome_binary()
    if not chrome_bin:
        print("[FATAL] no Chromium/Chrome binary found; pass --chrome", file=sys.stderr)
        return 2
    version_main = ac.detect_chrome_major(chrome_bin)

    print(f"[*] Chrome:    {chrome_bin} (major {version_main})")
    print(f"[*] Extension: {ext}")
    print(f"[*] Modes:     {', '.join(m.name for m in modes)}")
    print(f"[*] Domains:   {domains}")
    print(f"[*] Headless:  {args.headless}\n")

    ac._install_signal_handlers()
    driver, profile = ac.build_driver(
        0, headless=args.headless, chrome_binary=chrome_bin,
        version_main=version_main, proxy=None, extension_path=ext,
    )

    results = []
    ok = 0
    try:
        for mode in modes:
            for d in domains:
                print(f"--> [{mode.name}] {d} ...", flush=True)
                row = ac.scrape_domain(driver, d, mode)
                row["mode"] = mode.name
                results.append(row)
                status = row.get("status")
                if status == "completed":
                    ok += 1
                summary = {k: v for k, v in row.items()
                           if k in ("status", "dr", "backlinks", "linking_websites",
                                    "organic_traffic", "traffic_value", "error",
                                    "elapsed_seconds")}
                print(f"    {json.dumps(summary)}", flush=True)
        if args.keep_open:
            input("\n[keep-open] browser left running — press Enter to quit...")
    finally:
        try:
            driver.quit()
        except Exception:
            pass
        ac._global_profile_cleanup()

    with open(args.out, "w") as fh:
        json.dump(results, fh, indent=2)
    total = len(results)
    print(f"\n[*] {ok}/{total} completed -> {args.out}")
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(main())
