# Ahrefs Domain Authority Checker — Pull-Based Local Browser Processing

## Overview

Local script that pulls domains from the server queue, processes them in parallel browser instances, and posts results back. No tunnel or port-forwarding needed — the script makes outbound HTTP calls only.

---

## Local vendored setup (recommended)

Run once after cloning the repo:

```bash
bash tools/setup_vendor.sh
```

This downloads ungoogled-chromium (portable build, ~135 MB) into `vendor/ungoogled-chromium/` and clones the [cf-autoclick](https://github.com/tenacious6/cf-autoclick) extension into `vendor/cf-autoclick/`. Both are gitignored — they live in your local clone only.

After that, `ahrefs_checker.py` auto-discovers both at runtime, so you don't need any `--chrome` or `--extension` flags. It also skips the GitHub master-profile download entirely.

To upgrade chromium later: bump `CHROMIUM_VERSION` in `tools/setup_vendor.sh`, delete `vendor/ungoogled-chromium/`, and re-run the script.

### macOS

The portable tarball above is a Linux x86_64 build and will not run on a Mac. On macOS, `tools/setup_vendor.sh` instead installs [ungoogled-chromium](https://github.com/ungoogled-software/ungoogled-chromium-macos) via Homebrew (`brew install --cask ungoogled-chromium`, native arm64/x86_64) and clones cf-autoclick into `vendor/`. `ahrefs_checker.py` auto-discovers `/Applications/Chromium.app` first and only falls back to Google Chrome if no Chromium is installed (Google Chrome 137+ ignores `--load-extension`, so the cf-autoclick extension would not load).

```bash
bash tools/setup_vendor.sh                     # once
uv venv --python 3.13 .venv                    # or: python3.13 -m venv .venv
.venv/bin/pip install -r requirements.txt      # or: uv pip install --python .venv/bin/python -r requirements.txt
.venv/bin/python ahrefs_checker.py --workers 1 --no-proxy
```

Use Python 3.11–3.13 for the venv; undetected-chromedriver 3.5.x is not yet verified on 3.14.

### Local smoke test (no server)

`tools/local_test.py` scrapes domains from `test_domains.txt` through the exact same browser setup and `scrape_domain()` path as the production worker, without pulling from the queue, and writes `results.json`:

```bash
.venv/bin/python tools/local_test.py                              # authority mode, test_domains.txt
.venv/bin/python tools/local_test.py --modes authority,traffic
.venv/bin/python tools/local_test.py --domains example.com github.com --headless
.venv/bin/python tools/local_test.py --keep-open                  # leave the browser open to inspect
```

Exit code is 0 only when every domain/mode completed.

---

## Batch mode — one captcha, many domains (GitHub Actions)

Instead of pulling from the queue, batch mode takes a fixed list of domains, checks them and writes a JSON file. It is what `.github/workflows/ahref-batch.yml` runs.

```bash
.venv/bin/python ahrefs_checker.py --domains-file domains/sample-200.txt --out results.json \
    --modes authority --proxy brd.superproxy.io:44445:brd-customer-<id>-zone-<zone>:<password>
.venv/bin/python ahrefs_checker.py --domains "example.com, github.com" --no-proxy
```

### What happens (authority)

1. One real browser check (through the proxy) solves the invisible Cloudflare Turnstile and returns the first result.
2. The Turnstile token the page sent to `POST https://ahrefs.com/v4/stGetFreeWebsiteOverview` is read from Chrome's network log. That token is **not single-use**: for about 4 minutes it answers for any domain, from plain HTTP, as long as the request carries the browser's cookies, User-Agent and comes from the same exit IP.
3. The remaining domains are sent straight to that API, `--concurrency` at a time (default 5). Measured: ~1.5 s per call, so 200 domains take roughly 1–2 minutes with one or two captchas.
4. Tokens are refreshed after 180 s or as soon as a whole wave comes back `InvalidCaptcha`; the next domain in the list is used for the new browser check, so nothing is wasted. Sporadic `InvalidCaptcha` / `InternalError` are retried up to 4 times.
5. Results stream into `--out` after every domain (safe to read while running). API rows carry exact numbers (`backlinks: 4920490868`), browser rows carry the modal's abbreviated strings (`"4.9B"`); both have `source` set to `api` or `browser`.

Traffic mode has no reusable endpoint, so `--modes traffic` checks each domain in the browser one by one.

### Rate limits (measured)

| Setting | Effect |
|---|---|
| 5 concurrent | clean, ~200 domains/min |
| 10 concurrent | bursts of `InternalError` (rate limiting), retried |
| 20 concurrent | ~1 in 8 rejected at random, still 173/200 in 34 s |
| ~500 fast calls from one browser build | Cloudflare flagged that browser's fingerprint for hours — every later check from it failed, on any IP |

Keep `--concurrency` at 5 and spread volume across runs / proxies rather than pushing one browser harder.

### GitHub Actions workflow `ahref-batch.yml`

Trigger it from the Actions tab ("Ahref Batch Check" → Run workflow):

| Input | Default | Meaning |
|---|---|---|
| `domains` | empty | Inline list (comma/space/newline separated). Empty → use `domains_file`. |
| `domains_file` | `domains/sample-200.txt` | File in the repo, one domain per line, `#` comments allowed |
| `modes` | `authority` | `authority`, `traffic` or both |
| `concurrency` | `5` | Parallel API calls per token |
| `proxy` | empty | `host:port:user:pass`; empty → repository secret `BRIGHTDATA_PROXY` |

Add the secret once: **Settings → Secrets and variables → Actions → New repository secret**, name `BRIGHTDATA_PROXY`, value `brd.superproxy.io:44445:brd-customer-<id>-zone-<zone>:<password>`. The value and the password are masked in logs.

The job installs Xvfb (no VNC/desktop needed — nobody has to watch it), runs `tools/setup_vendor.sh` for ungoogled-chromium + cf-autoclick, runs the batch under `xvfb-run`, writes a result table to the run's **Summary** tab and uploads `results.json` + `checker.log` as the artifact `ahrefs-results-<run number>`. A 200-domain authority run finishes in roughly 5 minutes including setup. The old `ahref-vnc.yml` is unchanged and still serves the queue/VNC use case.

### Proxies: Bright Data and authenticated proxies in general

* `--proxy host:port:user:pass` (or env `AHREF_PROXY`) works for both batch and queue mode and for every worker.
* The browser never talks to the upstream proxy directly. Every Chromium gets a local **fingerprint proxy** (`fingerprint_proxy.py`) on `127.0.0.1:<port>` via `--proxy-server`; it carries the upstream credentials itself, so no Manifest V2 "Proxy Auth" extension is needed (current Chromium builds refuse MV2 extensions). The same credentials are used for the batch API calls, so browser and API share one exit IP.
* Bright Data's ISP zone rotates the exit IP on every connection unless the username has a `-session-<id>` suffix. Cloudflare binds its cookies and the Turnstile token to the IP, so the checker appends a unique session id per worker automatically (`make_sticky_proxy`). Pass a username that already contains `-session-` to pin it yourself.

### TLS / HTTP-2 fingerprint proxy (`fingerprint_proxy.py`)

Cloudflare scores the TLS ClientHello (JA3/JA4) and the HTTP/2 SETTINGS of whoever connects. A plain CONNECT tunnel lets the vendored ungoogled-chromium do its own TLS, so Cloudflare saw *that* fingerprint. The checker now runs a local man-in-the-middle proxy instead:

```
Chromium --CONNECT host:443--> 127.0.0.1:<port>  (fingerprint_proxy.FingerprintProxy)
         <== TLS, leaf cert for host signed by a local CA ==>
         HTTP/1.1 requests  --> curl_cffi.AsyncSession(impersonate="chrome", proxy=<Bright Data>)
                                    ==> Chrome TLS ClientHello + h2 frames ==> origin
```

* **What the origin sees:** curl_cffi's Chrome fingerprint (JA4 `t13d1516h2_8daaf6152771_806a8c22fdea` with curl_cffi 0.16 / chrome150), not the local browser's. Cookies, User-Agent, `sec-ch-ua`, `Accept-Encoding` and every other header are passed through verbatim and in order; bodies are passed through still compressed.
* **Downstream** is HTTP/1.1 only (ALPN `http/1.1`); both CONNECT (https) and absolute-form (plain http) requests work. WebSocket upgrades are raw-tunnelled (CONNECT through the upstream proxy, bidirectional pipe).
* **CA:** an EC P-256 CA is generated once and kept in `~/.ahref-fp-proxy/` (`ca.pem`, `ca.key`); leaf certs per host are cached under `certs/`. Chromium is started with `--ignore-certificate-errors` whenever a proxy is set, so nothing needs installing. Override the directory with `AHREF_FP_CA_DIR`.
* **One instance per upstream** (i.e. per sticky Bright Data session / per worker), started on demand by `chrome_proxy_arg()` and stopped at exit. IP-authorised `host:port` proxies go through it too.
* **Env knobs:** `AHREF_FP_IMPERSONATE` (curl_cffi target, default `chrome`), `AHREF_FP_DEBUG=1` (log every request), `AHREF_FP_DIRECT=1` (route the browser through the fingerprint proxy even with `--no-proxy` — no upstream; handy to verify the fingerprint locally).
* **Verify:** `python fingerprint_proxy.py` starts it standalone, then
  `curl -x http://127.0.0.1:<port> --cacert ~/.ahref-fp-proxy/ca.pem https://tls.peet.ws/api/clean`
  (or open that URL / `https://tls.browserleaks.com/json` in the checker's browser with `AHREF_FP_DIRECT=1`) and compare `ja4` / `akamai_hash` with a direct request.
* Requires `curl_cffi` and `cryptography` (both in `requirements.txt`). Recreate the venv with `uv venv .venv && uv pip install --python .venv/bin/python -r requirements.txt` if yours predates them.

---

## Docker (Ubuntu 24.04, arm64)

Everything above packaged in one image: vendored ungoogled-chromium + cf-autoclick, the fingerprint proxy (CA trust in Chromium's NSS store is opt-in via `AHREF_FP_TRUST_CA=1` — see below), Xvfb (headed browser, not headless), a dummy audio sink, fonts, and `TZ`/`LANG` pinned to the proxy's geography. Files live in `docker/`.

```bash
cp docker/.env.example docker/.env   # BRIGHTDATA_PROXY=brd.superproxy.io:44445:brd-customer-<id>-zone-<zone>:<password>
docker compose -f docker/docker-compose.yml build
docker compose -f docker/docker-compose.yml run --rm checker --domains-file domains/sample-200.txt --modes authority
docker compose -f docker/docker-compose.yml run --rm probe        # browser-side fingerprint probe → out/probe-docker.json
```

* Results, `burned_ips.txt`, probe JSON and screenshots land in `./out/` on the host; the fingerprint-proxy CA persists in the `fp-ca` volume.
* The image is **`linux/arm64`** so it runs natively on Apple Silicon (Docker Desktop). The earlier `linux/amd64` image ran under Rosetta and Cloudflare rejected it outright (see the two findings sections below); the arm64 build passes. ungoogled-chromium ships arm64 portable builds from 154 on, so the vendored build is 155.0.8059.39 (the Mac runs 150 — brands differ by major, which did not matter). For an x86_64 host switch `--platform` in `docker/Dockerfile` and `platform:` in `docker-compose.yml` back to `linux/amd64`; `tools/setup_vendor.sh` picks the right tarball from `uname -m`.
* If your shell exports `DOCKER_DEFAULT_PLATFORM=linux/amd64` (this Mac does), compose refuses the arm64 platform. Prefix the commands: `DOCKER_DEFAULT_PLATFORM=linux/arm64 docker compose -f docker/docker-compose.yml build`.
* Google publishes no linux-arm64 chromedriver, so undetected-chromedriver cannot download one. The tarball's own `chromedriver` is patched at build time and `ahrefs_checker.py` passes it as `driver_executable_path` whenever it sits next to the vendored `chrome` (override with `AHREF_CHROMEDRIVER`). The Mac path is unchanged.
* Knobs via `docker/.env` or the environment: `TZ` (default `America/New_York`), `SCREEN` (`1920x1080x24`), `AHREF_FP_DEBUG`, `AHREF_FP_DIRECT`, `AHREF_FP_IMPERSONATE`, `AHREF_EVIDENCE_DIR` (compose sets `/app/out`: a screenshot is saved whenever the Turnstile widget appears, another if it is clicked, another if the check still fails), `AHREF_TURNSTILE_CLICKS` (default 2, `0` = never click the checkbox), `AHREF_MAX_ROTATIONS` (default 10, `0` = never take a second IP — use it for one-domain validation runs so a failure burns one IP, not ten).
* `docker run … ahref-local -- bash` drops into a shell with the display already set up.
* `AHREF_FP_TRUST_CA=1` installs the proxy CA into `~/.pki/nssdb` so the browser shows a normal padlock instead of running with `--ignore-certificate-errors`. Measured 2026-10-10 (Chromium 149 under Rosetta): with the CA trusted, Chromium dropped 18 of 100 same-origin responses from the proxy and the Ahrefs app never hydrated; with the flag, 1 of 101 (same as with no proxy). Leave it off unless you are debugging that.
* `AHREF_CHROME_ARGS` (default `--use-gl=angle --use-angle=gl --ignore-gpu-blocklist`) gives the GPU-less container a Mesa llvmpipe WebGL renderer; without it there is no WebGL at all, which bot.sannysoft.com flags.
* `tools/diag_ahrefs.py` opens the checker page and logs every few seconds whether the Turnstile iframe / result modal / "Something went wrong" is present, saving screenshots — use it when a check silently times out in a new environment.

### Findings 2026-10-10: Mac vs container under Rosetta

Ahrefs' Cloudflare integration scores high and treats virtualization/hypervisor signals as risk, so everything comes down to fingerprint parity with the Mac. Same domains (`test_domains.txt` baseline), same Bright Data ISP zone, same fingerprint proxy and the same cf-click extension (`vendor/cf-autoclick`, "Cfpass CDP Extension" MV3) in both environments.

| | Mac (native) | Container on the Mac (Rosetta) |
|---|---|---|
| Browser | ungoogled-chromium 150.0.7871.46, `/Applications/Chromium.app`, arm64 native | vendored ungoogled-chromium 149.0.7827.53 x86_64, `linux/amd64` image run by Docker Desktop on Apple Silicon (Rosetta/QEMU emulation) |
| Turnstile | invisible widget, no checkbox; baseline **9/10** | escalates to the **interactive checkbox**; cf-click never satisfied it; both sticky IPs ended with "2 failed captcha checks" (168.158.52.190, 168.158.111.92 — now in `burned_ips.txt`) |
| User-Agent / platform | `Macintosh; Intel Mac OS X 10_15_7`, `navigator.platform=MacIntel`, UA-CH platform macOS | `X11; Linux x86_64`, `navigator.platform=Linux x86_64`, UA-CH platform Linux — Linux desktop traffic is a small, bot-heavy slice for Cloudflare |
| WebGL | `ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)` | **none** without flags (sannysoft fails "WebGL Vendor/Renderer"); with the flags below `ANGLE (Mesa, llvmpipe (LLVM 20.1.2 128 bits), OpenGL 4.5)` — a software renderer, read as VM/server |
| Timing | native | Rosetta/QEMU drift: JS, canvas and WebGL work runs several times slower and jittery, challenge timing checks see an emulated CPU |
| Screen | 1440×900 @2x, 30-bit | 1920×1080 @1x, 24-bit (Xvfb) |
| Audio | 48 000 Hz | 44 100 Hz (PulseAudio null sink) |
| Locale / TZ | en-GB, Asia/Calcutta (mismatch with the US exit IP) | en-US, America/New_York (matches the exit IP) |
| TLS / h2 seen by origin | curl_cffi chrome JA4 `t13d1516h2_8daaf6152771_806a8c22fdea` | same |

What the diffs say: the container only differs from the Mac in things Cloudflare uses as risk signals (Linux UA, software GPU, emulated timing); cookies, TLS, headers and the extension are identical. The three deltas Rosetta cannot fix are the UA/platform (inherent to the Linux build), the GPU (no GPU in a container) and the timing (emulation). Which of them tips the score cannot be separated on the Mac, hence the x86_64 host test below.

Fixes that were applied and kept in the image:

* **`--ignore-certificate-errors` stays** (fingerprint-proxy leaf certs are signed by a local CA). Trusting that CA in Chromium's NSS store instead (`AHREF_FP_TRUST_CA=1`) made Chromium drop 18 of 100 same-origin responses from the proxy and the Ahrefs app never hydrated; with the flag it was 1 of 101, the same as with no proxy. The flag is a known automation signal only when combined with other flags, and it is on in both environments under test.
* **Mesa / llvmpipe WebGL** via `AHREF_CHROME_ARGS="--use-gl=angle --use-angle=gl --ignore-gpu-blocklist"` (default in the Dockerfile) plus `libgl1-mesa-dri`, `libegl1`, `libvulkan1`, `mesa-vulkan-drivers`. Before: `webgl: null`, bot.sannysoft.com red on WebGL vendor/renderer. After: 35 extensions, max texture 16384, renderer "ANGLE (Mesa, llvmpipe …)". The alternative `--enable-unsafe-swiftshader --use-angle=swiftshader` reports "SwiftShader Device (Subzero)", the classic headless-Chrome signature, and was rejected.
* **cf-click extension unchanged.** The bundled cf-autoclick handles the interactive checkbox on the Mac and is loaded identically in the container (`--load-extension`, `--disable-extensions-except`).
* **"Something went wrong" = burned IP.** Never retry a captcha on that IP; the checker closes Chromium and takes a fresh Bright Data session. All such IPs are recorded in `burned_ips.txt` (`AHREF_BURNED_IPS` in the container points at `out/burned_ips.txt`).

Diagnostics used: `tools/probe_fingerprint.py` (`out/probe-mac.json`, `out/probe-docker.json`, `out/probe-gl-{A,B,C}.json` for the GL variants), `tools/diag_ahrefs.py` runs in `out/diag-*` (direct, fpdirect, GL, noGL, skipnss — in every one the Ahrefs page loaded but the result modal never appeared within the 70–150 s window).

### Docker Desktop run 2026-10-10 (one domain at a time)

Image `ahref-local:latest` (linux/amd64, ungoogled-chromium 149) run by Docker Desktop on the M1 (Rosetta), same flags, fonts, `TZ`, fingerprint proxy and cf-click extension as before. Bright Data ISP zone, fresh sticky session per run. Results of each step, one IP per step:

| Step | What happened | Evidence |
|---|---|---|
| `probe` | sannysoft all green except the software GPU; renderer `ANGLE (Mesa, llvmpipe …)`; origin sees the same JA4 as the Mac; UA-CH brands `Chromium 149` + `Not)A;Brand` (no `Google Chrome` brand, same as the Mac build) | `out/probe-docker-2.json` |
| timing probe | 20 M-iteration JS loop 82 ms, 20× JSON.parse of 1 MB 150 ms, 300 canvas ops 88 ms, rAF median 17 ms, `setTimeout(0)` 5 ms, `performance.now()` granularity ≈1 ms, `deviceMemory` 4, 8 cores | `out/timing-docker.json` (`tools/timing_probe.py`) |
| 10-domain batch, browser check per domain (`--no-api`) | 0/10 — every check timed out after 45 s with no modal, no "Something went wrong" | `out/results-docker-ten.json` |
| `tools/diag_ahrefs.py` botxbyte.com | page hydrates, Turnstile **escalates to the interactive "Verify you are human" checkbox at ~20 s**, nobody clicks it, it sits there until the 45 s poll gives up | `out/diag-one/*.png` |
| `tools/diag_click.py` botxbyte.com | the widget `<iframe>` has an **empty `src`** (the challenge frame only exists as a separate DevTools target); cf-autoclick's lookup (`src.includes('challenges.cloudflare.com')`) and the checker's ActionChains fallback (same `src` test) therefore never find it, so the checkbox is never clicked | `out/diag-click/diag-click.json` (`iframes`, `targets`) |
| `tools/diag_click.py` with a CDP click on the checkbox | click delivered at 28 s via `Input.dispatchMouseEvent`; Turnstile answered with its **"Troubleshoot" failure state** and the widget was torn down — Cloudflare rejected the browser even after a correct interactive click | `out/diag-click4/after-click.png`, `t045.png` |
| one run | the Ahrefs app never hydrated (no logo, no prefilled input, no widget) — the response-drop flakiness noted under `AHREF_FP_TRUST_CA` | `out/diag-click3/t063.png` |

**Reading.** Two independent problems, and fixing the first would not have saved the run:

1. **The checkbox click path is broken for the current Turnstile build** (empty-`src` widget iframe). The extension stays as it is; the checker's own fallback should locate the widget by box (≈300×65) or by the `challenges.cloudflare.com` *frame target*, and click through CDP. Worth doing for the Mac too, where the 1-in-10 interactive case has the same lookup.
2. **The container's fingerprint fails Cloudflare's verdict outright.** With the click delivered, Turnstile still refused. A web page cannot read CPUID, SMBIOS or MAC addresses, so "hypervisor" is never detected directly; it is inferred from exactly the deltas in the table above: software WebGL renderer (no GPU), emulated-CPU timing under Rosetta, Xvfb's 1920×1080 @1× 24-bit screen without a window manager, a PulseAudio null sink, `deviceMemory` 4, and a Linux UA/platform. That bundle is the canonical "headless Linux server" profile. Nothing in the checker's Python code (poll loop, ActionChains pauses) affects it.

**What can still move the needle, in order of expected effect:**

* **Drop the emulation.** Run an arm64 Linux ungoogled-chromium in an arm64 container on the Mac (OBS Debian/Ubuntu arm64 packages exist), or the amd64 image on native x86 hardware. This removes the timing delta entirely; nothing else does.
* **A real GPU renderer string.** Only possible on a Linux host with `/dev/dri` passed through (Intel/AMD Mesa then reports the real card). Docker Desktop cannot do it. Keep llvmpipe over "no WebGL" and over SwiftShader.
* **Match the Mac build.** Bump `CHROMIUM_VERSION` in `tools/setup_vendor.sh` to the 150 series so brands match.
* **Do not spoof the UA to macOS.** UA-CH platform, `navigator.platform`, fonts and the GPU string would contradict it; contradictions score worse than an honest Linux desktop.

Burned by these tests (all in `burned_ips.txt`): 95.135.3.225, 185.89.106.161, 168.158.247.164. Not burned (no captcha attempt): 95.135.3.15, 158.46.131.201, 168.158.137.176.

### Validation 2026-10-10: linux/arm64 image passes

Plan: kill the emulation (arm64 image, native on the M1), fix the checkbox fallback, keep everything else (`TZ`, locale, screen, fingerprint proxy, cf-click unchanged, Linux UA not spoofed). One domain per run, `AHREF_MAX_ROTATIONS=0` so a failure costs one IP.

| Run | Exit IP | What happened | Result |
|---|---|---|---|
| 1 — fallback on | 168.158.48.134 | widget appeared at ~10 s ("Verifying…"), fallback clicked it twice from 6 s later, token minted | **completed**, DR 0.2, 28.4 s |
| 2 — fallback on | 31.204.17.23 | same sequence | **completed**, DR 0.2, 33.5 s |
| 3 — `AHREF_TURNSTILE_CLICKS=0` | 31.204.8.123 | first attempt timed out at 45 s with no widget at all (the page did not hydrate — the known response-drop flake), the retry on the same IP showed the widget at 9.3 s and Cloudflare cleared it **without any click** | **completed**, DR 0.2, 44.9 s |

So the invisible/managed pass works on the arm64 image (run 3, zero clicks), whereas the amd64 image under Rosetta was rejected even after a correct click. The clicks in runs 1–2 landed while the widget still said "Verifying…"; they did no harm and the runs finished faster, but run 3 shows they were not what made the difference. Rosetta was the trigger.

Evidence: `out/results-arm64.json`, `out/results-arm64-2.json`, `out/results-arm64-noclick.json` (rows carry `turnstile_widget`, `turnstile_widget_seconds`, `turnstile_clicks`, `turnstile_widget_html`), screenshots `out/turnstile-botxbyte.com-*.png`. The widget iframe this time had a real `src` (`…/turnstile/f/av0/rch/…/light/fbE/new/normal`) but sat where `querySelectorAll('iframe')` could not see it; the CDP pierce lookup found it by its 300×65 box. No IP was burned.

What changed for this (all local, nothing pushed):

* `docker/Dockerfile`, `docker/docker-compose.yml`: `linux/arm64`; the tarball's own `chromedriver` is patched at build time (no Google arm64 download exists); `AHREF_EVIDENCE_DIR` defaults to `/app/out`.
* `tools/setup_vendor.sh`: ungoogled-chromium 155.0.8059.39-1, tarball chosen by `uname -m` and cached per arch (`vendor/ungoogled-chromium-<arch>.tar.xz`), refuses an unpacked dir built for another arch.
* `ahrefs_checker.py`: `find_chromedriver_binary()` → `driver_executable_path`; Turnstile fallback rewritten — `_find_turnstile_widget()` (light DOM by src/title/box, then CDP pierce by box), `_cdp_click_turnstile()` (`Input.dispatchMouseEvent` with an approach path, ≤2 clicks, 6 s grace after the widget appears, 8 s between clicks), `_save_evidence()`; `AHREF_TURNSTILE_CLICKS`, `AHREF_MAX_ROTATIONS`.
* `tools/diag_ahrefs.py`: widget detection by box as well as src.

Brand note: the Mac runs Chromium 150, the container 155 (the oldest arm64 portable build is 154). Cloudflare did not care. Keep `tools/setup_vendor.sh` on whatever arm64 build is current rather than chasing the Mac's major.

**200-domain batch, same image (run 4, exit IP 168.158.165.162):** `domains/sample-200.txt`, authority, `--concurrency 5`. 200/200 completed in 326.7 s on one IP: 2 browser checks (botxbyte.com 33.9 s, pexels.com 19.8 s for the 180 s token refresh — both showed the widget and were clicked once after the 6 s grace), 198 via the API (7 sporadic `InvalidCaptcha` retried, 1 partial), no rotation, no IP burned. Output `out/results-arm64-200.json`.

Still open: the invisible pass took 44.9 s against a 45 s poll deadline in run 3. If no-click runs start timing out, raise `poll_deadline` in `scrape_domain()` to 60 s before touching anything else.

### Is a container detectable? (`tools/probe_fingerprint.py`)

Docker itself is invisible to a web page; what leaks are its side effects. The probe opens the checker's own browser (same undetected-chromedriver + extension + fingerprint proxy path) and dumps everything Cloudflare's challenge JS can read: `navigator.*` (webdriver, UA-CH brands, cores, memory, plugins), screen geometry, **WebGL vendor/renderer** (SwiftShader/llvmpipe = software GPU = VM/server), fonts, AudioContext, chromedriver globals, the JS timezone **vs the exit IP's timezone**, the TLS/h2 fingerprint the origin sees, and a bot.sannysoft.com screenshot. It prints a `flags` list of anything suspicious.

```bash
AHREF_PROXY=… .venv/bin/python tools/probe_fingerprint.py --out out/probe-mac.json --screenshot-dir out
docker compose -f docker/docker-compose.yml run --rm probe
diff <(jq -S .browser out/probe-mac.json) <(jq -S .browser out/probe-docker.json)
```

Baseline on the Mac (2026-10-10, Chromium 150 through Bright Data + fingerprint proxy): sannysoft all green, Apple M1 ANGLE renderer, 26/26 fonts, no chromedriver globals, origin sees JA4 `t13d1516h2_8daaf6152771_806a8c22fdea`. One flag: **timezone mismatch** (browser Asia/Calcutta vs exit IP America/New_York) — the container pins `TZ` for exactly this reason.

The real test is the Turnstile success rate: same domains, same Bright Data zone, N fresh sessions, compare mints succeeded / "Something went wrong" / IPs burned between Mac, Docker and CI.

---

## Architecture (Pull Approach)

```
┌─────────────────────────────────────────────────────────┐
│  Server (Kubernetes)                                     │
│                                                          │
│  Campaign created → ahref.authority-pool-queue           │
│       ↑                              ↓                   │
│  workflow.domain-final-queue    GET /ahref-authority/     │
│       ↑                              ↓                   │
│  POST /ahref-authority/  ←──── returns execution record  │
└────────────────────────────────────────────────────────── ┘
         ↑                              ↓
         │         YOUR LAPTOP          │
         │                              │
         │    ┌──────────────────┐      │
         └────│  Worker 0 (proxy)│←─────┘
              │  Worker 1 (proxy)│
              │  Worker 2 (proxy)│
              │  Worker 3 (proxy)│
              │  Worker 4 (proxy)│
              └──────────────────┘
              5 parallel Chrome instances
```

---

## Commands

### Run with 5 instances + proxies (default)
```bash
cd /home/sanket777/Desktop/Botxbyte/ahref-lambda
.venv/bin/python ahrefs_checker.py
```

### Run without proxies (local IP)
```bash
.venv/bin/python ahrefs_checker.py --no-proxy
```

### Run with custom number of instances
```bash
# 3 instances with proxies
.venv/bin/python ahrefs_checker.py --workers 3

# 1 instance, no proxy
.venv/bin/python ahrefs_checker.py --workers 1 --no-proxy

# 2 instances, no proxy, headless
.venv/bin/python ahrefs_checker.py --workers 2 --no-proxy --headless
```

### Run headless (no visible browser)
```bash
.venv/bin/python ahrefs_checker.py --headless
```

### All options
```bash
.venv/bin/python ahrefs_checker.py \
  --workers 5 \
  --no-proxy \
  --headless \
  --api-url http://164.90.252.85/domain-metrics-management-service/api/v1 \
  --chrome /usr/bin/google-chrome-stable \
  --proxies proxies.txt
```

---

## Options Reference

| Flag | Default | Description |
|------|---------|-------------|
| `--workers N` | 5 | Number of parallel browser instances |
| `--no-proxy` | off | Disable proxies, all instances use local IP |
| `--headless` | off | Run browsers in headless mode |
| `--api-url URL` | (production) | Management service API URL |
| `--chrome PATH` | auto-detect | Path to Chrome binary |
| `--proxies FILE` | proxies.txt | Path to proxy list file |
| `--proxy SPEC` | env `AHREF_PROXY` | One proxy for all workers: `host:port` or `host:port:user:pass` (Bright Data gets sticky sessions automatically) |
| `--domains-file FILE` / `--domains LIST` | — | **Batch mode**: check this list and exit instead of pulling from the queue |
| `--out FILE` | results.json | Batch mode output |
| `--concurrency N` | 5 | Batch mode: parallel API calls per Turnstile token |
| `--pace SEC` | 0.5 | Batch mode: pause between API waves |
| `--no-api` | off | Batch mode: browser check for every domain (no token reuse) |

---

## Proxy Format

File: `proxies.txt` (one per line)
```
ip:port:username:password
```

Example:
```
38.154.203.95:5863:kpmtwkyv:t6ggqskw3rka
198.105.121.200:6462:kpmtwkyv:t6ggqskw3rka
64.137.96.74:6641:kpmtwkyv:t6ggqskw3rka
```

If `--workers` exceeds the number of proxies, proxies are reused round-robin.

---

## How It Works

1. Script launches N browser instances (each with its own proxy if enabled)
2. Each worker independently polls `GET /ahref-authority/` for a domain
3. When a domain is available, it opens a new tab, navigates to Ahrefs, extracts metrics
4. Closes the work tab (browser stays alive on blank tab)
5. Posts results to `POST /ahref-authority/` which routes to the next workflow step
6. Loops back to step 2

---

## Services Involved

| Service | Role |
|---------|------|
| **domain-metrics-management-service** | `GET /ahref-authority/` pops from queue, `POST /ahref-authority/` routes results to next step |
| **domain-metrics-orchestration-service** | Worker scaled to 0 (not needed) |
| **ahref-lambda (this script)** | Pulls domains, processes in browser, posts results |

---

## Stopping

Press `Ctrl+C` to gracefully shut down all browser instances.

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Browser crashes with proxy | Check proxy credentials, ensure proxy supports HTTP |
| Browser shows local IP although a proxy was given | Fixed: authenticated proxies now use the built-in forwarder instead of an MV2 extension. Look for `[proxy] auth forwarder 127.0.0.1:…` in the log |
| Batch: `token mint … FAILED`, modal says "Something went wrong" | Cloudflare rejects this browser build's Turnstile tokens (fingerprint flag after a burst). Switch browser build (Google Chrome / plain Chromium) or wait; a new IP alone does not help |
| Batch: whole wave `InvalidCaptcha` | Token expired (~4 min) — handled automatically by re-minting |
| Batch: `InternalError` bursts | Ahrefs rate limiting — lower `--concurrency` |
| Bright Data IP changes between requests | Username lacks `-session-<id>`; the checker adds one, make sure you pass the raw username |
| Queue always empty | Create a campaign with ahref workflow in the frontend |
| POST fails | Check if management service is deployed and accessible |
| All workers idle | Normal when queue is empty — they poll every 3-5s |
