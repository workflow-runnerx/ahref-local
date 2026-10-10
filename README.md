# ahref-local

## Quick start

```bash
bash tools/setup_vendor.sh                       # chromium + cf-autoclick into vendor/
uv venv .venv && uv pip install --python .venv/bin/python -r requirements.txt   # or: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# Queue worker (pulls from the server, posts results back)
.venv/bin/python ahrefs_checker.py --workers 1 --no-proxy

# Batch: fixed list in, results.json out — one captcha per ~200 domains
.venv/bin/python ahrefs_checker.py --domains-file domains/sample-200.txt \
    --proxy brd.superproxy.io:44445:<brightdata-user>:<password>
```

With a proxy set, the browser goes through the local TLS/h2 **fingerprint proxy** (`fingerprint_proxy.py`, curl_cffi impersonating Chrome) so Cloudflare sees a Chrome fingerprint instead of ungoogled-chromium's — see `DOCUMENTATION.md` → "TLS / HTTP-2 fingerprint proxy".

GitHub Actions: **Ahref Batch Check** (`.github/workflows/ahref-batch.yml`) runs the batch for a pasted domain list or a file in `domains/`, through the `BRIGHTDATA_PROXY` secret, and uploads `results.json`. See `DOCUMENTATION.md` → "Batch mode".
