# ahref-local in a container: Ubuntu 24.04 + vendored ungoogled-chromium (arm64)
# + cf-autoclick + fingerprint proxy, driven under Xvfb (headed, not headless).
#
# Build (from ahref-local/):   docker compose -f docker/docker-compose.yml build
# Run a batch:                 docker compose -f docker/docker-compose.yml run --rm checker \
#                                  --domains-file domains/sample-200.txt --modes authority
# Fingerprint probe:           docker compose -f docker/docker-compose.yml run --rm probe
#
# linux/arm64: runs natively on Apple Silicon (Docker Desktop). The amd64
# image under Rosetta failed Cloudflare's Turnstile outright (2026-10-10,
# DOCUMENTATION.md "Docker Desktop run"); emulated CPU timing was the one
# delta nothing else could remove. ungoogled-chromium ships arm64 portable
# builds from 154 on. For an x86_64 host change the platform here and in
# docker-compose.yml and drop the matching tarball in vendor/.
FROM --platform=linux/arm64 ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=America/New_York \
    LANG=en_US.UTF-8 \
    LANGUAGE=en_US:en \
    LC_ALL=en_US.UTF-8 \
    PYTHONUNBUFFERED=1 \
    DISPLAY=:99 \
    SCREEN=1920x1080x24 \
    AHREF_CHROME_ARGS="--use-gl=angle --use-angle=gl --ignore-gpu-blocklist"
# AHREF_CHROME_ARGS: a GPU-less container has no WebGL at all (a strong bot
# signal — bot.sannysoft.com flags it). ANGLE over Mesa llvmpipe gives a
# software renderer that reads like an ordinary Linux VM; the alternative
# "--enable-unsafe-swiftshader --use-angle=swiftshader" reports SwiftShader,
# the classic headless-Chrome signature.

# Runtime libs for Chromium, X virtual framebuffer, fonts, audio, NSS tools
# (certutil for trusting the fingerprint-proxy CA), tzdata/locales so the
# browser's timezone + locale match the proxy's geography.
RUN apt-get update -q && apt-get install -y --no-install-recommends \
      ca-certificates curl git xz-utils procps tzdata locales \
      python3 python3-venv \
      xvfb x11-utils xauth \
      libnss3 libnss3-tools libatk-bridge2.0-0 libatk1.0-0 libxkbcommon0 \
      libxcomposite1 libxdamage1 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 \
      libasound2t64 libcups2t64 libdrm2 libxfixes3 libxshmfence1 libx11-xcb1 \
      libxcb-dri3-0 libgtk-3-0t64 libxss1 libxtst6 libu2f-udev \
      libgl1 libegl1 libgl1-mesa-dri libvulkan1 mesa-vulkan-drivers \
      fonts-liberation fonts-liberation2 fonts-noto-core fonts-noto-color-emoji \
      fonts-dejavu-core fonts-freefont-ttf fonts-ubuntu fonts-roboto fontconfig \
      pulseaudio pulseaudio-utils \
    && sed -i 's/^# *en_US.UTF-8/en_US.UTF-8/' /etc/locale.gen && locale-gen \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone \
    && fc-cache -f \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.11.6 /uv /usr/local/bin/uv

# Non-root user: Chromium refuses to run as root without --no-sandbox tricks,
# and a normal user also looks normal.
RUN useradd -m -u 1001 -s /bin/bash ahref
WORKDIR /app
RUN chown ahref:ahref /app
USER ahref
ENV HOME=/home/ahref \
    PATH=/app/.venv/bin:/home/ahref/.local/bin:$PATH

# --- dependencies first (cache-friendly) -----------------------------------
COPY --chown=ahref:ahref requirements.txt tools/setup_vendor.sh ./tools/
RUN mv tools/requirements.txt . \
    && uv venv .venv --python 3.12 \
    && uv pip install --python .venv/bin/python -r requirements.txt

# Vendored ungoogled-chromium + cf-autoclick. If the host already has the
# arm64 tarball cached (vendor/ungoogled-chromium-arm64.tar.xz, gitignored)
# it is copied in and the download is skipped; the extracted dir is never
# copied (it may be for another architecture).
COPY --chown=ahref:ahref vendor/ungoogled-chromium-arm64.tar.x[z] vendor/
RUN bash tools/setup_vendor.sh \
    && rm -f vendor/ungoogled-chromium-*.tar.xz \
    && vendor/ungoogled-chromium/chrome --version \
    && vendor/ungoogled-chromium/chromedriver --version

# Google publishes no linux-arm64 chromedriver, so undetected-chromedriver
# cannot download one. The portable tarball ships a matching chromedriver;
# patch it in place now (ahrefs_checker.py passes it as driver_executable_path
# whenever it sits next to the vendored chrome binary).
RUN .venv/bin/python - <<'PY'
from undetected_chromedriver.patcher import Patcher
p = Patcher(executable_path="/app/vendor/ungoogled-chromium/chromedriver"); p.auto()
print("vendored chromedriver patched:", p.executable_path, p.is_binary_patched(p.executable_path))
PY

# --- application -------------------------------------------------------------
COPY --chown=ahref:ahref . .
RUN chmod +x docker/entrypoint.sh && mkdir -p out /home/ahref/.ahref-fp-proxy /home/ahref/.pki

VOLUME ["/app/out", "/home/ahref/.ahref-fp-proxy"]
ENTRYPOINT ["docker/entrypoint.sh"]
CMD ["--help"]
