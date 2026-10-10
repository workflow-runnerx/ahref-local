"""
TLS / HTTP-2 fingerprint rewriting proxy for ahrefs_checker.py.

Problem: Cloudflare scores the TLS ClientHello (JA3/JA4) and the HTTP/2
SETTINGS/priority frames of whoever connects. With a plain CONNECT tunnel the
vendored ungoogled-chromium talks TLS end-to-end, so Cloudflare sees *its*
fingerprint. This module terminates TLS locally instead and re-issues every
request with curl_cffi impersonating Chrome, so the origin sees curl_cffi's
Chrome ClientHello + h2 frames, while the browser keeps its own cookies,
User-Agent and every other header untouched.

    browser --CONNECT host:443--> FingerprintProxy (127.0.0.1:<port>)
            <-- 200 Connection established
            <== TLS (leaf cert for `host`, signed by the local CA) ==>
            HTTP/1.1 requests ............ curl_cffi.AsyncSession(impersonate="chrome",
                                                                  proxy=<Bright Data>)
                                              ==> TLS (Chrome fingerprint) ==> origin

* Downstream: HTTP/1.1 only (ALPN advertises just ``http/1.1``), both
  CONNECT (https) and absolute-form (plain http) requests.
* Upstream: one curl_cffi AsyncSession per proxy instance (keeps the h2
  connection pool warm). Cookies are never stored by the session
  (``discard_cookies``) and no default browser headers are added
  (``default_headers=False``) — the browser's headers go through verbatim,
  in order. Bodies are passed through still-encoded (``accept_encoding=None``
  keeps libcurl from decompressing), so Content-Encoding stays valid.
* WebSocket / other ``Upgrade:`` requests: raw tunnel — CONNECT through the
  upstream proxy (or a direct TCP connection without one), TLS as a plain
  client, and bidirectional byte piping. These carry Python's fingerprint but
  Ahrefs' checkers don't use them.
* CA: one EC P-256 CA, generated on first use and persisted in
  ``~/.ahref-fp-proxy/`` (``ca.pem`` / ``ca.key``). Leaf certs are minted per
  host, cached in memory, and written next to the CA so ``ssl`` can load
  them. Chromium is started with ``--ignore-certificate-errors`` so the CA
  does not need to be installed in the profile.

Usage:
    fp = FingerprintProxy(upstream="http://user:pass@brd.superproxy.io:44445")
    port = fp.start()            # background thread, returns the local port
    # chromium --proxy-server=http://127.0.0.1:<port> --ignore-certificate-errors
    fp.stop()

Standalone test:
    python fingerprint_proxy.py [--upstream http://user:pass@host:port] [--port N]
    curl -x http://127.0.0.1:<port> --cacert ~/.ahref-fp-proxy/ca.pem https://tls.peet.ws/api/clean
"""

from __future__ import annotations

import asyncio
import base64
import datetime as _dt
import ipaddress
import os
import re
import ssl
import sys
import threading
import time
from http import HTTPStatus
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, urlsplit

DEFAULT_CA_DIR = os.environ.get("AHREF_FP_CA_DIR") or os.path.expanduser("~/.ahref-fp-proxy")
DEFAULT_IMPERSONATE = os.environ.get("AHREF_FP_IMPERSONATE", "chrome")
DEBUG = os.environ.get("AHREF_FP_DEBUG", "") not in ("", "0", "false")

# Hop-by-hop headers never forwarded in either direction (RFC 7230 §6.1).
_HOP_BY_HOP = {
    "connection", "proxy-connection", "keep-alive", "transfer-encoding", "te",
    "trailer", "upgrade", "http2-settings", "proxy-authorization", "proxy-authenticate",
}
_MAX_HEAD = 256 * 1024
_HEAD_TIMEOUT = 60.0
_UPSTREAM_TIMEOUT = 120.0


def _log(msg: str) -> None:
    if DEBUG:
        print(f"  [fp-proxy] {msg}", flush=True)


# --------------------------------------------------------------------------- #
# Certificate authority + per-host leaf certificates
# --------------------------------------------------------------------------- #

class _CertAuthority:
    def __init__(self, ca_dir: str = DEFAULT_CA_DIR):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        self._x509, self._hashes, self._ser, self._ec, self._oid = x509, hashes, serialization, ec, NameOID
        self.ca_dir = ca_dir
        self.cert_dir = os.path.join(ca_dir, "certs")
        os.makedirs(self.cert_dir, mode=0o700, exist_ok=True)
        self.ca_pem = os.path.join(ca_dir, "ca.pem")
        self.ca_key_path = os.path.join(ca_dir, "ca.key")
        self._lock = threading.Lock()
        self._ctx_cache: Dict[str, ssl.SSLContext] = {}
        self._load_or_create_ca()

    # -- CA ------------------------------------------------------------------
    def _load_or_create_ca(self) -> None:
        x509, ser = self._x509, self._ser
        if os.path.isfile(self.ca_pem) and os.path.isfile(self.ca_key_path):
            try:
                with open(self.ca_key_path, "rb") as fh:
                    self.ca_key = ser.load_pem_private_key(fh.read(), password=None)
                with open(self.ca_pem, "rb") as fh:
                    self.ca_cert = x509.load_pem_x509_certificate(fh.read())
                if self.ca_cert.not_valid_after_utc > _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=30):
                    return
            except Exception as e:  # corrupt files — regenerate
                _log(f"CA reload failed ({e}); regenerating")
        self.ca_key = self._ec.generate_private_key(self._ec.SECP256R1())
        now = _dt.datetime.now(_dt.timezone.utc)
        name = x509.Name([
            x509.NameAttribute(self._oid.COMMON_NAME, "ahref-local fingerprint proxy CA"),
            x509.NameAttribute(self._oid.ORGANIZATION_NAME, "ahref-local"),
        ])
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(days=1))
            .not_valid_after(now + _dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key()), critical=False)
            .sign(self.ca_key, self._hashes.SHA256())
        )
        tmp_key = self.ca_key_path + ".tmp"
        with open(os.open(tmp_key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as fh:
            fh.write(self.ca_key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                                               ser.NoEncryption()))
        os.replace(tmp_key, self.ca_key_path)
        with open(self.ca_pem, "wb") as fh:
            fh.write(self.ca_cert.public_bytes(ser.Encoding.PEM))
        # stale leaves signed by an old CA
        for f in os.listdir(self.cert_dir):
            try:
                os.remove(os.path.join(self.cert_dir, f))
            except OSError:
                pass
        _log(f"new CA written to {self.ca_pem}")

    # -- leaves ----------------------------------------------------------------
    def context_for(self, host: str) -> ssl.SSLContext:
        """Server-side SSLContext presenting a leaf cert for `host` (ALPN http/1.1)."""
        host = host.lower().strip("[]")
        with self._lock:
            ctx = self._ctx_cache.get(host)
            if ctx is not None:
                return ctx
            pem_path = self._leaf_pem(host)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(pem_path)
            ctx.set_alpn_protocols(["http/1.1"])
            self._ctx_cache[host] = ctx
            return ctx

    def _leaf_pem(self, host: str) -> str:
        x509, ser = self._x509, self._ser
        safe = re.sub(r"[^a-z0-9.\-_]", "_", host)
        path = os.path.join(self.cert_dir, f"{safe}.pem")
        if os.path.isfile(path):
            try:
                with open(path, "rb") as fh:
                    data = fh.read()
                cert = x509.load_pem_x509_certificate(data)
                if (cert.issuer == self.ca_cert.subject
                        and cert.not_valid_after_utc > _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=2)):
                    return path
            except Exception:
                pass
        key = self._ec.generate_private_key(self._ec.SECP256R1())
        now = _dt.datetime.now(_dt.timezone.utc)
        try:
            san: List = [x509.IPAddress(ipaddress.ip_address(host))]
        except ValueError:
            san = [x509.DNSName(host)]
            # cover the bare domain's www. and vice versa — cheap, avoids extra leaves
            if host.startswith("www."):
                san.append(x509.DNSName(host[4:]))
            elif host.count(".") == 1:
                san.append(x509.DNSName("www." + host))
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(self._oid.COMMON_NAME, host[:64])]))
            .issuer_name(self.ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(days=1))
            .not_valid_after(now + _dt.timedelta(days=397))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
                           critical=False)
            .sign(self.ca_key, self._hashes.SHA256())
        )
        tmp = path + ".tmp"
        with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as fh:
            fh.write(key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
            fh.write(cert.public_bytes(ser.Encoding.PEM))
            fh.write(self.ca_cert.public_bytes(ser.Encoding.PEM))
        os.replace(tmp, path)
        return path


_CA_SINGLETON: Optional[_CertAuthority] = None
_CA_LOCK = threading.Lock()


def get_ca(ca_dir: str = DEFAULT_CA_DIR) -> _CertAuthority:
    global _CA_SINGLETON
    with _CA_LOCK:
        if _CA_SINGLETON is None or _CA_SINGLETON.ca_dir != ca_dir:
            _CA_SINGLETON = _CertAuthority(ca_dir)
        return _CA_SINGLETON


# --------------------------------------------------------------------------- #
# HTTP/1.1 parsing helpers
# --------------------------------------------------------------------------- #

class _Request:
    __slots__ = ("method", "target", "version", "headers", "body")

    def __init__(self, method: str, target: str, version: str,
                 headers: List[Tuple[str, str]], body: bytes = b""):
        self.method, self.target, self.version, self.headers, self.body = \
            method, target, version, headers, body

    def get(self, name: str) -> Optional[str]:
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None


async def _read_head(reader: asyncio.StreamReader) -> Optional[bytes]:
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=_HEAD_TIMEOUT)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
        return None
    except asyncio.LimitOverrunError:
        return None
    return head


def _parse_head(head: bytes) -> Optional[_Request]:
    try:
        text = head.decode("latin1")
    except Exception:
        return None
    lines = text.split("\r\n")
    # tolerate a stray leading CRLF between keep-alive requests
    while lines and not lines[0]:
        lines.pop(0)
    if not lines:
        return None
    parts = lines[0].split(" ", 2)
    if len(parts) != 3:
        return None
    method, target, version = parts
    headers: List[Tuple[str, str]] = []
    for ln in lines[1:]:
        if not ln:
            continue
        if ":" not in ln:
            return None
        k, v = ln.split(":", 1)
        headers.append((k.strip(), v.strip()))
    return _Request(method.upper(), target, version.upper(), headers)


async def _read_body(reader: asyncio.StreamReader, req: _Request) -> bytes:
    te = (req.get("transfer-encoding") or "").lower()
    if "chunked" in te:
        out = bytearray()
        while True:
            line = await reader.readline()
            size = int(line.split(b";", 1)[0].strip() or b"0", 16)
            if size == 0:
                # trailers until blank line
                while True:
                    t = await reader.readline()
                    if t in (b"\r\n", b"", b"\n"):
                        break
                return bytes(out)
            out += await reader.readexactly(size)
            await reader.readexactly(2)  # CRLF
    cl = req.get("content-length")
    if cl:
        n = int(cl)
        return await reader.readexactly(n) if n > 0 else b""
    return b""


def _split_hostport(hp: str, default_port: int) -> Tuple[str, int]:
    hp = hp.strip()
    if hp.startswith("["):                      # [v6]:port
        host, _, rest = hp[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") else default_port
        return host, port
    if hp.count(":") == 1:
        host, port = hp.split(":")
        return host, int(port or default_port)
    return hp, default_port


def _reason(status: int, fallback: str = "") -> str:
    if fallback:
        return fallback
    try:
        return HTTPStatus(status).phrase
    except ValueError:
        return "OK" if status < 400 else "Error"


async def _write_simple(writer: asyncio.StreamWriter, status: int, body: bytes = b"",
                        extra: str = "") -> None:
    try:
        writer.write(
            f"HTTP/1.1 {status} {_reason(status)}\r\n"
            f"Content-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n{extra}\r\n".encode("latin1") + body)
        await writer.drain()
    except Exception:
        pass


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            if writer.can_write_eof():
                writer.write_eof()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# The proxy
# --------------------------------------------------------------------------- #

class FingerprintProxy:
    """Local MITM proxy that re-issues the browser's requests through
    curl_cffi (Chrome TLS/h2 fingerprint), optionally via an upstream
    HTTP proxy such as Bright Data.

    upstream: "http://user:pass@host:port" / "http://host:port" / None (direct)
    """

    def __init__(self, upstream: Optional[str] = None, impersonate: str = DEFAULT_IMPERSONATE,
                 host: str = "127.0.0.1", port: int = 0, ca_dir: str = DEFAULT_CA_DIR,
                 verify: bool = True):
        self.upstream = upstream
        self.impersonate = impersonate
        self.host = host
        self.port = port
        self.verify = verify
        self.ca = get_ca(ca_dir)
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._server: Optional[asyncio.AbstractServer] = None
        self._session = None
        self._ready = threading.Event()
        self._start_error: Optional[BaseException] = None
        self.stats = {"requests": 0, "tunnels": 0, "errors": 0}
        self._up = urlsplit(upstream) if upstream else None
        self._clients: set = set()

    # -- lifecycle --------------------------------------------------------------
    def start(self, timeout: float = 15.0) -> int:
        if self._thread:
            return self.port
        self._thread = threading.Thread(target=self._run, name="fp-proxy", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout):
            raise RuntimeError("fingerprint proxy did not start in time")
        if self._start_error:
            raise RuntimeError(f"fingerprint proxy failed to start: {self._start_error}")
        return self.port

    def stop(self) -> None:
        loop = self._loop
        if loop and self._server:
            fut = asyncio.run_coroutine_threadsafe(self._shutdown(), loop)
            try:
                fut.result(10)
            except Exception:
                pass
        if loop:
            loop.call_soon_threadsafe(loop.stop)
        if self._thread:
            self._thread.join(5)
        self._thread = None

    @property
    def proxy_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._serve())
        except BaseException as e:  # noqa
            self._start_error = e
            self._ready.set()
            return
        try:
            loop.run_forever()
        finally:
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:
                pass
            loop.close()

    async def _serve(self) -> None:
        from curl_cffi.requests import AsyncSession
        self._session = AsyncSession(
            impersonate=self.impersonate, proxy=self.upstream, discard_cookies=True,
            default_headers=False, verify=self.verify, allow_redirects=False,
            max_clients=32,
        )
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port,
                                                  limit=_MAX_HEAD, reuse_address=True)
        self.port = self._server.sockets[0].getsockname()[1]
        _log(f"listening on {self.proxy_url} upstream={'direct' if not self.upstream else self._up.hostname} "
             f"impersonate={self.impersonate}")
        self._ready.set()

    async def _shutdown(self) -> None:
        if self._server:
            self._server.close()
        for t in list(self._clients):
            t.cancel()
        if self._clients:
            await asyncio.gather(*self._clients, return_exceptions=True)
        if self._server:
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=5)
            except Exception:
                pass
        if self._session:
            try:
                await self._session.close()
            except Exception:
                pass

    # -- connection handling ----------------------------------------------------
    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task:
            self._clients.add(task)
        try:
            head = await _read_head(reader)
            if not head:
                return
            req = _parse_head(head)
            if req is None:
                await _write_simple(writer, 400, b"bad request")
                return
            if req.method == "CONNECT":
                await self._handle_connect(reader, writer, req)
            else:
                await self._serve_http(reader, writer, first=req, scheme="http",
                                       default_host=None, default_port=80)
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.CancelledError):
            pass
        except Exception as e:
            self.stats["errors"] += 1
            _log(f"client handler error: {type(e).__name__}: {e}")
        finally:
            if task:
                self._clients.discard(task)
            try:
                writer.close()
            except Exception:
                pass

    async def _handle_connect(self, reader, writer, req: _Request) -> None:
        host, port = _split_hostport(req.target, 443)
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()
        if port != 443 and port not in (8443, 443):
            # non-TLS CONNECT target (rare) — can't MITM blindly; raw tunnel it
            await self._raw_tunnel(reader, writer, host, port, tls=False, initial=b"")
            return
        try:
            await asyncio.wait_for(writer.start_tls(self.ca.context_for(host)), timeout=30)
        except Exception as e:
            # Browser rejected our cert (pinning / no --ignore-certificate-errors)
            # or just closed a pre-connect — nothing to do.
            _log(f"TLS handshake with browser failed for {host}: {type(e).__name__}: {e}")
            return
        await self._serve_http(reader, writer, first=None, scheme="https",
                               default_host=host, default_port=port)

    async def _serve_http(self, reader, writer, first: Optional[_Request], scheme: str,
                          default_host: Optional[str], default_port: int) -> None:
        """Keep-alive loop: parse HTTP/1.1 requests, forward via curl_cffi."""
        req = first
        while True:
            if req is None:
                head = await _read_head(reader)
                if not head:
                    return
                req = _parse_head(head)
                if req is None:
                    await _write_simple(writer, 400, b"bad request")
                    return

            # ---- resolve absolute URL ----
            if req.target.startswith("http://") or req.target.startswith("https://"):
                url = req.target
                u = urlsplit(url)
                host, port = _split_hostport(u.netloc, 443 if u.scheme == "https" else 80)
                scheme_now = u.scheme
            else:
                host, port = default_host, default_port
                hh = req.get("host")
                if hh:
                    host, port = _split_hostport(hh, default_port)
                if not host:
                    await _write_simple(writer, 400, b"missing host")
                    return
                scheme_now = scheme
                std = (scheme_now == "https" and port == 443) or (scheme_now == "http" and port == 80)
                url = f"{scheme_now}://{host}{'' if std else f':{port}'}{req.target}"

            if "websocket" in (req.get("upgrade") or "").lower():
                # WebSocket → raw tunnel for the rest of this connection. Other
                # Upgrade headers (h2c, …) are hop-by-hop and simply dropped.
                self.stats["tunnels"] += 1
                raw = _rebuild_head(req)
                await self._raw_tunnel(reader, writer, host, port, tls=(scheme_now == "https"),
                                       initial=raw)
                return

            body = await _read_body(reader, req)
            close_after = (req.get("connection") or "").lower() == "close" or req.version == "HTTP/1.0"
            try:
                close_after = (await self._forward(writer, req, url, body)) or close_after
            except Exception as e:
                self.stats["errors"] += 1
                _log(f"upstream error for {req.method} {url}: {type(e).__name__}: {e}")
                await _write_simple(writer, 502, f"fingerprint proxy upstream error: {e}".encode()[:1000])
                return
            if close_after:
                return
            req = None

    async def _forward(self, writer, req: _Request, url: str, body: bytes) -> bool:
        """Issue the request upstream and stream the response back.
        Returns True if the downstream connection must be closed afterwards."""
        self.stats["requests"] += 1
        headers = [(k, v) for k, v in req.headers if k.lower() not in _HOP_BY_HOP]
        t0 = time.time()
        # Plain http:// — libcurl would try an h2c "Upgrade" on cleartext, which
        # Chrome never does; pin those to HTTP/1.1. https keeps the impersonated
        # Chrome h2 behaviour.
        extra = {"http_version": "v1"} if url.startswith("http://") else {}
        resp = await self._session.request(
            req.method, url, headers=headers, content=body if body else None,
            stream=True, allow_redirects=False, accept_encoding=None,
            timeout=_UPSTREAM_TIMEOUT, **extra,
        )
        status = int(resp.status_code)
        reason = _reason(status, getattr(resp, "reason", "") or "")
        out_headers: List[Tuple[str, str]] = []
        for k, v in resp.headers.multi_items():
            kl = k.lower()
            if kl in _HOP_BY_HOP or kl == "content-length":
                continue
            out_headers.append((k, v))
        no_body = (req.method == "HEAD" or status < 200 or status in (204, 304))
        if no_body:
            out_headers.append(("Content-Length", "0"))
        else:
            out_headers.append(("Transfer-Encoding", "chunked"))
        out_headers.append(("Connection", "keep-alive"))
        head = f"HTTP/1.1 {status} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in out_headers) + "\r\n"
        writer.write(head.encode("latin1", "replace"))
        await writer.drain()
        total = 0
        try:
            if not no_body:
                async for chunk in resp.aiter_content():
                    if not chunk:
                        continue
                    total += len(chunk)
                    writer.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                    await writer.drain()
                writer.write(b"0\r\n\r\n")
                await writer.drain()
            else:
                # drain / discard upstream body so the connection can be reused
                async for _ in resp.aiter_content():
                    pass
        finally:
            try:
                await resp.aclose()
            except Exception:
                pass
        _log(f"{req.method} {url} -> {status} {total}B {time.time() - t0:.2f}s")
        return False

    async def _raw_tunnel(self, reader, writer, host: str, port: int, tls: bool,
                          initial: bytes) -> None:
        """Bidirectional byte pipe to host:port (via the upstream proxy's CONNECT
        when configured). Used for WebSocket / Upgrade and non-443 CONNECTs."""
        try:
            if self._up:
                ur, uw = await asyncio.wait_for(
                    asyncio.open_connection(self._up.hostname, self._up.port or 80), timeout=30)
                auth = ""
                if self._up.username:
                    cred = f"{self._up.username}:{self._up.password or ''}".encode()
                    auth = "Proxy-Authorization: Basic " + base64.b64encode(cred).decode() + "\r\n"
                uw.write(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n{auth}\r\n".encode())
                await uw.drain()
                resp_head = await asyncio.wait_for(ur.readuntil(b"\r\n\r\n"), timeout=30)
                if b" 200" not in resp_head.split(b"\r\n", 1)[0]:
                    raise ConnectionError(f"upstream CONNECT refused: {resp_head.split(b'\r\n', 1)[0]!r}")
            else:
                ur, uw = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=30)
            if tls:
                ctx = ssl.create_default_context()
                if not self.verify:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                await asyncio.wait_for(uw.start_tls(ctx, server_hostname=host), timeout=30)
        except Exception as e:
            self.stats["errors"] += 1
            _log(f"tunnel to {host}:{port} failed: {type(e).__name__}: {e}")
            await _write_simple(writer, 502, b"tunnel failed")
            return
        if initial:
            uw.write(initial)
            await uw.drain()
        try:
            await asyncio.gather(_pipe(reader, uw), _pipe(ur, writer))
        finally:
            try:
                uw.close()
            except Exception:
                pass


def _rebuild_head(req: _Request) -> bytes:
    """Serialise a parsed request head back to bytes (for raw tunnelling)."""
    target = req.target
    if target.startswith("http://") or target.startswith("https://"):
        u = urlsplit(target)
        target = (u.path or "/") + (f"?{u.query}" if u.query else "")
    lines = [f"{req.method} {target} {req.version}"]
    for k, v in req.headers:
        if k.lower() in ("proxy-connection", "proxy-authorization"):
            continue
        lines.append(f"{k}: {v}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin1", "replace")


def upstream_url(host: str, port: int, user: Optional[str] = None,
                 passwd: Optional[str] = None) -> str:
    """Build the curl-style proxy URL from the checker's parsed proxy spec."""
    if user:
        return f"http://{quote(user, safe='')}:{quote(passwd or '', safe='')}@{host}:{port}"
    return f"http://{host}:{port}"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _main() -> int:
    import argparse
    p = argparse.ArgumentParser(description="TLS/h2 fingerprint rewriting proxy (curl_cffi Chrome upstream)")
    p.add_argument("--upstream", default=os.environ.get("AHREF_FP_UPSTREAM") or None,
                   help="upstream proxy URL http://user:pass@host:port (default: direct)")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--impersonate", default=DEFAULT_IMPERSONATE)
    p.add_argument("--insecure", action="store_true", help="do not verify upstream certificates")
    args = p.parse_args()
    global DEBUG
    DEBUG = True
    fp = FingerprintProxy(upstream=args.upstream, impersonate=args.impersonate, port=args.port,
                          verify=not args.insecure)
    port = fp.start()
    print(f"fingerprint proxy listening on http://127.0.0.1:{port}  (CA: {fp.ca.ca_pem})", flush=True)
    print(f"  curl -x http://127.0.0.1:{port} --cacert {fp.ca.ca_pem} https://tls.peet.ws/api/clean", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    fp.stop()
    return 0


if __name__ == "__main__":
    sys.exit(_main())
