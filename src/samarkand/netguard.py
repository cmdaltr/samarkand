"""Connecting only where the URL check said: never a link-local address (cloud metadata), however the
host is written and whatever its name resolves to.

The URL checks (`webhooks.url_problem`) read the host as written. A name is only known once it's
resolved, and a name can resolve to 169.254.169.254, or to a public address when checked and a
link-local one a moment later (DNS rebinding). So every request samarkand sends resolves the host
once here, refuses it if any of its addresses is link-local, and connects to the address it checked;
the name stays in the Host header, in SNI and in the certificate check.

`resolve` is the rule; `AsyncTransport` applies it to an httpx client (a product's own requests to an
admin-set address); `samarkand._http` applies it to every request it sends.
"""

from __future__ import annotations

import asyncio
import http.client
import ipaddress
import socket
import urllib.request
from typing import Any

LINK_LOCAL = "never connects to a link-local address"


class Refused(OSError):
    """The host is, or resolves to, a link-local address. An OSError, as a failure to connect is."""


def _literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """An address written in the host, read as the resolver reads it (2852039166 is 169.254.169.254)."""
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        try:
            return ipaddress.IPv4Address(socket.inet_aton(host))
        except OSError:
            return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def _usable(address: ipaddress.IPv4Address | ipaddress.IPv6Address, host: str) -> str:
    if address.is_link_local:
        raise Refused(f"{host}: samarkand {LINK_LOCAL}")
    return str(address)


def resolve(host: str, port: int) -> str:
    """The address to connect to for `host`: the first it resolves to, once none of them is link-local.
    Raises Refused for a link-local one, and socket.gaierror for a name that doesn't resolve."""
    literal = _literal(host)
    if literal is not None:
        return _usable(literal, host)
    found = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = [_literal(str(info[4][0]).split("%")[0]) for info in found]
    usable = [_usable(a, host) for a in addresses if a is not None]
    if not usable:
        raise Refused(f"{host} didn't resolve to an address")
    return usable[0]


# ---- the standard library (samarkand._http's sync sender) -------------------------------------------


def _create_connection(address: tuple[str, int], *args: Any, **kwargs: Any) -> socket.socket:
    host, port = address
    return socket.create_connection((resolve(host, port), port), *args, **kwargs)


class _HTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._create_connection = _create_connection


class _HTTPSConnection(http.client.HTTPSConnection):
    """Connects to the checked address; TLS still wraps with server_hostname=self.host, so SNI and the
    certificate check use the name."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._create_connection = _create_connection


class HTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(_HTTPConnection, req)


class HTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, context: Any = None) -> None:
        super().__init__(context=context)
        self._guarded_context = context

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(_HTTPSConnection, req, context=self._guarded_context)


# ---- httpx (samarkand._http's async sender, and a product's own clients) ----------------------------

try:
    import httpx
except ImportError:  # pragma: no cover - only without the async extra
    httpx = None  # type: ignore[assignment]


if httpx is not None:

    class AsyncTransport(httpx.AsyncHTTPTransport):
        """httpx's transport, connecting to the address `resolve` checked. Takes httpx.AsyncHTTPTransport's
        arguments (verify, retries…); a client given a transport ignores its own `verify`, so pass it here."""

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            host = request.url.host
            port = request.url.port or (443 if request.url.scheme == "https" else 80)
            try:
                address = await asyncio.get_running_loop().run_in_executor(None, resolve, host, port)
            except OSError as exc:
                raise httpx.ConnectError(str(exc), request=request) from exc
            if address != host:
                request.url = request.url.copy_with(host=address)
                request.extensions = {**request.extensions, "sni_hostname": host}
            return await super().handle_async_request(request)
