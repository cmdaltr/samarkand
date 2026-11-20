"""Connecting only where the URL check said: never a link-local address (cloud metadata), however the
host is written and whatever its name resolves to.

The URL checks (`webhooks.url_problem`) read the host as written. A name is only known once it's
resolved, and a name can resolve to 169.254.169.254, or to a public address when checked and a
link-local one a moment later (DNS rebinding). So every request samarkand sends resolves the host
once here, refuses it if any of its addresses is link-local, and connects to the addresses it checked,
each in turn until one answers (`localhost` is ::1 then 127.0.0.1 on macOS, and a server listening on
only one of them is still reached); the name stays in the Host header, in SNI and in the certificate
check.

`addresses` is the rule; `AsyncTransport` applies it to an httpx client (a product's own requests to an
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


def addresses(host: str, port: int) -> list[str]:
    """The addresses to try for `host`, in the resolver's order, once none of them is link-local.
    Raises Refused for a link-local one, and socket.gaierror for a name that doesn't resolve."""
    literal = _literal(host)
    if literal is not None:
        return [_usable(literal, host)]
    found = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    usable: list[str] = []
    for info in found:
        address = _literal(str(info[4][0]).split("%")[0])
        if address is None:
            continue
        checked = _usable(address, host)
        if checked not in usable:
            usable.append(checked)
    if not usable:
        raise Refused(f"{host} didn't resolve to an address")
    return usable


def resolve(host: str, port: int) -> str:
    """The first of `addresses`."""
    return addresses(host, port)[0]


# ---- the standard library (samarkand._http's sync sender) -------------------------------------------


def _create_connection(address: tuple[str, int], *args: Any, **kwargs: Any) -> socket.socket:
    host, port = address
    failure: OSError | None = None
    for candidate in addresses(host, port):
        try:
            return socket.create_connection((candidate, port), *args, **kwargs)
        except OSError as exc:
            failure = exc
    assert failure is not None
    raise failure


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
        """httpx's transport, connecting to the addresses `addresses` checked, each in turn until one
        answers. Takes httpx.AsyncHTTPTransport's arguments (verify, retries…); a client given a
        transport ignores its own `verify`, so pass it here."""

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            host = request.url.host
            port = request.url.port or (443 if request.url.scheme == "https" else 80)
            try:
                candidates = await asyncio.get_running_loop().run_in_executor(None, addresses, host, port)
            except OSError as exc:
                raise httpx.ConnectError(str(exc), request=request) from exc
            url, extensions = request.url, request.extensions
            for i, address in enumerate(candidates):
                if address != host:
                    request.url = url.copy_with(host=address)
                    request.extensions = {**extensions, "sni_hostname": host}
                try:
                    return await super().handle_async_request(request)
                except (httpx.ConnectError, httpx.ConnectTimeout):
                    if i == len(candidates) - 1:
                        raise
            raise AssertionError("unreachable")  # pragma: no cover
